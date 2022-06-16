use std::env;
use std::fs;

use bytes::Bytes;
use chrono::prelude::*;
use jsonwebtoken::{Algorithm, decode, DecodingKey, encode, EncodingKey, Header, Validation};
use openssl::rsa::{Padding, Rsa};
use serde::{Deserialize, Serialize};
use serde_json;

use actix_web::{
    post, web, App, HttpResponse, HttpServer,
    http::{header::ContentType, StatusCode},
};

use jwtd::errors::{ErrorKind, new_error, Result};


#[derive(Debug, Serialize)]
pub struct ErrorDTO {
    pub error_code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct HealthDTO {
    pub status: String,
    pub version: String,
}

pub fn load_private_key(location: String) -> Result<Vec<u8>> {
    return fs::read(location).map_err(|err| new_error(ErrorKind::PrivateKeyReadingError(err)));
}

pub fn private_key() -> Result<Vec<u8>> {
    let location = env::var("JWT_PRIV_KEY_LOCATION".to_string()).map_err(|_| {
        new_error(ErrorKind::MissingConfigError(
            "Environment variable 'JWT_PRIV_KEY_LOCATION' not set; unable to read private key"
                .to_string(),
        ))
    })?;
    return load_private_key(location);
}

fn to_public_key(private_key: &Vec<u8>) -> Result<Vec<u8>> {
    let rsa = Rsa::private_key_from_pem(&private_key);
    return rsa
        .unwrap()
        .public_key_to_pem()
        .map_err(|err| new_error(ErrorKind::PublicKeyError(err)));
}

pub fn issuer() -> String {
    return match env::var("JWT_ISSUER".to_string()) {
        Ok(s) => s,
        _ => "jwtd".to_string(),
    };
}

pub fn generate_token<T: Serialize>(claims: &T, priv_key: &Vec<u8>) -> Result<String> {
    let header = Header::new(Algorithm::RS256);
    let encoding_key = EncodingKey::from_rsa_pem(priv_key)
        .map_err(|err| new_error(ErrorKind::PrivateKeyError(err)))?;
    return encode(&header, &claims, &encoding_key)
        .map_err(|err| new_error(ErrorKind::TokenError(err.into_kind())));
}

#[derive(Debug, Deserialize)]
pub struct SignOpts {
    pub generate: Option<String>,
    pub duration_seconds: Option<String>,
}

#[post("/sign")]
async fn sign(app_state: web::Data<AppState>,
              body: web::Json<serde_json::Value>,
              sign_opts: web::Query<SignOpts>) -> HttpResponse {
    log::debug!("sign_claims: {:?} // {:?}", body, &sign_opts);
    let claims = match &sign_opts.generate {
        Some(generate) => match body.0 {
            serde_json::Value::Object(m) => {
                let mut m = m.clone();
                let duration = sign_opts
                    .duration_seconds
                    .as_ref()
                    .map_or(600, |s| s.parse().unwrap_or(600));
                let issued_at = Utc::now().timestamp();
                let expiration = Utc::now()
                    .checked_add_signed(chrono::Duration::seconds(duration))
                    .expect("valid timestamp")
                    .timestamp();
                if generate.contains("iat") {
                    m.insert(
                        "iat".to_string(),
                        serde_json::Value::Number(issued_at.into()),
                    );
                }
                if generate.contains("exp") {
                    m.insert(
                        "exp".to_string(),
                        serde_json::Value::Number(expiration.into()),
                    );
                }
                if generate.contains("iss") {
                    m.insert("iss".to_string(), serde_json::Value::String(app_state.issuer.clone()));
                }
                serde_json::Value::Object(m)
            }
            _ => body.clone(),
        },
        _ => body.clone(),
    };

    match generate_token(&claims, &app_state.private_key) {
        Ok(token) =>
            HttpResponse::build(StatusCode::OK)
                .insert_header(ContentType::plaintext())
                .body(token),
        Err(err) => {
            log::error!("Ouch... {}", err);
            HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                .insert_header(ContentType::plaintext())
                .body(format!("Something bad happened: {:?}", err).to_string())
        }
    }
}


pub fn decode_token(
    token: String,
    priv_key: &Vec<u8>,
    validation: &Validation,
) -> Result<serde_json::Value> {
    let decoding_key = DecodingKey::from_rsa_pem(priv_key)
        .map_err(|err| new_error(ErrorKind::PrivateKeyError(err)))?;

    return decode::<serde_json::Value>(token.as_ref(), &decoding_key, validation)
        .map_err(|err| new_error(ErrorKind::TokenError(err.into_kind())))
        .map(|token_data| token_data.claims);
}


#[post("/verify")]
pub async fn verify(
    app_state: web::Data<AppState>,
    body: String,
) -> HttpResponse {
    log::debug!("verify_token: {:?}", body);

    match decode_token(body, &app_state.public_key, &app_state.validation) {
        Ok(claims) => {
            log::info!("Token verification sucessful... {:?}", claims);
            HttpResponse::Ok().json(claims)
        }
        Err(err) => {
            let error_code = match err.kind() {
                ErrorKind::TokenError(e) => {
                    log::info!("Token verification failed... {:?}", e);
                    "TOKEN_ERROR".to_string()
                }
                _ => {
                    log::error!("Token verification failed... {:?}", err);
                    "SERVER_ERROR".to_string()
                }
            };

            HttpResponse::InternalServerError()
                .json(ErrorDTO {
                    error_code,
                    message: format!("Something bad happened: {:?}", err).to_string(),
                })
        }
    }
}

fn encrypt_content(content: &Bytes, public_key: &Vec<u8>) -> Result<Bytes> {
    encrypt_content_with_padding(content, public_key, Padding::PKCS1_OAEP)
}

fn encrypt_content_with_padding(
    content: &Bytes,
    public_key: &Vec<u8>,
    padding: Padding,
) -> Result<Bytes> {
    let rsa = Rsa::public_key_from_pem(&public_key).unwrap();
    let mut buf = vec![0; rsa.size() as usize];
    match rsa.public_encrypt(&content[..], &mut buf, padding) {
        Ok(encrypted_len) => Ok(Bytes::copy_from_slice(&buf[0..encrypted_len])),
        Err(e) => Err(new_error(ErrorKind::EncryptError(format!(
            "{:?}, (Padding: {:?})",
            e, padding
        )))),
    }
}

fn decrypt_content(content: &Bytes, private_key: &Vec<u8>) -> Result<Bytes> {
    decrypt_content_with_padding(content, private_key, Padding::PKCS1_OAEP)
}

fn decrypt_content_with_padding(
    content: &Bytes,
    private_key: &Vec<u8>,
    padding: Padding,
) -> Result<Bytes> {
    let rsa = Rsa::private_key_from_pem(&private_key).unwrap();
    let mut buf = vec![0; rsa.size() as usize];
    match rsa.private_decrypt(&content[..], &mut buf, padding) {
        Ok(decrypted_len) => Ok(Bytes::copy_from_slice(&buf[0..decrypted_len])),
        Err(e) => Err(new_error(ErrorKind::DecryptError(format!(
            "{:?}, (Padding: {:?})",
            e, padding
        )))),
    }
}

#[post("/encrypt")]
pub async fn encrypt(
    app_state: web::Data<AppState>,
    body: web::Bytes,
) -> HttpResponse {
    log::debug!("encrypt: {:?}", body);
    match encrypt_content(&body, &app_state.public_key) {
        Ok(content) => {
            log::info!("Encryption successful... {:?}", content);
            HttpResponse::Ok()
                .body(base64::encode(content))
        }
        Err(err) =>
            HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                .insert_header(ContentType::plaintext())
                .body(format!("Encryption failed: {:?}", err).to_string())
    }
}


#[post("/decrypt")]
pub async fn decrypt(
    app_state: web::Data<AppState>,
    body: web::Bytes,
) -> HttpResponse {
    log::debug!("decrypt: {:?}", body);
    match base64::decode(body) {
        Ok(decoded) => {
            let decoded_bytes = Bytes::from(decoded);
            match decrypt_content(&decoded_bytes, &app_state.private_key) {
                Ok(content) => {
                    log::info!("Decryption successful... {:?}", content);
                    HttpResponse::build(StatusCode::OK)
                        .insert_header(ContentType::plaintext())
                        .body(base64::encode(content))
                }
                Err(err) => {
                    log::info!("Decryption failed... {:?}", err);
                    HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                        .insert_header(ContentType::plaintext())
                        .body(format!("Decryption failed: {:?}", err).to_string())
                }
            }
        }
        Err(err) => {
            log::info!("Decryption failed... {:?}", err);
            HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                .insert_header(ContentType::plaintext())
                .body(format!("Decryption failed (invalid base64 payload): {:?}", err).to_string())
        }
    }
}


#[post("/health")]
pub async fn health(
    app_state: web::Data<AppState>,
) -> HttpResponse {
    HttpResponse::Ok()
        .json(HealthDTO {
            status: "OK".to_string(),
            version: app_state.version.clone(),
        })
}

fn default_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.iss = Some(issuer());
    validation
}

// This struct represents state
pub struct AppState {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    issuer: String,
    version: String,
    validation: Validation,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if env::var_os("RUST_LOG").is_none() {
        // Set `RUST_LOG=jwtd=debug` to see debug logs,
        // info - only shows access logs.
        env::set_var("RUST_LOG", "jwtd=debug");
    }
    pretty_env_logger::init();

    let version = env!("CARGO_PKG_VERSION");
    log::info!("Starting jwtd {}", version);

    let private_key = private_key().unwrap();
    let public_key = to_public_key(&private_key).unwrap();
    log::info!("Private key loaded");
    let issuer = issuer();
    let validation = default_validation();

    let app_state = web::Data::new(AppState {
        public_key,
        private_key,
        issuer,
        version: version.to_string(),
        validation,
    });

    let port = env::var("PORT")
        .map(|a| match a.parse() {
            Ok(v) => v,
            _ => 8080,
        })
        .unwrap_or_else(|_err| {
            log::info!("Port not provided, fallback on default");
            8080
        });

    log::info!("Server starting on port {}", port);
    HttpServer::new(move || {
        let json_config = web::JsonConfig::default()
            .limit(4096)
            .error_handler(|err, _req| {
                // create custom error response
                actix_web::error::InternalError::from_response(err, HttpResponse::Conflict().finish())
                    .into()
            });

        App::new()
            .app_data(app_state.clone())
            .app_data(json_config)
            .service(sign)
            .service(verify)
            .service(health)
            .service(encrypt)
            .service(decrypt)
    })
        .bind(("0.0.0.0", port))?
        .run()
        .await
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[ctor::ctor] // see https://stackoverflow.com/a/63442117
    fn init() {
        env::set_var("RUST_LOG", "jwtd=debug");
        pretty_env_logger::init();
    }

    #[test]
    fn test_extract_public_key_from_private_key() {
        let priv_key = load_private_key("./local/key_prv.pem".to_string()).unwrap();
        let rsa = Rsa::private_key_from_pem(&priv_key);
        match rsa.unwrap().public_key_to_pem() {
            Ok(key) => assert_eq!(
                String::from_utf8(key).unwrap(),
                r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzLbgL2eRdwXPLGB/ncPM
OLPOZ8ARvvcK20igRX728KZIeJg/ISjJo3F9rKiouwYpKUZkYNonnT/NjVL4TG4f
4GnLwrJ8uF6IrFZ2N2ZX0AKZ3ukk9q88IvS4CQ1qc4BJvD6kLyn1F2M7vPYw6l+c
7IfK60tWeZAGnv15NP/XV4ri383Id1KMIW29dntonF1WmQbFKQhLjrpcmA0ZRm6i
nB9//raZSOCUU8R6WRtw4SWxPZRXsSDR26ZVyIYIUtHeCnP+qUsSGJJtsNmp/WTu
HnPwfkKmIrkKgnV2ufdRQ1tz3J6ZpYjYraqsHU3qAIc/GyWAtbjg+cBP+evT6ljz
vwIDAQAB
-----END PUBLIC KEY-----
"#
                    .to_string()
            ),
            Err(err) => panic!("{}", err),
        }
    }

    #[test]
    fn test_decode() {
        let priv_key = load_private_key("./local/key_prv.pem".to_string()).unwrap();
        let pub_key = to_public_key(&priv_key).unwrap();

        let mut validation = default_validation();
        validation.validate_exp = false;

        let raw_claims = r#"
        {
            "aid": "AGENT:007",
            "exp": 1648737097,
            "huk": [
              "r001",
              "r002"
            ],
            "iat": 1648736497,
            "iss": "jwtd"
        }"#;
        let expected_claims: serde_json::Value = serde_json::from_str(raw_claims).unwrap();

        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhaWQiOiJBR0VOVDowMDciLCJleHAiOjE2NDg3MzcwOTcsImh1ayI6WyJyMDAxIiwicjAwMiJdLCJpYXQiOjE2NDg3MzY0OTcsImlzcyI6Imp3dGQifQ.U6L7jor_1-_efkwsvuizUy3Ljswlxwb6QgDvq4cz7fAs3b4MTceBU02ArmV843x5YYjNvuGkyZgMXxWn11IJS2LPcV4P7s0su_zcVczTS9J_mC-8shZ0RdA8eZ9lgE9LPCn9Fma1ZimSgKk5x8930oqt8v-VokC6lLdpT9jjw2Dbr9xQPyJOpulX5mDvaymsN28fyBZM-QbaRa2rOgmUrvLCM_h94TgZ3kHGkbvLZcYaJFqIQRFoc5TXh1pIHv9Odxnl_ut7LCDqMF4ItmlNTq3QrsL3453vQjD-xJrOdqXEruwpvn52t2a3J7DjarFlFBJnP72yafEW2ApEv1nAxg".to_string();
        match decode_token(token, &pub_key, &validation) {
            Ok(claims) => {
                assert_eq!(claims, expected_claims);
            }

            Err(err) => {
                panic!("Failed to decode token {}", err);
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        let priv_key = load_private_key("./local/key_prv.pem".to_string()).unwrap();
        let pub_key = to_public_key(&priv_key).unwrap();
        let buff = Bytes::copy_from_slice("Hello Margarett!".as_bytes());
        match encrypt_content(&buff, &pub_key) {
            Ok(encrypted) => match decrypt_content(&encrypted, &priv_key) {
                Ok(decrypted) => {
                    let actual = String::from_utf8(Vec::from(&decrypted[..])).unwrap();
                    assert_eq!(actual, "Hello Margarett!".to_string());
                }
                Err(err) => {
                    panic!("Failed to decrypt content {}", err);
                }
            },
            Err(err) => {
                panic!("Failed to encrypt content {}", err);
            }
        }
    }
}
