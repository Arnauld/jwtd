use bytes::Bytes;
use chrono::prelude::*;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use jwtd::errors::{new_error, ErrorKind, Result};
use openssl::rsa::{Padding, Rsa};
use serde::{Deserialize, Serialize};
use serde_json;
use std::convert::Infallible;
use std::env;
use std::fs;
use std::result;
use warp::{http::StatusCode, Filter};

#[derive(Debug, Deserialize)]
pub struct SignOpts {
    pub generate: Option<String>,
    pub duration_seconds: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorDTO {
    pub error_code: String,
    pub message: String,
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

pub fn generate_token<T: Serialize>(claims: &T, priv_key: Vec<u8>) -> Result<String> {
    let header = Header::new(Algorithm::RS256);
    let encoding_key = EncodingKey::from_rsa_pem(&priv_key)
        .map_err(|err| new_error(ErrorKind::PrivateKeyError(err)))?;
    return encode(&header, &claims, &encoding_key)
        .map_err(|err| new_error(ErrorKind::TokenError(err.into_kind())));
}

pub async fn sign_claims(
    body: serde_json::Value,
    sign_opts: SignOpts,
    private_key: Vec<u8>,
) -> result::Result<impl warp::Reply, Infallible> {
    log::debug!("sign_claims: {:?} // {:?}", body, sign_opts);
    let claims = match sign_opts.generate {
        Some(generate) => match body {
            serde_json::Value::Object(m) => {
                let mut m = m.clone();
                let duration = sign_opts
                    .duration_seconds
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
                    m.insert("iss".to_string(), serde_json::Value::String(issuer()));
                }
                serde_json::Value::Object(m)
            }
            _ => body.clone(),
        },
        _ => body.clone(),
    };

    match generate_token(&claims, private_key) {
        Ok(token) => Ok(warp::reply::with_status(token, StatusCode::OK)),
        Err(err) => {
            log::error!("Ouch... {}", err);
            Ok(warp::reply::with_status(
                format!("Something bad happened: {:?}", err).to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

pub fn decode_token(
    token: String,
    priv_key: Vec<u8>,
    validation: Validation,
) -> Result<serde_json::Value> {
    let decoding_key = DecodingKey::from_rsa_pem(&priv_key)
        .map_err(|err| new_error(ErrorKind::PrivateKeyError(err)))?;

    return decode::<serde_json::Value>(token.as_ref(), &decoding_key, &validation)
        .map_err(|err| new_error(ErrorKind::TokenError(err.into_kind())))
        .map(|token_data| token_data.claims);
}

pub async fn verify_token(
    body: String,
    private_key: Vec<u8>,
    validation: Validation,
) -> result::Result<impl warp::Reply, Infallible> {
    log::debug!("verify_token: {:?}", body);

    match decode_token(body, private_key, validation) {
        Ok(claims) => {
            log::info!("Token verification sucessful... {:?}", claims);
            Ok(warp::reply::with_status(
                warp::reply::json(&claims),
                StatusCode::OK,
            ))
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

            Ok(warp::reply::with_status(
                warp::reply::json(&ErrorDTO {
                    error_code: error_code,
                    message: format!("Something bad happened: {:?}", err).to_string(),
                }),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

fn encrypt_content(content: &[u8], public_key: &Vec<u8>) -> Result<Vec<u8>> {
    let rsa = Rsa::public_key_from_pem(&public_key).unwrap();
    let mut buf = vec![0; rsa.size() as usize];
    let encrypted_len = rsa
        .public_encrypt(content, &mut buf, Padding::PKCS1_OAEP)
        .unwrap();
    Ok(buf[0..encrypted_len].to_vec())
}

pub async fn encrypt_payload(
    body: String,
    private_key: Vec<u8>,
) -> result::Result<impl warp::Reply, Infallible> {
    log::debug!("encrypt_payload: {:?}", body);
    match encrypt_content(body.as_bytes(), &private_key) {
        Ok(content) => {
            log::info!("Encryption successful... {:?}", content);
            Ok(warp::reply::with_status(
                hex::encode(content),
                StatusCode::OK,
            ))
        }
        Err(err) => {
            Ok(warp::reply::with_status(
                format!("Encryption failed: {:?}", err).to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

fn decrypt_content(content: &[u8], private_key: &Vec<u8>) -> Result<Vec<u8>> {
    let rsa = Rsa::private_key_from_pem(&private_key).unwrap();
    let mut buf = vec![0; content.len() as usize];
    let decrypted_len = rsa
        .private_decrypt(content, &mut buf, Padding::PKCS1_OAEP)
        .unwrap();
    Ok(buf[0..decrypted_len].to_vec())
}

pub async fn decrypt_payload(
    body: String,
    private_key: Vec<u8>,
) -> result::Result<impl warp::Reply, Infallible> {
    log::debug!("decrypt_payload: {:?}", body);
    match encrypt_content(body.as_bytes(), &private_key) {
        Ok(content) => {
            log::info!("Decryption successful... {:?}", content);
            Ok(warp::reply::with_status(
                hex::encode(content),
                StatusCode::OK,
            ))
        }
        Err(err) => Ok(warp::reply::with_status(
            format!("Decryption failed: {:?}", err).to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}

fn with_key(key: Vec<u8>) -> impl Filter<Extract = (Vec<u8>,), Error = Infallible> + Clone {
    warp::any().map(move || key.clone())
}

fn with_validation(
    validation: Validation,
) -> impl Filter<Extract = (Validation,), Error = Infallible> + Clone {
    warp::any().map(move || validation.clone())
}

pub fn body_as_string() -> warp::filters::BoxedFilter<(String,)> {
    warp::any()
        .and(warp::filters::body::bytes())
        .map(|bytes: Bytes| String::from_utf8(bytes.as_ref().to_vec()).unwrap())
        .boxed()
}

fn default_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.iss = Some(issuer());
    validation
}

#[tokio::main]
async fn main() {
    if env::var_os("RUST_LOG").is_none() {
        // Set `RUST_LOG=jwtd=debug` to see debug logs,
        // info - only shows access logs.
        env::set_var("RUST_LOG", "jwtd=debug");
    }
    pretty_env_logger::init();

    let private_key = private_key().unwrap();
    let public_key = to_public_key(&private_key).unwrap();
    log::info!("Private key loaded");

    let sign = warp::path!("sign")
        .and(warp::post())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .and(warp::query::<SignOpts>())
        .and(with_key(private_key.clone()))
        .and_then(sign_claims);

    let validation = default_validation();
    let verify = warp::path!("verify")
        .and(warp::post())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(body_as_string())
        .and(with_key(public_key.clone()))
        .and(with_validation(validation.clone()))
        .and_then(verify_token);

    let encrypt = warp::path!("encrypt")
        .and(warp::post())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(body_as_string())
        .and(with_key(public_key.clone()))
        .and_then(encrypt_payload);

    let decrypt = warp::path!("decrypt")
        .and(warp::post())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(body_as_string())
        .and(with_key(private_key.clone()))
        .and_then(decrypt_payload);

    let health = warp::path!("health")
        .and(warp::get())
        .map(|| Ok(warp::reply::with_status("OK", StatusCode::OK)));

    let port = env::var("PORT")
        .map(|a| match a.parse() {
            Ok(v) => v,
            _ => 8080,
        })
        .unwrap_or_else(|_err| {
            log::info!("Port not provided, fallback on default");
            8080
        });

    let routes = encrypt.or(decrypt).or(sign).or(verify).or(health);
    log::info!("Server starting on port {}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
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
        match decode_token(token, pub_key, validation) {
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
        match encrypt_content("Hello Margarett!".as_bytes(), &pub_key) {
            Ok(encrypted) => match decrypt_content(&encrypted, &priv_key) {
                Ok(decrypted) => {
                    assert_eq!(decrypted, "Hello Margarett!".as_bytes());
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
