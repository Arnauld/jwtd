use std::collections::HashSet;
use std::convert::Infallible;
use std::env;
use std::fs;
use std::result;

use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rsa::{pkcs1::DecodeRsaPrivateKey, PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json;
use time::{ext::NumericalDuration, OffsetDateTime};
use warp::{http::StatusCode, reject, Filter, Rejection};

use jwtd::errors::{new_error, ErrorKind, Result};

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

#[derive(Debug, Serialize)]
pub struct HealthDTO {
    pub status: String,
    pub version: String,
}

pub fn raw_private_key() -> Result<Vec<u8>> {
    let location = env::var("JWT_PRIV_KEY_LOCATION".to_string()).map_err(|_| {
        new_error(ErrorKind::MissingConfigError(
            "Environment variable 'JWT_PRIV_KEY_LOCATION' not set; unable to read private key"
                .to_string(),
        ))
    })?;
    fs::read(location)
        .map_err(|err| new_error(ErrorKind::PrivateKeyLoadingError(format!("{:?}", err))))
}

pub fn private_key(raw_bytes: Vec<u8>) -> Result<RsaPrivateKey> {
    let raw_content = String::from_utf8(raw_bytes)
        .map_err(|err| new_error(ErrorKind::PrivateKeyLoadingError(format!("{:?}", err))))
        .unwrap();
    let private_key = RsaPrivateKey::from_pkcs1_pem(&raw_content)
        .map_err(|err| new_error(ErrorKind::PrivateKeyLoadingError(format!("{:?}", err))))
        .unwrap();
    return Ok(private_key);
}

pub fn issuer() -> String {
    return match env::var("JWT_ISSUER".to_string()) {
        Ok(s) => s,
        _ => "jwtd".to_string(),
    };
}

pub fn generate_token<T: Serialize>(claims: &T, encoding_key: &EncodingKey) -> Result<String> {
    let header = Header::new(Algorithm::RS256);
    return encode(&header, &claims, &encoding_key)
        .map_err(|err| new_error(ErrorKind::TokenError(err.into_kind())));
}

pub async fn sign_claims(
    body: serde_json::Value,
    sign_opts: SignOpts,
    encoding_key: EncodingKey,
) -> result::Result<impl warp::Reply, Infallible> {
    log::debug!("sign_claims: {:?} // {:?}", body, sign_opts);
    let claims = match sign_opts.generate {
        Some(generate) => match body {
            serde_json::Value::Object(m) => {
                let mut m = m.clone();
                let duration = sign_opts
                    .duration_seconds
                    .map_or(600, |s| s.parse().unwrap_or(600));
                let issued_at = OffsetDateTime::now_utc().unix_timestamp();
                let expiration = OffsetDateTime::now_utc()
                    .checked_add(duration.seconds())
                    .expect("valid timestamp")
                    .unix_timestamp();
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

    match generate_token(&claims, &encoding_key) {
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
    decoding_key: DecodingKey,
    validation: Validation,
) -> Result<serde_json::Value> {
    return decode::<serde_json::Value>(token.as_ref(), &decoding_key, &validation)
        .map_err(|err| new_error(ErrorKind::TokenError(err.into_kind())))
        .map(|token_data| token_data.claims);
}

pub async fn verify_token(
    body: String,
    decoding_key: DecodingKey,
    validation: Validation,
) -> result::Result<impl warp::Reply, Infallible> {
    log::debug!("verify_token: {:?}", body);

    match decode_token(body, decoding_key, validation) {
        Ok(claims) => {
            log::info!("Token verification successful... {:?}", claims);
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

fn encrypt_content(content: &Bytes, public_key: RsaPublicKey) -> Result<Bytes> {
    // note that by default openssl PKCS1_OAEP use SHA1
    let mut rng = rand::thread_rng();
    let padding = rsa::Oaep::new::<sha1::Sha1>();
    match public_key.encrypt(&mut rng, padding, &content[..]) {
        Ok(encrypted) => Ok(Bytes::copy_from_slice(&encrypted[..])),
        Err(e) => Err(new_error(ErrorKind::EncryptError(format!("{:?}", e)))),
    }
}

fn decrypt_content(content: &Bytes, private_key: RsaPrivateKey) -> Result<Bytes> {
    // note that by default openssl PKCS1_OAEP use SHA1
    let padding = rsa::Oaep::new::<sha1::Sha1>();
    match private_key.decrypt(padding, &content[..]) {
        Ok(decrypted) => Ok(Bytes::copy_from_slice(&decrypted[..])),
        Err(e) => Err(new_error(ErrorKind::DecryptError(format!("{:?}", e)))),
    }
}

pub async fn encrypt_payload(
    body: Bytes,
    public_key: RsaPublicKey,
) -> result::Result<impl warp::Reply, Infallible> {
    log::debug!("encrypt_payload: {:?}", body);
    match encrypt_content(&body, public_key) {
        Ok(content) => {
            log::info!("Encryption successful... {:?}", content);
            Ok(warp::reply::with_status(
                general_purpose::STANDARD.encode(content),
                StatusCode::OK,
            ))
        }
        Err(err) => Ok(warp::reply::with_status(
            format!("Encryption failed: {:?}", err).to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}

pub async fn decrypt_payload(
    body: Bytes,
    private_key: RsaPrivateKey,
) -> result::Result<impl warp::Reply, Infallible> {
    log::debug!("decrypt_payload: {:?}", body);
    match general_purpose::STANDARD.decode(body) {
        Ok(decoded) => {
            let decoded_bytes = Bytes::from(decoded);
            match decrypt_content(&decoded_bytes, private_key) {
                Ok(content) => {
                    log::info!("Decryption successful... {:?}", content);
                    Ok(warp::reply::with_status(
                        general_purpose::STANDARD.encode(content),
                        StatusCode::OK,
                    ))
                }
                Err(err) => {
                    log::info!("Decryption failed... {:?}", err);
                    Ok(warp::reply::with_status(
                        format!("Decryption failed: {:?}", err).to_string(),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        }
        Err(err) => {
            log::info!("Decryption failed... {:?}", err);
            Ok(warp::reply::with_status(
                format!("Decryption failed (invalid base64 payload) {:?}", err).to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

fn with_private_key(
    key: RsaPrivateKey,
) -> impl Filter<Extract = (RsaPrivateKey,), Error = Infallible> + Clone {
    warp::any().map(move || key.clone())
}

fn with_public_key(
    key: RsaPublicKey,
) -> impl Filter<Extract = (RsaPublicKey,), Error = Infallible> + Clone {
    warp::any().map(move || key.clone())
}

fn with_encoding_key(
    key: EncodingKey,
) -> impl Filter<Extract = (EncodingKey,), Error = Infallible> + Clone {
    warp::any().map(move || key.clone())
}

fn with_decoding_key(
    key: DecodingKey,
) -> impl Filter<Extract = (DecodingKey,), Error = Infallible> + Clone {
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

pub fn body_as_bytes() -> warp::filters::BoxedFilter<(Bytes,)> {
    warp::any().and(warp::filters::body::bytes()).boxed()
}

pub fn body_as_base64() -> warp::filters::BoxedFilter<(Vec<u8>,)> {
    warp::any()
        .and(warp::filters::body::bytes())
        .map(|bytes: Bytes| general_purpose::STANDARD_NO_PAD.decode(bytes).unwrap())
        .boxed()
}

fn default_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.set_issuer(&[issuer()]);
    validation
}

#[derive(Debug)]
pub struct Unauthorized;

#[derive(Debug)]
pub struct MissingApiKey;

impl reject::Reject for Unauthorized {}

impl reject::Reject for MissingApiKey {}

fn api_keys_validation(
    api_keys: HashSet<String>,
) -> impl Filter<Extract = ((),), Error = Rejection> + Clone {
    warp::header::optional::<String>("x-api-key")
        .map(move |n: Option<String>| (n, api_keys.clone()))
        .and_then(|t: (Option<String>, HashSet<String>)| async move {
            if t.1.is_empty() {
                Ok(())
            } else if let Some(hdr) = t.0 {
                if t.1.contains(&hdr) {
                    Ok(())
                } else {
                    Err(reject::custom(Unauthorized))
                }
            } else {
                Err(reject::custom(MissingApiKey))
            }
        })
}

#[derive(Debug, Deserialize, Clone)]
pub struct BcryptCheckDTO {
    pub hash: String,
    pub plain: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct BcryptCheckResultDTO {
    pub password_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub error: Option<String>,
}

fn bcrypt_check_body() -> impl Filter<Extract = (BcryptCheckDTO,), Error = warp::Rejection> + Clone
{
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

pub async fn bcrypt_check(body: BcryptCheckDTO) -> result::Result<impl warp::Reply, Infallible> {
    log::debug!("bcryp_check: {:?}", body);

    match bcrypt::verify(body.plain, body.hash.as_str()) {
        Ok(is_valid) => {
            log::info!("Bcrypt check: {:?}", is_valid);
            Ok(warp::reply::with_status(
                warp::reply::json(&BcryptCheckResultDTO {
                    password_valid: is_valid,
                    error: None,
                }),
                StatusCode::OK,
            ))
        }
        Err(e) => {
            log::info!("Bcrypt check: {:?}", e);
            Ok(warp::reply::with_status(
                warp::reply::json(&BcryptCheckResultDTO {
                    password_valid: false,
                    error: Some(format!("{:?}", e)),
                }),
                StatusCode::BAD_REQUEST,
            ))
        }
    }
}

#[tokio::main]
async fn main() {
    let version = env!("CARGO_PKG_VERSION");
    log::info!("Starting jwtd {}", version);

    if env::var_os("RUST_LOG").is_none() {
        // Set `RUST_LOG=jwtd=debug` to see debug logs,
        // info - only shows access logs.
        env::set_var("RUST_LOG", "jwtd=debug");
    }
    pretty_env_logger::init();

    let raw_private_key = raw_private_key().unwrap();
    let private_key = private_key(raw_private_key.clone()).unwrap();
    let public_key = private_key.to_public_key();
    let encoding_key = EncodingKey::from_rsa_pem(&raw_private_key).unwrap();
    let decoding_key = DecodingKey::from_rsa_raw_components(
        &public_key.n().to_bytes_be(),
        &public_key.e().to_bytes_be(),
    );
    log::info!("Private key loaded");

    let api_keys: HashSet<String> = match env::var("API_KEYS") {
        Ok(keys) => {
            log::info!("API_KEYS loaded");
            keys.split(",").into_iter().map(|s| s.to_string()).collect()
        }
        _ => {
            log::info!("No API_KEYS defined");
            HashSet::new()
        }
    };

    let bcrypt_check = warp::path!("bcrypt" / "check")
        .and(warp::post())
        .and(bcrypt_check_body())
        .and_then(bcrypt_check);

    let sign = warp::path!("sign")
        .and(api_keys_validation(api_keys.clone()))
        .untuple_one()
        .and(warp::post())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .and(warp::query::<SignOpts>())
        .and(with_encoding_key(encoding_key))
        .and_then(sign_claims);

    let validation = default_validation();
    let verify = warp::path!("verify")
        .and(api_keys_validation(api_keys.clone()))
        .untuple_one()
        .and(warp::post())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(body_as_string())
        .and(with_decoding_key(decoding_key.clone()))
        .and(with_validation(validation.clone()))
        .and_then(verify_token);

    let encrypt = warp::path!("encrypt")
        .and(api_keys_validation(api_keys.clone()))
        .untuple_one()
        .and(warp::post())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(body_as_bytes())
        .and(with_public_key(public_key.clone()))
        .and_then(encrypt_payload);

    let decrypt = warp::path!("decrypt")
        .and(api_keys_validation(api_keys.clone()))
        .untuple_one()
        .and(warp::post())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(body_as_bytes())
        .and(with_private_key(private_key.clone()))
        .and_then(decrypt_payload);

    let health = warp::path!("health").and(warp::get()).map(|| {
        Ok(warp::reply::with_status(
            warp::reply::json(&HealthDTO {
                status: "OK".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            }),
            StatusCode::OK,
        ))
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

    let routes = encrypt
        .or(decrypt)
        .or(sign)
        .or(verify)
        .or(health)
        .or(bcrypt_check);
    log::info!("Server starting on port {:?}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}

#[cfg(test)]
mod tests {
    use rsa::pkcs1::{LineEnding};
    use rsa::pkcs8::EncodePublicKey;
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[ctor::ctor] // see https://stackoverflow.com/a/63442117
    fn init() {
        env::set_var("RUST_LOG", "jwtd=debug");
        pretty_env_logger::init();
    }

    #[test]
    fn test_extract_public_key_from_private_key() {
        let raw_bytes = fs::read("./local/key_prv.pem".to_string()).unwrap();
        let rsa = private_key(raw_bytes).unwrap();
        match rsa.to_public_key().to_public_key_pem(LineEnding::LF) {
            Ok(key) => assert_eq!(
                key,
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
        let raw_private_key = fs::read("./local/key_prv.pem".to_string()).unwrap();
        let private_key = private_key(raw_private_key.clone()).unwrap();
        let public_key = private_key.to_public_key();
        let decoding_key = DecodingKey::from_rsa_raw_components(
            &public_key.n().to_bytes_be(),
            &public_key.e().to_bytes_be(),
        );

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
        match decode_token(token, decoding_key, validation) {
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
        let raw_bytes = fs::read("./local/key_prv.pem".to_string()).unwrap();
        let priv_key = private_key(raw_bytes).unwrap();
        let pub_key = priv_key.to_public_key();
        let buff = Bytes::copy_from_slice("Hello Margarett!".as_bytes());
        match encrypt_content(&buff, pub_key.clone()) {
            Ok(encrypted) => match decrypt_content(&encrypted, priv_key.clone()) {
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
