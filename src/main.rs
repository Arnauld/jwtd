use warp::{
    http::StatusCode,
    Filter
};
use serde::{Serialize, Deserialize};
use serde_json;
use jsonwebtoken::{encode, Header, Algorithm, EncodingKey};
use chrono::prelude::*;
use std::env;
use std::fs;
use std::result;
use std::convert::Infallible;
use jwtd::errors::{new_error, ErrorKind, Result};


#[derive(Debug, Deserialize)]
pub struct SignOpts {
    pub generate: Option<String>,
    pub duration_seconds: Option<String>,
}

pub fn private_key() -> Result<Vec<u8>> {
    let location = env::var("JWT_PRIV_KEY_LOCATION".to_string())
                        .map_err(|_| new_error(ErrorKind::MissingConfigError("Environment variable 'JWT_PRIV_KEY_LOCATION' not set; unable to read private key".to_string())))?;

    return fs::read(location)
                .map_err(|err| new_error(ErrorKind::PrivateKeyReadingError(err)));
}

pub fn issuer() -> String {
    return match env::var("JWT_ISSUER".to_string()) {
        Ok(s) => s,
        _ => "jwtd".to_string(),
    }
} 

pub fn generate_token<T: Serialize>(
    claims: &T, 
    priv_key: Vec<u8>
) -> Result<String> {
    let header = Header::new(Algorithm::RS256);
    let encoding_key = EncodingKey::from_rsa_pem(&priv_key)
                            .map_err(|err| new_error(ErrorKind::PrivateKeyError(err)))?;
    return encode(&header, &claims, &encoding_key)
            .map_err(|err| new_error(ErrorKind::TokenError(err)));
}

pub async fn sign_claims(
    body: serde_json::Value, 
    sign_opts: SignOpts, 
    private_key: Vec<u8>
) -> result::Result<impl warp::Reply, Infallible> {
    log::debug!("sign_claims: {:?} // {:?}", body, sign_opts);
    let claims = match sign_opts.generate {
        Some(generate) => {
            match body {
                serde_json::Value::Object(m) => {
                    let mut m = m.clone();
                    let duration = sign_opts.duration_seconds.map_or(600, |s| s.parse().unwrap_or(600));
                    let issued_at = Utc::now().timestamp();
                    let expiration = Utc::now()
                        .checked_add_signed(chrono::Duration::seconds(duration))
                        .expect("valid timestamp")
                        .timestamp();
                    if generate.contains("iat") {
                        m.insert("iat".to_string(), serde_json::Value::Number(issued_at.into()));
                    }
                    if generate.contains("exp") {
                        m.insert("exp".to_string(), serde_json::Value::Number(expiration.into()));
                    }
                    if generate.contains("iss") {
                        m.insert("iss".to_string(), serde_json::Value::String(issuer()));
                    }
                    serde_json::Value::Object(m)
                },
                _ => body.clone(),
            }
        },
        _ => body.clone(),
    };

    match generate_token(&claims, private_key) {
        Ok(token) =>
            Ok(warp::reply::with_status(
                token,
                StatusCode::OK,
            )),
        Err(err)  => {
            log::error!("Ouch... {}", err);
            Ok(warp::reply::with_status(
                format!("Something bad happened: {:?}", err).to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        },
    }
}

fn with_private_key(
    priv_key: Vec<u8>,
) -> impl Filter<Extract = (Vec<u8>,), Error = Infallible> + Clone {
    warp::any().map(move || priv_key.clone())
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
    log::info!("Private key loaded");

    let sign = warp::path!("sign")
                    .and(warp::post())
                    .and(warp::body::content_length_limit(1024 * 32))
                    .and(warp::body::json())
                    .and(warp::query::<SignOpts>())
                    .and(with_private_key(private_key.clone()))
                    .and_then(sign_claims);

    let health = warp::path!("health")
                    .and(warp::get())
                    .map(|| "OK");

    let port = env::var("PORT")
                    .map(|a| match a.parse() {
                        Ok(v) => v,
                        _ => 8080
                    })
                    .unwrap_or_else(|_err| {
                        log::info!("Port not provided, fallback on default");
                        8080
                    });

    let routes = sign.or(health);
    log::info!("Server starting on port {}", port);
    warp::serve(routes)
        .run(([0, 0, 0, 0], port))
        .await;
}
