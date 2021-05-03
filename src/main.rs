use warp::Filter;
use serde::{Serialize, Deserialize};
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
}

pub fn private_key() -> Result<Vec<u8>> {
    //log::debug!("envs {:?}", env::vars);
    let location = env::var("JWT_PRIV_KEY_LOCATION")
                        .expect("Environment variable 'PRIV_KEY_LOCATION' not set; unable to read private key");

    return fs::read(location)
                .map_err(|err| new_error(ErrorKind::PrivateKeyReadingError(err)));
}

pub fn issuer() -> String {
    return match env::var("JWT_ISSUER") {
        Ok(s) => s,
        _ => "jwtd".to_string(),
    }
} 

pub fn generate_token<T: Serialize>(claims: &T) -> Result<String> {
    let header = Header::new(Algorithm::HS256);
    let priv_key = private_key().expect("Unable to load private key to sign JWT");
    return encode(&header, &claims, &EncodingKey::from_rsa_pem(&priv_key)
                                        .map_err(|err| new_error(ErrorKind::PrivateKeyError(err)))?)
            .map_err(|err| new_error(ErrorKind::TokenError(err)));
}

pub async fn sign_claims(body: serde_json::Value, sign_opts: SignOpts) -> result::Result<impl warp::Reply, Infallible> {
    log::debug!("sign_claims: {:?} // {:?}", body, sign_opts);
    let claims = match sign_opts.generate {
        Some(generate) => {
            match body {
                serde_json::Value::Object(m) => {
                    let mut m = m.clone();
                    let issued_at = Utc::now().timestamp();
                    let expiration = Utc::now()
                        .checked_add_signed(chrono::Duration::seconds(60))
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

    let token = generate_token(&claims)
                    .expect("Failed to generate token...");
    Ok(warp::reply::json(&token))
}

#[tokio::main]
async fn main() {
    let count = env::vars()
        .inspect(|(key, value)| println!("'{}': {}", key, value))
        .count();
    println!("#{} env vars", count);

    match env::var("PRIV_KEY_LOCATION".to_string()) {
        Ok(val) => println!(":: {:?}", val),
        Err(e) => println!("couldn't interpret :: {}", e),
    }

    if env::var_os("RUST_LOG").is_none() {
        // Set `RUST_LOG=jwtd=debug` to see debug logs,
        // info - only shows access logs.
        env::set_var("RUST_LOG", "jwtd=debug");
    }
    pretty_env_logger::init();

    let sign = warp::path!("sign")
                    .and(warp::post())
                    .and(warp::body::content_length_limit(1024 * 32))
                    .and(warp::body::json())
                    .and(warp::query::<SignOpts>())
                    .and_then(sign_claims);

    let port = env::var("PORT")
                    .map(|a| match a.parse() {
                                        Ok(n) => n,
                                        err => {
                                            eprintln!("error: port not an integer {:?}, fallback on default", err);
                                            8080
                                        }
                                    })
                    .unwrap_or_else(|_err| {
                        eprintln!("Port not provided, fallback on default");
                        8080
                    });

    let routes = sign;
    println!("Server starting on port {}", port);
    warp::serve(routes)
        .run(([127, 0, 0, 1], port))
        .await;
}
