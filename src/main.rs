use warp::Filter;
use serde::{Serialize, Deserialize};
use jsonwebtoken::{encode, Header, Algorithm, EncodingKey};
use chrono::prelude::*;
use std::env;
use std::fs;
use std::result;
use std::fmt;
use std::convert::Infallible;

/// A crate private constructor for `Error`.
pub(crate) fn new_error(kind: ErrorKind) -> Error {
    Error(Box::new(kind))
}

/// A type alias for `Result<T, jwtd::Error>`.
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(Box<ErrorKind>);

impl Error {
    /// Return the specific type of this error.
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }

    /// Unwrap this error into its underlying type.
    pub fn into_kind(self) -> ErrorKind {
        *self.0
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub enum ErrorKind {
    TokenError(jsonwebtoken::errors::Error),
    PrivateKeyReadingError(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self.0 {
            ErrorKind::TokenError(ref err) => write!(f, "Token error: {}", err),
            ErrorKind::PrivateKeyReadingError(ref err) => write!(f, "PrivateKey reading error: {}", err),
        }
    }
}


/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,         // Optional. Subject (whom token refers to)
    aud: String,         // Optional. Audience
    iat: usize,          // Optional. Issued at (as UTC timestamp)
    exp: usize,          // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iss: String,         // Optional. Issuer
}

// The query parameters for list_todos.
#[derive(Debug, Deserialize)]
pub struct Auth {
    pub aid: Option<String>,
    pub roles: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SignOpts {
    pub generate_iat: Option<bool>,
}


fn private_key() -> Result<String> {
    let location = env::var("PRIV_KEY_LOCATION")
                        .expect("Environment variable 'PRIV_KEY_LOCATION' not set; unable to read private key");

    return fs::read_to_string(location)
                .map_err(|err| new_error(ErrorKind::PrivateKeyReadingError(err)));
}

pub fn generate_token<T: Serialize>(claims: &T) -> Result<String> {
    let header = Header::new(Algorithm::HS256);
    return encode(&header, &claims, &EncodingKey::from_secret("secret".as_ref()))
            .map_err(|err| new_error(ErrorKind::TokenError(err)));
}

fn json_to_Auth() -> impl Filter<Extract = (Auth,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

pub async fn auth_token(opts: Auth) -> result::Result<impl warp::Reply, Infallible> {
    log::debug!("auth_token: {:?}", opts);

    let aid = match opts.aid {
                    Some(s) => s,
                    None => "AGENT:007".to_string(),
                };
    let issued_at = Utc::now().timestamp();
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::seconds(60))
        .expect("valid timestamp")
        .timestamp();
    let claims = Claims {
        sub: aid.to_owned(),
        aud: "".to_string(),
        iat: issued_at as usize,
        exp: expiration as usize,
        iss: "jwtd".to_string(),
    };
    let token = generate_token(&claims)
                    .expect("Failed to generate token...");
    Ok(warp::reply::json(&token))
}

pub async fn sign_claims(body: serde_json::Value, signOpts: SignOpts) -> result::Result<impl warp::Reply, Infallible> {
    log::debug!("sign_claims: {:?} // {:?}", body, signOpts);
    let token = generate_token(&body)
                    .expect("Failed to generate token...");
    Ok(warp::reply::json(&token))
}

#[tokio::main]
async fn main() {
    if env::var_os("RUST_LOG").is_none() {
        // Set `RUST_LOG=jwtd=debug` to see debug logs,
        // info - only shows access logs.
        env::set_var("RUST_LOG", "jwtd=debug");
    }
    pretty_env_logger::init();

    // GET /hello/warp => 200 OK with body "Hello, warp!"
    let hello = warp::path!("hello" / String)
                    .and(warp::get())
                    .map(|name| format!("Hello, {}!", name));
    let auth  = warp::path!("auth")
                    .and(warp::post())
                    .and(json_to_Auth())
                    .and_then(auth_token);

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

    let routes = hello
                    .or(auth)
                    .or(sign);

    println!("Server starting on port {}", port);
    warp::serve(routes)
        .run(([127, 0, 0, 1], port))
        .await;
}
