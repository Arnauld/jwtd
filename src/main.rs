use warp::Filter;
use serde::{Serialize, Deserialize};
use jsonwebtoken::{encode, Header, Algorithm, EncodingKey};
use jsonwebtoken::errors::Result;
use chrono::prelude::*;

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,         // Optional. Subject (whom token refers to)
    aud: String,         // Optional. Audience
    iat: usize,          // Optional. Issued at (as UTC timestamp)
    exp: usize,          // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iss: String,         // Optional. Issuer
}

pub fn generate_token(aid: &String) -> Result<String> {
    let header = Header::new(Algorithm::HS256);
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
    return encode(&header, &claims, &EncodingKey::from_secret("secret".as_ref()));
}


#[tokio::main]
async fn main() {
    // GET /hello/warp => 200 OK with body "Hello, warp!"
    let hello = warp::path!("hello" / String)
        .map(|name| format!("Hello, {}!", name));

    warp::serve(hello)
        .run(([127, 0, 0, 1], 3030))
        .await;
}
