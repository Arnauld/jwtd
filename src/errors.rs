use std::fmt;
use std::result;

/// A crate private constructor for `Error`.
pub fn new_error(kind: ErrorKind) -> Error {
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
    TokenError(jsonwebtoken::errors::ErrorKind),
    PrivateKeyError(jsonwebtoken::errors::Error),
    PrivateKeyReadingError(std::io::Error),
    PrivateKeyLoadingError(String),
    MissingConfigError(String),
    DecryptError(String),
    EncryptError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self.0 {
            ErrorKind::TokenError(ref err) => write!(f, "Token error: {:?}", err),
            ErrorKind::PrivateKeyReadingError(ref err) => {
                write!(f, "PrivateKey reading error: {}", err)
            }
            ErrorKind::PrivateKeyError(ref err) => write!(f, "PrivateKey error: {}", err),
            ErrorKind::PrivateKeyLoadingError(ref err) => write!(f, "PrivateKey error: {}", err),
            ErrorKind::MissingConfigError(ref err) => write!(f, "MissingConfig error: {}", err),
            ErrorKind::DecryptError(ref err) => write!(f, "Decrypt error: {}", err),
            ErrorKind::EncryptError(ref err) => write!(f, "Encrypt error: {}", err),
        }
    }
}
