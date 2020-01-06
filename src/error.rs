use base64;
use openssl;
use serde_json;
use std::fmt::Display;
use std::string;
use std::{error, io};

pub type CryptResult<T> = Result<T, CryptError>;

#[derive(Debug)]
pub enum CryptError {
    Io(io::Error),
    Base64Decode(base64::DecodeError),
    Str(string::FromUtf8Error),
    Json(serde_json::Error),
    OpenSSL(openssl::error::ErrorStack),
    HasherNotFound(String),
    CipherNotFound(String),
    // ...
}

macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl From<$f> for CryptError {
            fn from(f: $f) -> CryptError {
                $e(f)
            }
        }
    };
}

impl_from_error!(io::Error, CryptError::Io);
impl_from_error!(base64::DecodeError, CryptError::Base64Decode);
impl_from_error!(string::FromUtf8Error, CryptError::Str);
impl_from_error!(serde_json::Error, CryptError::Json);
impl_from_error!(openssl::error::ErrorStack, CryptError::OpenSSL);

impl Display for CryptError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        match *self {
            CryptError::Io(ref err) => err.fmt(f),
            CryptError::Base64Decode(ref err) => err.fmt(f),
            CryptError::Str(ref err) => err.fmt(f),
            CryptError::Json(ref err) => err.fmt(f),
            CryptError::OpenSSL(ref err) => err.fmt(f),
            CryptError::HasherNotFound(ref algorithm) => {
                write!(f, "Hasher algorithm: {} not implemented", algorithm)
            }
            CryptError::CipherNotFound(ref algorithm) => {
                write!(f, "Cipher algorithm: {} not implemented", algorithm)
            }
        }
    }
}

impl error::Error for CryptError {
    fn description(&self) -> &str {
        match *self {
            CryptError::Io(ref err) => err.description(),
            CryptError::Base64Decode(ref err) => err.description(),
            CryptError::Str(ref err) => err.description(),
            CryptError::Json(ref err) => err.description(),
            CryptError::OpenSSL(ref err) => err.description(),
            CryptError::HasherNotFound(ref _algorithm) => "Hasher algorithm not implemented",
            CryptError::CipherNotFound(ref _algorithm) => "Cipher algorithm not implemented",
        }
    }

    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            CryptError::Io(ref err) => Some(err),
            CryptError::Base64Decode(ref err) => Some(err),
            CryptError::Str(ref err) => Some(err),
            CryptError::Json(ref err) => Some(err),
            CryptError::OpenSSL(ref err) => Some(err),
            CryptError::HasherNotFound(ref _algorithm) => None,
            CryptError::CipherNotFound(ref _algorithm) => None,
        }
    }
}
