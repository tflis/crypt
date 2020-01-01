use openssl;
use std::fmt::Display;
use std::string;
use std::{error, io};

pub type CryptResult<T> = Result<T, CryptError>;

#[derive(Debug)]
pub enum CryptError {
    Io(io::Error),
    Str(string::FromUtf8Error),
    OpenSSL(openssl::error::ErrorStack),
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
impl_from_error!(string::FromUtf8Error, CryptError::Str);
impl_from_error!(openssl::error::ErrorStack, CryptError::OpenSSL);

impl Display for CryptError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        match *self {
            CryptError::Io(ref err) => err.fmt(f),
            CryptError::Str(ref err) => err.fmt(f),
            CryptError::OpenSSL(ref err) => err.fmt(f),
        }
    }
}

impl error::Error for CryptError {
    fn description(&self) -> &str {
        match *self {
            CryptError::Io(ref err) => err.description(),
            CryptError::Str(ref err) => err.description(),
            CryptError::OpenSSL(ref err) => err.description(),
        }
    }

    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            CryptError::Io(ref err) => Some(err),
            CryptError::Str(ref err) => Some(err),
            CryptError::OpenSSL(ref err) => Some(err),
        }
    }
}
