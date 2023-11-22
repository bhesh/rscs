//! Path Validation Errors

use alloc::fmt;

/// Path validation error types
#[derive(Debug)]
pub enum Error {
    /// ASN.1 errors
    Asn1(der::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Error::Asn1(e) => write!(f, "ASN.1 error: {}", e),
        }
    }
}

impl From<der::Error> for Error {
    fn from(other: der::Error) -> Self {
        Self::Asn1(other)
    }
}
