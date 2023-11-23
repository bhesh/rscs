//! Path Validation Errors

use alloc::fmt;
use der::asn1::ObjectIdentifier;

/// Certificate parsing error types
#[derive(Clone, Debug)]
pub enum CertificateError {
    /// Invalid certificate policies. Typically, a duplicate policy.
    InvalidPolicies,

    /// Invalid name constraints. Typically, if minimum or maximum are not the default values. Or
    /// the sequence is empty.
    InvalidNameConstraints,

    /// Unsupported critical extension
    UnsupportedCriticalExtension(ObjectIdentifier),

    /// ASN.1 errors
    Asn1(der::Error),
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            CertificateError::InvalidPolicies => write!(f, "Invalid policies"),
            CertificateError::InvalidNameConstraints => write!(f, "Invalid name constraints"),
            CertificateError::UnsupportedCriticalExtension(oid) => {
                write!(f, "Unsupported critical extension: {}", oid)
            }
            CertificateError::Asn1(e) => write!(f, "ASN.1 error: {}", e),
        }
    }
}

impl From<der::Error> for CertificateError {
    fn from(other: der::Error) -> Self {
        Self::Asn1(other)
    }
}

/// Path validation error types
#[derive(Debug)]
pub enum Error {
    /// Certificate parsing errors
    Certificate(CertificateError),

    /// ASN.1 errors
    Asn1(der::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Error::Certificate(e) => write!(f, "Certificate error: {}", e),
            Error::Asn1(e) => write!(f, "ASN.1 error: {}", e),
        }
    }
}

impl From<CertificateError> for Error {
    fn from(other: CertificateError) -> Self {
        Self::Certificate(other)
    }
}

impl From<der::Error> for Error {
    fn from(other: der::Error) -> Self {
        Self::Asn1(other)
    }
}
