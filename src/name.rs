//! NameBytes

use crate::error::Error;
use alloc::vec::Vec;
use core::hash::Hash;
use der::Encode;
use x509_verify::x509_cert::{name::Name, Certificate};

/// X.509 Name structure represented as a `Vec<u8>` of the DER-encoded bytes
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct NameBytes(Vec<u8>);

impl TryFrom<&Name> for NameBytes {
    type Error = Error;

    fn try_from(name: &Name) -> Result<Self, Self::Error> {
        Ok(Self(name.to_der()?))
    }
}

impl TryFrom<&Certificate> for NameBytes {
    type Error = Error;

    /// Creates [`NameBytes`] from the `subject` of the Certificate
    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        Self::try_from(&cert.tbs_certificate.subject)
    }
}
