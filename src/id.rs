//! Certificate store ID

use alloc::string::String;
use der::Encode;
use digest::Digest;
use sha2::Sha256;
use x509_verify::x509_cert::name::Name;

#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct CertificateId([u8; 32]);

impl CertificateId {
    pub fn as_str(&self) -> String {
        String::from(hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for CertificateId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for CertificateId {
    fn from(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

impl TryFrom<&Name> for CertificateId {
    type Error = der::Error;

    fn try_from(name: &Name) -> Result<Self, Self::Error> {
        Ok(Self::from(name.to_der()?.as_ref()))
    }
}
