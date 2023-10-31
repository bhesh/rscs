//! Certificate store ID

use alloc::string::String;
use der::Encode;
use digest::Digest;
use sha2::Sha256;
use x509_verify::x509_cert::name::Name;

pub trait AsStr {
    fn as_str(&self) -> String;
}

/// A quick reference to the Certificate
///
/// From an issued certificate's point of view, only the issuer's name is provided for lookup.
/// X.509 certificates do have a field for an issuer's unique identity. However, that field is
/// optional. Thus, the ID of the certificate will be the SHA-256 of the DER encoded subject.
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct CertificateId(T)
where
    T: Copy + Clone + Debug + PartialOrd + Ord + PartialEq + Eq + AsStr + AsRef<[u8]> + From<&[u8]>;

impl CertificateId {
    pub fn as_str(&self) -> String {
        self.0.as_str()
    }
}

impl AsRef<[u8]> for CertificateId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
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
