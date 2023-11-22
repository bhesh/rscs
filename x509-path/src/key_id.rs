//! SubjectKeyIdentifier representation

use crate::Error;
use alloc::vec::Vec;
use const_oid::db::rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER;
use der::{asn1::OctetString, Decode};
use digest::Digest;
use sha1::Sha1;
use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::{ext::pkix::SubjectKeyIdentifier, Certificate};

/// SubjectKeyIdentifier representation
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyId(Vec<u8>);

impl From<Vec<u8>> for KeyId {
    fn from(other: Vec<u8>) -> Self {
        Self(other)
    }
}

impl From<OctetString> for KeyId {
    fn from(other: OctetString) -> Self {
        Self::from(other.into_bytes())
    }
}

impl From<SubjectKeyIdentifier> for KeyId {
    fn from(other: SubjectKeyIdentifier) -> Self {
        Self::from(other.0)
    }
}

impl From<SubjectPublicKeyInfoRef<'_>> for KeyId {
    fn from(other: SubjectPublicKeyInfoRef<'_>) -> Self {
        Self::from(Sha1::digest(other.subject_public_key.raw_bytes()).to_vec())
    }
}

impl From<&SubjectPublicKeyInfoOwned> for KeyId {
    fn from(other: &SubjectPublicKeyInfoOwned) -> Self {
        Self::from(Sha1::digest(other.subject_public_key.raw_bytes()).to_vec())
    }
}

impl From<SubjectPublicKeyInfoOwned> for KeyId {
    fn from(other: SubjectPublicKeyInfoOwned) -> Self {
        Self::from(&other)
    }
}

impl TryFrom<&Certificate> for KeyId {
    type Error = Error;

    fn try_from(cert: &Certificate) -> Result<KeyId, Self::Error> {
        if let Some(extns) = &cert.tbs_certificate.extensions {
            let mut filter = extns
                .iter()
                .filter(|e| e.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER);
            if let Some(e) = filter.next() {
                return Ok(Self::from(SubjectKeyIdentifier::from_der(
                    e.extn_value.as_bytes(),
                )?));
            }
        }
        Ok(Self::from(&cert.tbs_certificate.subject_public_key_info))
    }
}
