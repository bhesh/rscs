//! Subject key identifier representation

use der::{asn1::OctetStringRef, referenced::OwnedToRef};
use digest::Digest;
use sha1::Sha1;
use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::impl_newtype;

/// SHA-1 digest output size
const OUTPUT_SIZE: usize = 20;

/// Referenced subject key identifier
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SubjectKeyIdentifierRef<'a>(pub OctetStringRef<'a>);

impl_newtype!(SubjectKeyIdentifierRef<'a>, OctetStringRef<'a>);

/// Subject key identifier representation
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyIdentifier<'a> {
    /// Referenced from subject key identifier extension
    Referenced(&'a [u8]),

    /// SHA-1 digest of the subject public key
    Owned([u8; OUTPUT_SIZE]),
}

impl<'a> From<SubjectKeyIdentifierRef<'a>> for KeyIdentifier<'a> {
    fn from(other: SubjectKeyIdentifierRef<'a>) -> Self {
        Self::Referenced(other.0.as_bytes())
    }
}

impl From<SubjectPublicKeyInfoRef<'_>> for KeyIdentifier<'static> {
    fn from(other: SubjectPublicKeyInfoRef<'_>) -> Self {
        let mut output = [0u8; OUTPUT_SIZE];
        Sha1::new_with_prefix(other.subject_public_key.raw_bytes())
            .finalize_into((&mut output).into());
        Self::Owned(output)
    }
}

impl From<&SubjectPublicKeyInfoOwned> for KeyIdentifier<'static> {
    fn from(other: &SubjectPublicKeyInfoOwned) -> Self {
        Self::from(other.owned_to_ref())
    }
}
