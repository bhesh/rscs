//! NameBytes

use crate::error::Error;
use alloc::vec::Vec;
use core::hash::Hash;
use der::Encode;
use x509_verify::x509_cert::name::Name;

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct NameBytes(Vec<u8>);

impl TryFrom<&Name> for NameBytes {
    type Error = Error;

    fn try_from(name: &Name) -> Result<Self, Self::Error> {
        Ok(Self(name.to_der()?))
    }
}
