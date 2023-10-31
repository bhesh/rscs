//! In-memory loader

use crate::{error::Error, loader::Loader};
use alloc::{boxed::Box, vec::Vec};
use core::hash::Hash;
use der::Encode;
use hashbrown::HashMap;
use x509_verify::x509_cert::{name::Name, Certificate};

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct NameBytes(Vec<u8>);

impl TryFrom<&Name> for NameBytes {
    type Error = Error;

    fn try_from(name: &Name) -> Result<Self, Self::Error> {
        Ok(Self(name.to_der()?))
    }
}

pub struct MemLoader(HashMap<NameBytes, Certificate>);

impl MemLoader {
    pub fn new() -> Self {
        Self(HashMap::new())
    }
}

impl Loader<NameBytes> for MemLoader {
    fn insert(&mut self, id: NameBytes, cert: Certificate) -> Option<Certificate> {
        self.0.insert(id, cert)
    }

    fn remove(&mut self, id: &NameBytes) -> Option<Certificate> {
        self.0.remove(id)
    }

    fn get(&self, id: &NameBytes) -> Option<&Certificate> {
        self.0.get(id)
    }

    fn iter(&self) -> Box<dyn Iterator<Item = (&'_ NameBytes, &'_ Certificate)> + '_> {
        Box::from(self.0.iter())
    }
}
