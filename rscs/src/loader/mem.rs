//! In-memory loader

use crate::{loader::Loader, name::NameBytes};
use alloc::boxed::Box;
use hashbrown::HashMap;
use x509_verify::x509_cert::Certificate;

/// Memory-only certificate loader. Stores the Certificates in a `HashMap`
#[derive(Clone, Debug, Default)]
pub struct MemLoader(HashMap<NameBytes, Certificate>);

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
