//! Certificate Loader

use alloc::boxed::Box;
use x509_verify::x509_cert::Certificate;

mod mem;

pub use mem::MemLoader;

pub trait Loader<Id>: Default
where
    Id: Eq,
{
    fn insert(&mut self, name: Id, cert: Certificate) -> Option<Certificate>;

    fn remove(&mut self, id: &Id) -> Option<Certificate>;

    fn get(&self, id: &Id) -> Option<&Certificate>;

    fn iter(&self) -> Box<dyn Iterator<Item = (&'_ Id, &'_ Certificate)> + '_>;
}
