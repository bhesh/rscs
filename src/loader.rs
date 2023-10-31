//! Certificate Loader

use x509_verify::x509_cert::Certificate;

mod mem;

pub use mem::MemLoader;

pub trait Loader<Id>
where
    Id: PartialEq + Eq,
{
    fn insert(&mut self, id: Id, cert: Certificate) -> Option<Certificate>;

    fn remove(&mut self, id: &Id) -> Option<Certificate>;

    fn get(&self, id: &Id) -> Option<&Certificate>;

    fn iter<'a, I>(&'a self) -> I
    where
        I: Iterator<Item = (&'a Id, &'a Certificate)>;
}
