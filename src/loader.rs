//! Certificate Loader

use alloc::boxed::Box;
use x509_verify::x509_cert::Certificate;

mod mem;

pub use mem::MemLoader;

/// Trait for defining a certificate loader to be used within the certificate store
pub trait Loader<Id>: Default
where
    Id: Eq,
{
    /// Inserts a certificate into the internal storage. Returns the Certificate it replaces, if
    /// any. `None`, otherwise.
    fn insert(&mut self, id: Id, cert: Certificate) -> Option<Certificate>;

    /// Removes a certificate from the internal storage and returns it. Returns `None` if nothing
    /// was removed.
    fn remove(&mut self, id: &Id) -> Option<Certificate>;

    /// Retrieves a certificate from the internal storage and returns it. Returns `None` if no
    /// certificate was found.
    fn get(&self, id: &Id) -> Option<&Certificate>;

    /// Returns an iterator over the internal storage in the form of a Tuple `(&Id, &Certificate)`
    fn iter(&self) -> Box<dyn Iterator<Item = (&'_ Id, &'_ Certificate)> + '_>;
}
