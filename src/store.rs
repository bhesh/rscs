//! Certificate Store

use crate::{
    error::Error,
    loader::{Loader, MemLoader},
    name::NameBytes,
};
use alloc::boxed::Box;
use core::marker::PhantomData;
use x509_verify::x509_cert::Certificate;

/// Certificate Store implementation. Can store and retrieve certificates by a defined, unique ID.
#[derive(Clone, Debug)]
pub struct CertificateStore<Id, L>
where
    L: Loader<Id>,
    Id: Eq + for<'a> TryFrom<&'a Certificate>,
    Error: for<'a> From<<Id as TryFrom<&'a Certificate>>::Error>,
{
    inner: L,
    phantom: PhantomData<Id>,
}

impl<Id, L> CertificateStore<Id, L>
where
    L: Loader<Id>,
    Id: Eq + for<'a> TryFrom<&'a Certificate>,
    Error: for<'a> From<<Id as TryFrom<&'a Certificate>>::Error>,
{
    /// Creates an empty [`CertificateStore`]
    pub fn new() -> Self {
        Self {
            inner: L::default(),
            phantom: PhantomData::default(),
        }
    }

    /// Inserts a certificate into the certificate store. Returns [`Error`] if the conversion from
    /// `Certificate` to `Id` fails.
    pub fn insert(&mut self, cert: Certificate) -> Result<Option<Certificate>, Error> {
        let id = Id::try_from(&cert)?;
        Ok(self.inner.insert(id, cert))
    }

    /// Removes a certificate from the certificate store. The certificate is returned if any was
    /// found.
    pub fn remove(&mut self, id: &Id) -> Option<Certificate> {
        self.inner.remove(id)
    }

    /// Retrieves a certificate from the certificate store. Returns `None` if nothing was found.
    pub fn get(&self, id: &Id) -> Option<&Certificate> {
        self.inner.get(id)
    }

    /// Returns an iterator over the internal storage in the form of a Tuple `(&Id, &Certificate)`
    pub fn iter(&self) -> Box<dyn Iterator<Item = (&'_ Id, &'_ Certificate)> + '_> {
        self.inner.iter()
    }
}

/// Memory-only certificate store
pub type MemCertificateStore = CertificateStore<NameBytes, MemLoader>;
