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
{
    inner: L,
    phantom: PhantomData<Id>,
}

impl<Id, L> CertificateStore<Id, L>
where
    L: Loader<Id>,
    Id: Eq + for<'a> TryFrom<&'a Certificate>,
{
    /// Creates an empty [`CertificateStore`]
    pub fn new() -> Self {
        Self {
            inner: L::default(),
            phantom: PhantomData::default(),
        }
    }

    /// Inserts a certificate into the certificate store. Returns `E` if the conversion from
    /// `Certificate` to `Id` fails.
    pub fn insert<E>(&mut self, cert: Certificate) -> Result<Option<Certificate>, E>
    where
        E: for<'a> From<<Id as TryFrom<&'a Certificate>>::Error>,
    {
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

    /// Verifies `cert` up its own issuance chain. Verification ends once a certificate in `cert`'s
    /// chain is found in the certificate store and all signatures are verified. Verification fails
    /// when any of the following hold true:
    ///
    /// - None of the certificates in the chain are trusted
    /// - The trust chain is broken and can not be inferred
    /// - Any of the certificates in the trust chain are expired
    /// - Any of the certificates in the trust chain are not yet valid
    /// - Signature verification fails
    ///
    /// This function makes no guarantees about the certificates in `chain`. The sole focus is to
    /// verify `cert` all the way up its own trust chain. The `chain` is only used when an issuer
    /// in `cert`'s trust chain is not already present in the certificate store.
    ///
    /// This function does not provide any revocation checking.
    pub fn verify(&self, cert: &Certificate, chain: &[&Certificate]) -> Result<(), Error> {
        unimplemented!()
    }
}

/// Memory-only certificate store
pub type MemCertificateStore = CertificateStore<NameBytes, MemLoader>;
