//! Certificate Store

use crate::loader::Loader;
use core::marker::PhantomData;
use x509_verify::x509_cert::Certificate;

#[derive(Clone, Debug)]
pub struct CertificateStore<Id, L>(L, PhantomData<Id>)
where
    L: Loader<Id>,
    Id: Eq;

impl<Id, L> CertificateStore<Id, L>
where
    L: Loader<Id>,
    Id: Eq,
{
    pub fn new() -> Self {
        Self(L::default(), PhantomData::default())
    }
}
