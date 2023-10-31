//! Certificate Store

use crate::loader::Loader;
use core::marker::PhantomData;
use x509_verify::x509_cert::Certificate;

pub struct CertificateStore<Id, L>(L, PhantomData<Id>)
where
    L: Loader<Id>,
    Id: PartialEq + Eq;
