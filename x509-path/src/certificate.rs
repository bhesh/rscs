//! Stripped certificate representation

use x509_cert::Certificate;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CertTarget<'a>(&'a Certificate);
