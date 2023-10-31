//! Certificate Loader

use crate::CertificateId;
use x509_verify::x509_cert::Certificate;

pub trait CertificateLoader {
    fn load(id: CertificateId) -> Option<Certificate>;
}
