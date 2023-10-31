//! Certificate Store

use crate::{CertificateId, CertificateLoader};
use hashbrown::HashMap;

pub struct CertificateStore<T>
where
    T: CertificateLoader,
{
    map: HashMap<CertificateId, T>,
}
