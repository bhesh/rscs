//! Certificate Store

use crate::CertificateId;
use hashbrown::HashMap;

pub struct CertificateStore<T> {
    map: HashMap<CertificateId, T>,
}
