//! Validation target

use crate::{CertificateError, PolicySet};
use const_oid::db::rfc5912::ID_CE_CERTIFICATE_POLICIES;
use der::Decode;
use x509_cert::{ext::pkix::CertificatePolicies, Certificate};

/// Certificate target for path validation
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertTarget<'a> {
    certificate: &'a Certificate,
    policies: Option<PolicySet>,
}

impl<'a> TryFrom<&'a Certificate> for CertTarget<'a> {
    type Error = CertificateError;

    fn try_from(root: &'a Certificate) -> Result<Self, Self::Error> {
        let mut policies = None;
        if let Some(extns) = &root.tbs_certificate.extensions {
            let mut filter = extns
                .iter()
                .filter(|e| e.extn_id == ID_CE_CERTIFICATE_POLICIES);
            if let Some(e) = filter.next() {
                policies = Some(PolicySet::try_from(CertificatePolicies::from_der(
                    e.extn_value.as_bytes(),
                )?)?);
            }
        }
        Ok(Self {
            certificate: root,
            policies,
        })
    }
}
