//! Trust Anchor

use crate::{Error, KeyId, PolicyFlags, PolicySet};
use const_oid::db::{
    rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_NAME_CONSTRAINTS},
    rfc5912::ID_CE_CERTIFICATE_POLICIES,
};
use der::{referenced::OwnedToRef, Decode};
use spki::SubjectPublicKeyInfoRef;
use x509_cert::{
    anchor::CertPolicyFlags,
    ext::{
        pkix::{certpolicy::CertificatePolicies, BasicConstraints, NameConstraints},
        Extensions,
    },
    name::Name,
    Certificate,
};

macro_rules! find_extension {
    ($cert:ident, $ext:ty, $oid:ident) => {{
        match &$cert.tbs_certificate.extensions {
            Some(extn) => {
                let mut filter = extn.iter().filter(|e| e.extn_id == $oid);
                match filter.next() {
                    Some(e) => <$ext>::from_der(e.extn_value.as_bytes()).ok(),
                    None => None,
                }
            }
            None => None,
        }
    }};
}

#[derive(Debug)]
pub struct TrustAnchor<'a> {
    name: Name,
    pub_key: SubjectPublicKeyInfoRef<'a>,
    key_id: KeyId,
    policy_set: Option<PolicySet>,
    policy_flags: Option<PolicyFlags>,
    name_constraints: Option<NameConstraints>,
    path_len_constraint: Option<u32>,
}

/*
impl<'a> TryFrom<&'a Certificate> for TrustAnchor<'a> {
    type Error = Error;

    fn try_from(root: &'a Certificate) -> Result<Self, Self::Error> {
        let name = root.tbs_certificate.subject.clone();
        let pub_key = root.tbs_certificate.subject_public_key_info.owned_to_ref();
        let key_id = KeyId::try_from(root)?;
        let policy_set = find_extension!(root, CertificatePolicies, ID_CE_CERTIFICATE_POLICIES);
        let name_constraints = find_extension!(root, NameConstraints, ID_CE_NAME_CONSTRAINTS);
        let basic_constraints = find_extension!(root, BasicConstraints, ID_CE_BASIC_CONSTRAINTS);
        let path_len_constraint = match &basic_constraints {
            Some(ext) => ext.path_len_constraint.map(|t| t.into()),
            None => None,
        };
        Ok(Self {
            name,
            pub_key,
            key_id,
            policy_set,
            policy_flags: None,
            name_constraints,
            path_len_constraint,
        })
    }
}
*/
