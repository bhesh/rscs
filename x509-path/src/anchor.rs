//! Trust Anchor

use crate::{
    name::NameConstraintsRef, Error, KeyIdentifier, NameConstraints, PolicyFlags, PolicySet,
    SubjectKeyIdentifierRef,
};
use alloc::vec::Vec;
use const_oid::db::{
    rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_NAME_CONSTRAINTS, ID_CE_SUBJECT_KEY_IDENTIFIER},
    rfc5912::ID_CE_CERTIFICATE_POLICIES,
};
use der::{referenced::OwnedToRef, Decode};
use spki::SubjectPublicKeyInfoRef;
use x509_cert::{
    ext::{
        pkix::{BasicConstraints, CertificatePolicies},
        Extension,
    },
    name::Name,
    Certificate,
};

/// Trust anchor representation
#[derive(Debug)]
pub struct TrustAnchor<'a> {
    name: &'a Name,
    pub_key: SubjectPublicKeyInfoRef<'a>,
    key_id: KeyIdentifier<'a>,
    policy_set: Option<PolicySet>,
    policy_flags: Option<PolicyFlags>,
    name_constraints: Option<NameConstraints<'a, 'a>>,
    path_len_constraint: Option<u32>,
    extensions: Option<Vec<&'a Extension>>,
}

impl<'a> TryFrom<&'a Certificate> for TrustAnchor<'a> {
    type Error = Error;

    fn try_from(root: &'a Certificate) -> Result<Self, Self::Error> {
        let name = &root.tbs_certificate.subject;
        let pub_key = root.tbs_certificate.subject_public_key_info.owned_to_ref();
        let mut key_id = None;
        let mut policy_set = None;
        let mut name_constraints = None;
        let mut path_len_constraint = None;
        let mut extensions = alloc::vec![];
        if let Some(extns) = &root.tbs_certificate.extensions {
            for extn in extns {
                match extn.extn_id {
                    ID_CE_SUBJECT_KEY_IDENTIFIER => {
                        key_id = Some(KeyIdentifier::from(SubjectKeyIdentifierRef::from_der(
                            extn.extn_value.as_bytes(),
                        )?));
                    }
                    ID_CE_CERTIFICATE_POLICIES => {
                        policy_set = Some(PolicySet::try_from(CertificatePolicies::from_der(
                            extn.extn_value.as_bytes(),
                        )?)?);
                    }
                    ID_CE_NAME_CONSTRAINTS => {
                        name_constraints = Some(NameConstraints::try_from(
                            NameConstraintsRef::from_der(extn.extn_value.as_bytes())?,
                        )?);
                    }
                    ID_CE_BASIC_CONSTRAINTS => {
                        let basic_constraints =
                            BasicConstraints::from_der(extn.extn_value.as_bytes())?;
                        path_len_constraint =
                            basic_constraints.path_len_constraint.map(|t| t.into());
                    }
                    _ => extensions.push(extn),
                }
            }
        }
        let key_id = match key_id {
            Some(id) => id,
            None => KeyIdentifier::from(&root.tbs_certificate.subject_public_key_info),
        };
        Ok(Self {
            name,
            pub_key,
            key_id,
            policy_set,
            policy_flags: None,
            name_constraints,
            path_len_constraint,
            extensions: if extensions.is_empty() {
                None
            } else {
                Some(extensions)
            },
        })
    }
}
