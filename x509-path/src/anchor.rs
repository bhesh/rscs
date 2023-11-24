//! Trust Anchor

use crate::{
    Error, KeyIdentifier, NameConstraints, PolicyFlags, PolicySet, SubjectKeyIdentifierRef,
};
use const_oid::db::{
    rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_NAME_CONSTRAINTS, ID_CE_SUBJECT_KEY_IDENTIFIER},
    rfc5912::ID_CE_CERTIFICATE_POLICIES,
};
use der::{referenced::OwnedToRef, Decode};
use spki::SubjectPublicKeyInfoRef;
use x509_cert::{
    ext::{
        pkix::{BasicConstraints, CertificatePolicies, NameConstraints as X509NameConstraints},
        Extensions,
    },
    name::Name,
    Certificate,
};

/// Trust anchor representation
///
/// References the name, public key, and key identifer (if possible).
///
/// The policies, constraints, and extensions are currently owned. All of these fields need to be
/// decoded to an owned structure as the [`x509-cert`] crate does not have referenced
/// implementations of these complex structures. The policy OIDs are relatively cheap, while the
/// [`GeneralName`]s in [`NameConstraints`] may have some performance impact.
#[derive(Debug)]
pub struct TrustAnchor<'a> {
    name: &'a Name,
    pub_key: SubjectPublicKeyInfoRef<'a>,
    key_id: KeyIdentifier<'a>,
    policy_set: Option<PolicySet>,
    policy_flags: Option<PolicyFlags>,
    name_constraints: Option<NameConstraints>,
    path_len_constraint: Option<u32>,
    extensions: Option<Extensions>,
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
                match &extn.extn_id {
                    &ID_CE_SUBJECT_KEY_IDENTIFIER => {
                        key_id = Some(KeyIdentifier::from(SubjectKeyIdentifierRef::from_der(
                            extn.extn_value.as_bytes(),
                        )?));
                    }
                    &ID_CE_CERTIFICATE_POLICIES => {
                        policy_set = Some(PolicySet::try_from(CertificatePolicies::from_der(
                            extn.extn_value.as_bytes(),
                        )?)?);
                    }
                    &ID_CE_NAME_CONSTRAINTS => {
                        name_constraints = Some(NameConstraints::try_from(
                            X509NameConstraints::from_der(extn.extn_value.as_bytes())?,
                        )?);
                    }
                    &ID_CE_BASIC_CONSTRAINTS => {
                        let basic_constraints =
                            BasicConstraints::from_der(extn.extn_value.as_bytes())?;
                        path_len_constraint =
                            basic_constraints.path_len_constraint.map(|t| t.into());
                    }
                    _ => extensions.push(extn.clone()),
                }
            }
        }
        if key_id.is_none() {
            key_id = Some(KeyIdentifier::from(
                &root.tbs_certificate.subject_public_key_info,
            ));
        }
        Ok(Self {
            name,
            pub_key,
            key_id: key_id.unwrap(),
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
