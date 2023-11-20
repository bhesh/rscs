//! Trust Anchor

use alloc::string::String;
use der::asn1::OctetStringRef;
use spki::SubjectPublicKeyInfoRef;
use x509_cert::{
    anchor::CertPolicyFlags,
    ext::{
        pkix::{certpolicy::CertificatePolicies, NameConstraints},
        Extensions,
    },
    name::Name,
};

pub struct TrustAnchor<'a, 'b> {
    ta_name: Name,
    pub_key: SubjectPublicKeyInfoRef<'a>,
    key_id: OctetStringRef<'b>,
    policy_set: Option<CertificatePolicies>,
    policy_flags: Option<CertPolicyFlags>,
    name_constraints: Option<NameConstraints>,
    path_len_constraint: Option<usize>,
}

impl<'a> TryFrom<&'a Certificate> for TrustAnchor<'a, 'a> {}
