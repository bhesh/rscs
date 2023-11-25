//! GeneralNames as defined in [RFC 5280 Section 4.2.1.6].

use super::{EdiPartyNameRef, OtherNameRef};
use der::{
    asn1::{Ia5StringRef, ObjectIdentifier, OctetStringRef},
    referenced::OwnedToRef,
    Choice, ValueOrd,
};
use x509_cert::{ext::pkix::name::GeneralName, name::Name};

/// [`GeneralNames`](x509_cert::ext::pkix::name::GeneralNames) as reference
pub type GeneralNameRefs<'a> = alloc::vec::Vec<GeneralNameRef<'a>>;

/// [`GeneralName`] as reference (except [`Name`])
#[derive(Clone, Debug, Eq, PartialEq, Choice, ValueOrd)]
#[allow(missing_docs)]
pub enum GeneralNameRef<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    OtherName(OtherNameRef<'a>),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT")]
    Rfc822Name(Ia5StringRef<'a>),

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    DnsName(Ia5StringRef<'a>),

    #[asn1(context_specific = "4", tag_mode = "EXPLICIT", constructed = "true")]
    DirectoryName(Name),

    #[asn1(context_specific = "5", tag_mode = "IMPLICIT", constructed = "true")]
    EdiPartyName(EdiPartyNameRef<'a>),

    #[asn1(context_specific = "6", tag_mode = "IMPLICIT")]
    UniformResourceIdentifier(Ia5StringRef<'a>),

    #[asn1(context_specific = "7", tag_mode = "IMPLICIT")]
    IpAddress(OctetStringRef<'a>),

    #[asn1(context_specific = "8", tag_mode = "IMPLICIT")]
    RegisteredId(ObjectIdentifier),
}

impl<'a> From<&'a GeneralName> for GeneralNameRef<'a> {
    fn from(other: &'a GeneralName) -> Self {
        match other {
            GeneralName::OtherName(n) => Self::OtherName(n.into()),
            GeneralName::Rfc822Name(n) => Self::Rfc822Name(n.owned_to_ref()),
            GeneralName::DnsName(n) => Self::DnsName(n.owned_to_ref()),
            GeneralName::DirectoryName(n) => Self::DirectoryName(n.clone()),
            GeneralName::EdiPartyName(n) => Self::EdiPartyName(n.into()),
            GeneralName::UniformResourceIdentifier(n) => {
                Self::UniformResourceIdentifier(n.owned_to_ref())
            }
            GeneralName::IpAddress(n) => Self::IpAddress(n.owned_to_ref()),
            GeneralName::RegisteredId(n) => Self::RegisteredId(*n),
        }
    }
}
