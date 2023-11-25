use super::DirectoryStringRef;
use der::{Sequence, ValueOrd};
use x509_cert::ext::pkix::name::EdiPartyName;

/// [`EdiPartyName`] as reference
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct EdiPartyNameRef<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub name_assigner: Option<DirectoryStringRef<'a>>,

    #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
    pub party_name: DirectoryStringRef<'a>,
}

impl<'a> From<&'a EdiPartyName> for EdiPartyNameRef<'a> {
    fn from(other: &'a EdiPartyName) -> Self {
        Self {
            name_assigner: other.name_assigner.as_ref().map(|n| n.into()),
            party_name: (&other.party_name).into(),
        }
    }
}
