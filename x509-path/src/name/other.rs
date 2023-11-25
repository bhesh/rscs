use der::{asn1::ObjectIdentifier, referenced::OwnedToRef, AnyRef, Sequence, ValueOrd};
use x509_cert::ext::pkix::name::OtherName;

/// [`OtherName`] as reference
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct OtherNameRef<'a> {
    pub type_id: ObjectIdentifier,

    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub value: AnyRef<'a>,
}

impl<'a> From<&'a OtherName> for OtherNameRef<'a> {
    fn from(other: &'a OtherName) -> Self {
        Self {
            type_id: other.type_id,
            value: other.value.owned_to_ref(),
        }
    }
}
