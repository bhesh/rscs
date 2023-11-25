use der::{
    asn1::{PrintableStringRef, TeletexStringRef, Utf8StringRef},
    referenced::OwnedToRef,
    {Choice, ValueOrd},
};
use x509_cert::ext::pkix::name::DirectoryString;

/// [`DirectoryString`] as reference
#[derive(Clone, Debug, Eq, PartialEq, Choice, ValueOrd)]
#[allow(missing_docs)]
pub enum DirectoryStringRef<'a> {
    #[asn1(type = "PrintableString")]
    PrintableString(PrintableStringRef<'a>),

    #[asn1(type = "TeletexString")]
    TeletexString(TeletexStringRef<'a>),

    #[asn1(type = "UTF8String")]
    Utf8String(Utf8StringRef<'a>),
}

impl<'a> From<&'a DirectoryString> for DirectoryStringRef<'a> {
    fn from(other: &'a DirectoryString) -> Self {
        match other {
            DirectoryString::PrintableString(ds) => Self::PrintableString(ds.owned_to_ref()),
            DirectoryString::TeletexString(ds) => Self::TeletexString(ds.owned_to_ref()),
            DirectoryString::Utf8String(ds) => {
                Self::Utf8String(Utf8StringRef::new(ds).expect("DirectoryString::OwnedToRef"))
            }
        }
    }
}
