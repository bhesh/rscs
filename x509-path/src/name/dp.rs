use super::GeneralNameRefs;
use der::{Choice, ValueOrd};
use x509_cert::{ext::pkix::name::DistributionPointName, name::RelativeDistinguishedName};

/// [`DistributionPointName`] as reference (except for [`RelativeDistinguishedName`])
#[derive(Clone, Debug, Eq, PartialEq, Choice, ValueOrd)]
#[allow(missing_docs)]
pub enum DistributionPointNameRef<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    FullName(GeneralNameRefs<'a>),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    NameRelativeToCRLIssuer(RelativeDistinguishedName),
}

impl<'a> From<&'a DistributionPointName> for DistributionPointNameRef<'a> {
    fn from(other: &'a DistributionPointName) -> Self {
        match other {
            DistributionPointName::FullName(n) => {
                let mut full_name = GeneralNameRefs::new();
                for name in n {
                    full_name.push(name.into());
                }
                Self::FullName(full_name)
            }
            DistributionPointName::NameRelativeToCRLIssuer(n) => {
                Self::NameRelativeToCRLIssuer(n.clone())
            }
        }
    }
}
