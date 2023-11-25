//! Certificate name requirements

use crate::CertificateError;
use alloc::{slice::Iter, vec::Vec};
use der::Sequence;

mod dirstr;
mod dp;
mod ediparty;
mod general;
mod other;

pub use dirstr::DirectoryStringRef;
pub use dp::DistributionPointNameRef;
pub use ediparty::EdiPartyNameRef;
pub use general::{GeneralNameRef, GeneralNameRefs};
pub use other::OtherNameRef;

/// [`GeneralSubtree`] as reference
///
/// [`GeneralSubtree`]: https://github.com/RustCrypto/formats/blob/master/x509-cert/src/ext/pkix/name/general.rs
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct GeneralSubtreeRef<'a> {
    pub base: GeneralNameRef<'a>,
    pub minimum: u32,
    pub maximum: Option<u32>,
}

/// [`GeneralSubtrees`] as reference
///
/// [`GeneralSubtrees`]: https://github.com/RustCrypto/formats/blob/master/x509-cert/src/ext/pkix/name/general.rs
pub type GeneralSubtreeRefs<'a> = Vec<GeneralSubtreeRef<'a>>;

/// [`NameConstraints`] as reference
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct NameConstraintsRef<'a> {
    pub permitted_subtrees: Option<GeneralSubtreeRefs<'a>>,
    pub excluded_subtrees: Option<GeneralSubtreeRefs<'a>>,
}

/// Acts like a `set` and only allows unique [`GeneralName`] values. However, it is implemented as
/// a `list` and performs all actions with `O(n)`.
///
/// [`GeneralName`]: x509_cert::ext::pkix::name::GeneralName
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Names<'a>(Vec<GeneralNameRef<'a>>);

/// Macro to create a `Names`
///
/// ```rust
/// use der::asn1::Ia5String;
/// use std::str::FromStr;
/// use x509_cert::{ext::pkix::name::GeneralName, name::Name};
/// use x509_path::{name::GeneralNameRef, names};
///
/// let dn = GeneralName::DirectoryName(
///     Name::from_str("C=US,O=Evil Corp.,OU=Employees").unwrap()
/// );
/// let dns = GeneralName::DnsName(Ia5String::new(".example.com").unwrap());
///
/// let dn_ref = GeneralNameRef::from(&dn);
/// let dns_ref = GeneralNameRef::from(&dns);
///
/// let empty = names![];
/// let tree = names![dn_ref, dns_ref];
/// ```
#[macro_export]
macro_rules! names {
    () => { $crate::Names::default() };
    ($($n:expr),+ $(,)?) => {{
        let mut tree = $crate::Names::default();
        $(tree.insert($n);)*
            tree
    }};
}

impl<'a> Names<'a> {
    /// Returns an empty `Names`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a [`GeneralNameRef`] into the tree. Returns `false` if the [`GeneralNameRef`]
    /// already existed in the tree.
    pub fn insert(&mut self, name: GeneralNameRef<'a>) -> bool {
        if self.contains(&name) {
            false
        } else {
            self.0.push(name);
            true
        }
    }

    /// Removes a [`GeneralNameRef`] from the tree. Returns `false` if the [`GeneralNameRef`] never
    /// existed in the tree.
    pub fn remove(&mut self, name: &GeneralNameRef<'_>) -> bool {
        match self.index_of(name) {
            Some(ind) => {
                self.0.remove(ind);
                true
            }
            None => false,
        }
    }

    /// Returns the index of the [`GeneralNameRef`]. `None` if it is not found.
    pub fn index_of(&self, name: &GeneralNameRef<'_>) -> Option<usize> {
        self.0.iter().position(|n| n == name)
    }

    /// Returns `true` if the set contains the [`GeneralNameRef`].
    pub fn contains(&self, name: &GeneralNameRef<'_>) -> bool {
        self.0.contains(name)
    }

    /// Returns the length of the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over the [`GeneralNameRef`]s.
    pub fn iter(&self) -> Iter<'_, GeneralNameRef<'a>> {
        self.0.iter()
    }
}

impl<'a> AsRef<Vec<GeneralNameRef<'a>>> for Names<'a> {
    fn as_ref(&self) -> &Vec<GeneralNameRef<'a>> {
        &self.0
    }
}

/// List of allowed and prohibited naming conventions. Used in X.509 to restrict the `subject` and
/// `subjectAltName` fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct NameConstraints<'a, 'b> {
    permitted_subtrees: Names<'a>,
    excluded_subtrees: Names<'b>,
}

impl<'a> TryFrom<NameConstraintsRef<'a>> for NameConstraints<'a, 'a> {
    type Error = CertificateError;

    fn try_from(other: NameConstraintsRef<'a>) -> Result<Self, Self::Error> {
        // Permitted names
        let mut permitted_subtrees = Names::new();
        if let Some(permitted) = other.permitted_subtrees {
            for name in permitted {
                if name.minimum != 0 || name.maximum.is_some() {
                    return Err(CertificateError::InvalidNameConstraints);
                }
                permitted_subtrees.insert(name.base);
            }
        }

        // Excluded names
        let mut excluded_subtrees = Names::new();
        if let Some(excluded) = other.excluded_subtrees {
            for name in excluded {
                if name.minimum != 0 || name.maximum.is_some() {
                    return Err(CertificateError::InvalidNameConstraints);
                }
                excluded_subtrees.insert(name.base);
            }
        }

        if permitted_subtrees.is_empty() && excluded_subtrees.is_empty() {
            // If both subtrees are empty
            return Err(CertificateError::InvalidNameConstraints);
        }
        Ok(Self {
            permitted_subtrees,
            excluded_subtrees,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{name::GeneralNameRef, names, Names};
    use core::str::FromStr;
    use der::asn1::Ia5String;
    use x509_cert::{ext::pkix::name::GeneralName, name::Name};

    #[test]
    fn names_sanity() {
        let name =
            GeneralName::DirectoryName(Name::from_str("C=US,O=Evil Corp.,OU=Employees").unwrap());
        let name_ref = GeneralNameRef::from(&name);
        let dns = GeneralName::DnsName(Ia5String::new(".example.com").unwrap());
        let dns_ref = GeneralNameRef::from(&dns);
        let mut tree = names![
            name_ref.clone(),
            name_ref.clone(),
            dns_ref.clone(),
            dns_ref.clone()
        ];
        assert!(tree.contains(&name_ref));
        assert!(tree.contains(&dns_ref));
        tree.remove(&name_ref);
        tree.remove(&dns_ref);
        assert!(!tree.contains(&name_ref));
        assert!(!tree.contains(&dns_ref));
    }

    #[test]
    fn single_name() {
        let dns = GeneralName::DnsName(Ia5String::new(".example.com").unwrap());
        let dns_ref = GeneralNameRef::from(&dns);
        let tree = names![dns_ref.clone()];
        assert!(tree.contains(&dns_ref));
    }

    #[test]
    fn empty_names() {
        let empty = names![];
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
        assert_eq!(empty, Names::new());
        assert_eq!(&empty, &Names::new());
    }
}
