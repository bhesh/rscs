//! Certificate name requirements

use crate::CertificateError;
use alloc::{slice::Iter, vec::Vec};
use x509_cert::ext::pkix::{name::GeneralName, NameConstraints as X509NameConstraints};

/// Acts like a `set` and only allows unique [`GeneralName`] values. However, it is implemented as
/// a `list` and performs all actions with `O(n)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Names(Vec<GeneralName>);

/// Macro to create a `Names`
///
/// ```rust
/// use der::asn1::Ia5String;
/// use std::str::FromStr;
/// use x509_cert::{ext::pkix::name::GeneralName, name::Name};
/// use x509_path::names;
///
/// let empty = names![];
/// let tree = names![
///     GeneralName::DirectoryName(Name::from_str("C=US,O=Evil Corp.,OU=Employees").unwrap()),
///     GeneralName::DnsName(Ia5String::new(".example.com").unwrap()),
/// ];
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

impl Names {
    /// Returns an empty `Names`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a [`GeneralName`] into the tree. Returns `false` if the [`GeneralName`] already
    /// existed in the tree.
    pub fn insert(&mut self, name: GeneralName) -> bool {
        if self.contains(&name) {
            false
        } else {
            self.0.push(name);
            true
        }
    }

    /// Removes a [`GeneralName`] from the tree. Returns `false` if the [`GeneralName`] never
    /// existed in the tree.
    pub fn remove(&mut self, name: &GeneralName) -> bool {
        match self.index_of(name) {
            Some(ind) => {
                self.0.remove(ind);
                true
            }
            None => false,
        }
    }

    /// Returns the index of the [`GeneralName`]. `None` if it is not found.
    pub fn index_of(&self, name: &GeneralName) -> Option<usize> {
        self.0.iter().position(|n| n == name)
    }

    /// Returns `true` if the set contains the [`GeneralName`].
    pub fn contains(&self, name: &GeneralName) -> bool {
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

    /// Returns an iterator over the [`GeneralName`]s.
    pub fn iter(&self) -> Iter<'_, GeneralName> {
        self.0.iter()
    }
}

impl AsRef<Vec<GeneralName>> for Names {
    fn as_ref(&self) -> &Vec<GeneralName> {
        &self.0
    }
}

/// List of allowed and prohibited naming conventions. Used in X.509 to restrict the `subject` and
/// `subjectAltName` fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameConstraints {
    permitted_subtrees: Names,
    excluded_subtrees: Names,
}

impl NameConstraints {
    /// Returns a new `NameConstraints` structure
    pub fn new(permitted_subtrees: Names, excluded_subtrees: Names) -> Self {
        Self {
            permitted_subtrees,
            excluded_subtrees,
        }
    }
}

impl TryFrom<X509NameConstraints> for NameConstraints {
    type Error = CertificateError;

    fn try_from(other: X509NameConstraints) -> Result<Self, Self::Error> {
        // Permitted names
        let mut permitted_subtrees = Names::new();
        if let Some(permitted) = other.permitted_subtrees {
            for name in permitted {
                if name.minimum != 0 || name.maximum.is_some() {
                    return Err(CertificateError::InvalidNameConstraints);
                }
                permitted_subtrees.insert(name.base.clone());
            }
        }

        // Excluded names
        let mut excluded_subtrees = Names::new();
        if let Some(excluded) = other.excluded_subtrees {
            for name in excluded {
                if name.minimum != 0 || name.maximum.is_some() {
                    return Err(CertificateError::InvalidNameConstraints);
                }
                excluded_subtrees.insert(name.base.clone());
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
    use crate::{names, Names};
    use core::str::FromStr;
    use der::asn1::Ia5String;
    use x509_cert::{ext::pkix::name::GeneralName, name::Name};

    #[test]
    fn names_sanity() {
        let name =
            GeneralName::DirectoryName(Name::from_str("C=US,O=Evil Corp.,OU=Employees").unwrap());
        let dns = GeneralName::DnsName(Ia5String::new(".example.com").unwrap());
        let mut tree = names![name.clone(), name.clone(), dns.clone(), dns.clone()];
        assert!(tree.contains(&name));
        assert!(tree.contains(&dns));
        tree.remove(&name);
        tree.remove(&dns);
        assert!(!tree.contains(&name));
        assert!(!tree.contains(&dns));
    }

    #[test]
    fn single_name() {
        let dns = GeneralName::DnsName(Ia5String::new(".example.com").unwrap());
        let tree = names![dns.clone()];
        assert!(tree.contains(&dns));
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
