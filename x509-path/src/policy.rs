//! Certificate Policy Requirements

use der::asn1::ObjectIdentifier;
use hashbrown::{hash_set::Iter, HashSet};

/// Policy flags to define the behavior of the policy tree during path validation.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyFlags {
    /// `inhibitPolicyMapping` indicates if policy mapping is allowed in the certification path. When
    /// set to `true`, policy mapping is not permitted.
    pub inhibit_policy_mapping: bool,

    /// `requireExplicitPolicy` indicates if the certification path MUST be valid for at least one of
    /// the certificate policies in the [`PolicySet`]. When set to TRUE, all certificates in the
    /// certification path MUST contain an acceptable policy identifier in the certificate policies
    /// extension.
    pub require_explicit_policy: bool,

    /// `inhibitAnyPolicy` indicates whether the special anyPolicy policy identifier is considered an
    /// explicit match for other certificate policies.
    pub inhibit_any_policy: bool,
}

/// Set of policy OIDs. Each OID in the set is guaranteed to be unique. The X.509 specification
/// requires that a specific policy OID can only appear once in the certificate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicySet(HashSet<ObjectIdentifier>);

/// Macro to create a `PolicySet`
///
/// ```rust
/// use der::asn1::ObjectIdentifier;
/// use x509_path::policy_set;
///
/// let empty = policy_set![];
/// let policies = policy_set![
///     ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11.36"),
///     ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11.39"),
///     ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11.42"),
///     ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11.59"),
/// ];
/// ```
#[macro_export]
macro_rules! policy_set {
    () => { $crate::PolicySet::default() };
    ($($p:expr),+ $(,)?) => {{
        let mut policy_set = $crate::PolicySet::default();
        $(policy_set.insert($p);)*
            policy_set
    }};
}

impl PolicySet {
    /// Returns an empty `PolicySet`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a policy OID into the set. Returns `false` if the policy OID already existed in the
    /// set.
    pub fn insert(&mut self, policy: ObjectIdentifier) -> bool {
        self.0.insert(policy)
    }

    /// Removes a policy OID from the set. Returns `false` if the policy OID never existed in the
    /// set.
    pub fn remove(&mut self, policy: &ObjectIdentifier) -> bool {
        self.0.remove(policy)
    }

    /// Returns `true` if the set contains the policy OID.
    pub fn contains(&self, policy: &ObjectIdentifier) -> bool {
        self.0.contains(policy)
    }

    /// Returns the length of the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over policy OIDs.
    pub fn iter(&self) -> Iter<'_, ObjectIdentifier> {
        self.0.iter()
    }
}

impl AsRef<HashSet<ObjectIdentifier>> for PolicySet {
    fn as_ref(&self) -> &HashSet<ObjectIdentifier> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::{policy_set, PolicySet};
    use const_oid::db::{
        rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_NAME_CONSTRAINTS},
        rfc5912::ID_CE_CERTIFICATE_POLICIES,
    };

    #[test]
    fn policy_set_sanity() {
        let mut policies = policy_set![
            ID_CE_BASIC_CONSTRAINTS,
            ID_CE_BASIC_CONSTRAINTS,
            ID_CE_NAME_CONSTRAINTS,
            ID_CE_NAME_CONSTRAINTS,
            ID_CE_CERTIFICATE_POLICIES,
            ID_CE_CERTIFICATE_POLICIES,
        ];
        assert!(policies.contains(&ID_CE_BASIC_CONSTRAINTS));
        assert!(policies.contains(&ID_CE_NAME_CONSTRAINTS));
        assert!(policies.contains(&ID_CE_CERTIFICATE_POLICIES));
        policies.remove(&ID_CE_BASIC_CONSTRAINTS);
        policies.remove(&ID_CE_NAME_CONSTRAINTS);
        policies.remove(&ID_CE_CERTIFICATE_POLICIES);
        assert!(!policies.contains(&ID_CE_BASIC_CONSTRAINTS));
        assert!(!policies.contains(&ID_CE_NAME_CONSTRAINTS));
        assert!(!policies.contains(&ID_CE_CERTIFICATE_POLICIES));
    }

    #[test]
    fn single_policy() {
        let policies = policy_set![ID_CE_BASIC_CONSTRAINTS];
        assert!(policies.contains(&ID_CE_BASIC_CONSTRAINTS));
    }

    #[test]
    fn empty_policy_set() {
        let empty = policy_set![];
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
        assert_eq!(empty, PolicySet::new());
        assert_eq!(&empty, &PolicySet::new());
    }
}
