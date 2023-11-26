#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod anchor;
mod cert;
mod error;
mod key_identifier;
mod policy;

pub mod name;

pub use anchor::TrustAnchor;
pub use cert::CertTarget;
pub use error::{CertificateError, Error};
pub use key_identifier::{KeyIdentifier, SubjectKeyIdentifierRef};
pub use name::{NameConstraints, Names};
pub use policy::{PolicyFlags, PolicySet};
