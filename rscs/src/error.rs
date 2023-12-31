//! RSCS Errors

/// Possible RSCS errors
#[derive(Clone, Debug)]
pub enum Error {
    /// A certificate in the chain could not be verified
    Verification,

    /// A certificate in the chain is expired
    Expired,

    /// A certificate in the chain is not yet valid
    NotYetValid,

    /// DER error
    Der(der::Error),

    /// IO error
    #[cfg(feature = "std")]
    Io(std::io::Error),
}

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Self::Der(e)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
