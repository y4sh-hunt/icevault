//! Error types, including the one generic decryption error (design section 9).

use thiserror::Error;

/// Everything that can go wrong in this crate.
///
/// `DecryptionFailed` is the ONLY error for a failed decryption. A wrong key, a wrong
/// password and a changed byte all produce exactly this value, so an attacker cannot
/// learn which guess came closer. The other errors are raised before any secret is
/// used (bad input, unsafe settings) or by the operating system, so they reveal nothing
/// about a key.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// Decryption failed. The reason is deliberately not given.
    #[error("decryption failed")]
    DecryptionFailed,

    /// Stored text is malformed or uses a version this program does not know.
    #[error("invalid or unsupported stored format")]
    InvalidFormat,

    /// Key-derivation settings are below the safe minimum (design section 3).
    #[error("key derivation settings are too weak")]
    WeakKdfParameters,

    /// The key-derivation function itself reported a failure.
    #[error("key derivation failed")]
    KeyDerivationFailed,

    /// The operating system could not supply random bytes.
    #[error("secure random bytes are unavailable")]
    RandomnessUnavailable,
}

/// Shorthand: `Result<T>` means `Result<T, CryptoError>`.
pub type Result<T> = core::result::Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decryption_failure_message_is_generic() {
        assert_eq!(
            CryptoError::DecryptionFailed.to_string(),
            "decryption failed"
        );
    }

    #[test]
    fn errors_can_be_compared() {
        assert_eq!(CryptoError::InvalidFormat, CryptoError::InvalidFormat);
        assert_ne!(CryptoError::InvalidFormat, CryptoError::DecryptionFailed);
    }
}
