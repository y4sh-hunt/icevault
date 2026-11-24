//! The single source of randomness: salts, nonces and keys all come from the operating system.

use rand::TryRng;
use rand::rngs::SysRng;

use crate::error::{CryptoError, Result};
use crate::secret::{KEY_LEN, SecretKey};

/// Length in bytes of an XChaCha20-Poly1305 nonce (192 bits).
pub const NONCE_LEN: usize = 24;

/// Length in bytes of an Argon2id salt (128 bits).
pub const SALT_LEN: usize = 16;

/// Fills `buffer` with random bytes from the operating system.
///
/// # Errors
///
/// Returns [`CryptoError::RandomnessUnavailable`] if the operating system cannot supply
/// random bytes. The buffer must then not be used.
pub fn fill_random(buffer: &mut [u8]) -> Result<()> {
    SysRng
        .try_fill_bytes(buffer)
        .map_err(|_| CryptoError::RandomnessUnavailable)
}

/// Returns `N` random bytes.
///
/// # Errors
///
/// Returns [`CryptoError::RandomnessUnavailable`] if the operating system cannot supply
/// random bytes.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

/// Returns a new random 256-bit secret key.
///
/// # Errors
///
/// Returns [`CryptoError::RandomnessUnavailable`] if the operating system cannot supply
/// random bytes.
pub fn random_key() -> Result<SecretKey> {
    Ok(SecretKey::from_bytes(random_array::<KEY_LEN>()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::ExposeSecret;

    #[test]
    fn random_array_has_the_requested_length() {
        assert_eq!(random_array::<NONCE_LEN>().map(|a| a.len()), Ok(NONCE_LEN));
        assert_eq!(random_array::<SALT_LEN>().map(|a| a.len()), Ok(SALT_LEN));
    }

    #[test]
    fn two_random_arrays_differ() {
        assert_ne!(random_array::<NONCE_LEN>(), random_array::<NONCE_LEN>());
    }

    #[test]
    fn fill_random_changes_the_buffer() {
        let mut buffer = [0u8; 64];
        assert_eq!(fill_random(&mut buffer), Ok(()));
        assert_ne!(buffer, [0u8; 64]);
    }

    #[test]
    fn random_keys_differ_and_are_not_all_zero() {
        let a = random_key();
        let b = random_key();
        assert!(a.is_ok() && b.is_ok());
        assert_ne!(a, b);
        assert!(a.is_ok_and(|k| k.expose_secret() != &[0u8; KEY_LEN]));
    }
}
