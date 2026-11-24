//! Wrappers that keep secrets out of logs and wipe them on drop (design section 9).

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use secrecy::{ExposeSecret, SecretSlice, SecretString};

/// Length in bytes of every key in icevault (256 bits).
pub const KEY_LEN: usize = 32;

/// A 256-bit secret key: the master secret, wrap key, auth key, vault key or recovery key.
///
/// - Wiped from memory when dropped.
/// - Prints as `SecretKey([REDACTED])`, never its value.
/// - Has no `Clone` and no `Display`, so a copy cannot be made or printed by accident.
/// - Compared in constant time.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// Wraps existing key bytes.
    ///
    /// The array you pass in is copied. If you still hold the original, wipe it yourself
    /// with `bytes.zeroize()` once you no longer need it.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl ExposeSecret<[u8; KEY_LEN]> for SecretKey {
    fn expose_secret(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SecretKey {}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_the_value() {
        let key = SecretKey::from_bytes([0xAB; KEY_LEN]);
        assert_eq!(format!("{key:?}"), "SecretKey([REDACTED])");
    }

    #[test]
    fn equal_keys_are_equal_and_different_keys_are_not() {
        let a = SecretKey::from_bytes([1; KEY_LEN]);
        let b = SecretKey::from_bytes([1; KEY_LEN]);
        let c = SecretKey::from_bytes([2; KEY_LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn key_bytes_can_be_read_back_on_purpose() {
        let key = SecretKey::from_bytes([9; KEY_LEN]);
        assert_eq!(key.expose_secret(), &[9u8; KEY_LEN]);
    }

    #[test]
    fn zeroize_clears_the_key() {
        let mut key = SecretKey::from_bytes([7; KEY_LEN]);
        key.zeroize();
        assert_eq!(key.expose_secret(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn secret_string_hides_its_value() {
        let password = SecretString::from("hunter2");
        assert!(!format!("{password:?}").contains("hunter2"));
        assert_eq!(password.expose_secret(), "hunter2");
    }
}
