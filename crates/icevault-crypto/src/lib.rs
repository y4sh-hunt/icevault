//! Cryptographic core of icevault. See docs/CRYPTO_DESIGN.md.
//!
//! No custom cryptography: this crate only assembles audited primitives.

mod cipher;
mod encstring;
mod error;
mod generator;
mod kdf;
mod keys;
mod random;
mod secret;
