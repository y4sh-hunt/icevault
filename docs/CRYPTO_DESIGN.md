# icevault cryptographic design

Status: draft 1. Written before any code. Read together with
THREAT_MODEL.md. No custom cryptography: this document only assembles
well-reviewed primitives.

## 1. Primitives

| Job | Primitive | Why |
|---|---|---|
| Password to key | Argon2id (RFC 9106) | Memory-hard, resists GPU cracking |
| Splitting keys | HKDF-SHA256 (RFC 5869) | Standard, safe for domain separation |
| Encryption | XChaCha20-Poly1305 | AEAD, 192-bit nonce is safe to randomise |
| Randomness | Operating-system CSPRNG | Never our own generator |
| Wiping memory | `zeroize` | Secrets cleared when dropped |

## 2. Keys

| Key | Origin | Stored? |
|---|---|---|
| Master password | The user | Never |
| Master secret | Argon2id(password, salt) | Never |
| Wrap key | HKDF(master secret, "icevault/v1/wrap") | Never |
| Auth key | HKDF(master secret, "icevault/v1/auth") | Never. Only a hash of it lives on the server |
| Vault key | 32 random bytes, made once at setup | Only wrapped (encrypted) by the wrap key and by the recovery key |
| Recovery key | 32 random bytes, shown once | Printed by the user. Never stored |

HKDF is used in expand-only mode: the Argon2id output is already uniform,
so no extra salt is needed. `info` is the exact label string shown above.

## 3. Key derivation parameters

- Argon2id, 32-byte output, 16-byte random salt.
- **Floor** (never accept less): memory 64 MiB, 3 passes, 4 lanes
  (the RFC 9106 second recommendation).
- Default is tuned per device to about one second, and never below the floor.
- Salt and parameters are stored with the vault, so they can be raised
  later. A raise takes effect at the next unlock.
- Master password is normalised (Unicode NFKC) before use, so the same
  password typed on any device gives the same key.

## 4. Encrypting an item

For each save: a fresh 24-byte random nonce, then
`XChaCha20-Poly1305(vault key, nonce, plaintext, AAD)`.

AAD = `"icevault/v1/item" || account id || item id || item version`

Effect: a ciphertext moved to another item or another account fails to
decrypt. Rollback to an older version is NOT caught by this alone. The
client keeps the highest version it has seen for each item (and a vault
revision counter) and rejects anything lower.

The encrypted payload holds all user content: name, URL, username,
password, notes, custom fields, and TOTP seeds. The server sees only the
item id, version, size, and timestamps.

## 5. Stored format (EncString)

`v1.<nonce, base64>.<ciphertext + tag, base64>`

The leading version number lets us change algorithms later without
breaking old data. Unknown versions are rejected, never guessed.

## 6. Wrapping the vault key

`wrapped = XChaCha20-Poly1305(wrap key, nonce, vault key, AAD = "icevault/v1/vk" || account id)`

Changing the master password: derive a new wrap key, re-wrap the same
vault key. Items are not re-encrypted. Rotating the vault key itself
(after a suspected leak) re-encrypts every item and is a separate,
explicit operation.

Limit: a password change does not protect against someone who already
copied the old wrapped vault key and knows the old password. In that case
the user must rotate the vault key.

## 7. Login without sending the password

1. The client asks the server for the account's salt and KDF settings.
   The server answers identically for unknown accounts, returning a
   deterministic fake salt (HMAC of the username with a server secret).
2. The client rejects any settings below the floor in section 3, so a
   malicious server cannot make guessing cheaper.
3. The client derives the auth key locally and sends it over TLS.
4. The server stores only `Argon2id(auth key, server-side salt)`.
5. The server learns nothing that decrypts data, because the wrap key is
   derived from a different label.

If the server database leaks, the attacker faces a hash of a hash and
still has no data key.

## 8. Recovery

At setup the app generates a recovery key and wraps the vault key under
it a second time. The user prints it and stores it offline. With it,
they can set a new master password. Without it, a lost master password
means lost data (see THREAT_MODEL, section 4).

## 9. Handling secrets in code

- Secret types never print their value: `Debug` shows `[REDACTED]`, and they have no `Display` or `Clone`.
- Wiped on drop (`zeroize`).
- Comparisons of secret values use constant time.
- Every decryption failure returns one generic error.
- Keys are held in memory only while unlocked. Locking drops them.

## 10. Testing requirements

- Known-answer tests from the published test vectors for Argon2id,
  HKDF, and XChaCha20-Poly1305.
- Round trips: encrypt then decrypt returns the original.
- Tamper tests: flipping any bit of the ciphertext, nonce, or AAD fails.
- Wrong password and wrong key both fail with the same error.
- Nonces differ across 100,000 encryptions.

## 11. Not decided yet

- Per-item keys (each item gets its own random key, wrapped by the
  vault key): considered for sharing in a later version.
- Whether to add a second factor into key derivation.
- Padding item sizes to hide their length.