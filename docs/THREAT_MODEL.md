# icevault threat model

Status: draft 1. This document is written before any code exists, so it
can be reviewed and attacked first.

## 1. What we protect

| Asset | Why it matters |
|---|---|
| Vault contents (passwords, notes, TOTP seeds) | The whole point of the product |
| Master password | Unlocks everything. Never stored, never sent anywhere |
| Vault key | Random key that encrypts the data. Only ever stored wrapped |
| Metadata (item count, sizes, change times) | Leaks habits even when contents are safe |
| Integrity of the vault | A silent change (swapping a password) is as bad as theft |
| Availability | Losing the vault means losing every login |

## 2. Who attacks, and how

| # | Attacker | What they can do |
|---|---|---|
| A1 | Server thief | Steals the full database or backups |
| A2 | Malicious or hacked server | Reads everything, alters or replays data, lies to clients |
| A3 | Network attacker (public Wi-Fi) | Reads, blocks, or changes traffic |
| A4 | Online guesser | Tries passwords against the login endpoint |
| A5 | Offline cracker | Has a stolen vault and tries billions of guesses |
| A6 | Device thief | Has the phone or laptop, locked |
| A7 | Malware on a device | Runs as the user while the vault is open |
| A8 | Supply-chain attacker | Poisons a dependency or a build |
| A9 | Phisher | Tricks the user into entering the password elsewhere |
| A10 | Compromised web delivery | A hacked server sends modified web-vault code that steals the master password |

## 3. What we do about each

| Attacker | Defense |
|---|---|
| A1 | Zero-knowledge: the server stores only encrypted blobs. The master password and vault key never reach it. Stolen data is unreadable without the password |
| A2 | Every item is authenticated encryption (a change is detected). Each record is bound to its ID, so moving a record to another item or account is detected. The client keeps the highest version seen per item and rejects anything lower, which detects rollback. The client never trusts server-supplied data without checking it |
| A3 | TLS 1.3 only. Encryption inside the vault means even a broken TLS reveals no contents |
| A4 | Rate limits and lockouts per account and per IP. Identical responses for "no such user" and "wrong password". Login proof derived separately from the encryption key |
| A5 | Argon2id with strong, tunable settings makes each guess expensive. Master password strength is checked at setup. The user is warned that a weak password is the real limit |
| A6 | Vault is encrypted at rest. Auto-lock after a timeout. Keys are held in memory only while unlocked, and wiped on lock |
| A7 | Partly out of scope (section 4). Mitigations: short unlock window, clipboard cleared after 20 seconds, no secrets in logs, memory wiped after use |
| A8 | Pinned dependency versions, `cargo deny`, Dependabot, a small dependency list, reviewed updates, signed commits and releases |
| A9 | Documented as a risk. Later: the browser extension fills only on a matching domain |
| A10 | The desktop, mobile, and CLI apps are the recommended clients because their code is not served live by the server. The web vault is lower trust: ship it with integrity checks, content security policy, and a clear warning |

## 4. What we do NOT defend against (honest limits)

- **Malware that already controls the device while the vault is unlocked.**
  It can read memory, log keystrokes, and take screenshots. No password
  manager can stop this fully.
- **A weak master password.** Argon2id slows guessing but cannot save a
  guessable password.
- **A compromised build machine or compiler.**
- **Physical coercion** ("give me the password").
- **Metadata the server must see:** account existence, number of items,
  record sizes, and when sync happens. We minimise this and encrypt item
  names, but we do not claim to hide it.
- **Loss of the master password.** There is no reset. This is
  deliberate: any recovery path is also an attack path. An emergency
  recovery kit is offered instead.
- **Denial of service** against a self-hosted server beyond basic rate limits.
- **A malicious server serving malicious web code.** Zero-knowledge does
  not cover code the server itself delivers to a browser.

## 5. Assumptions

- The user's device is not compromised at setup time.
- The cryptographic libraries (RustCrypto) are correct.
- The operating system's random number generator is secure.
- The user keeps the recovery kit offline.

## 6. Security rules for the code

1. No custom cryptography. Only well-reviewed libraries.
2. `unsafe` code is forbidden in the workspace.
3. Secrets are wiped from memory when dropped.
4. Secrets never appear in logs, errors, or `Debug` output.
5. Every decryption failure is one generic error. It never says why.
6. The server gets no key material. It sees only ciphertext.

## 7. Open questions

- Cloud backup: how do we deliver encrypted backups without a trusted server?
- Sharing between users: out of scope for v1.
- Hardware keys (WebAuthn) for login: planned for Phase 14.