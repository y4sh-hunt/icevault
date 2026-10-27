# icevault

A zero-knowledge, end-to-end encrypted password manager written in Rust.

> **Work in progress. Not audited. Do not store real passwords in it yet.**

## Goals

- Your master password and unencrypted data never leave your device
- Modern cryptography: Argon2id and XChaCha20-Poly1305
- Self-hostable, so you can reach your vault from anywhere
- 100% open source, built on open source

## Roadmap

- [ ] Crypto core
- [ ] Vault core
- [ ] Command-line app
- [ ] Sync server
- [ ] Desktop app
- [ ] Browser extension
- [ ] Mobile apps

## Building

```bash
cargo build
cargo test
```

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE).
