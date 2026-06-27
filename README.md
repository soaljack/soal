# soal

[![CI](https://github.com/soaljack/soal/actions/workflows/ci.yml/badge.svg)](https://github.com/soaljack/soal/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache-blue)](LICENSE)

**Soal** — A lightweight, sovereign, open-source protocol for secure, redundant, versioned, content-addressed distributed file storage and synchronization.

Designed for local networks first (LAN, home clusters, off-grid), with a clean path to opt-in internet peering.

## Links

- **Repository**: https://github.com/soaljack/soal
- **Spec**: [spec.md](spec.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Code of Conduct**: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- **Security**: [SECURITY.md](SECURITY.md)

## Status

**Phase 0 (Core Local Foundation) is implemented** — a usable local backup + snapshot tool.

See [spec.md](./spec.md) for the full Soal Protocol Specification (v0.1).

## Phase 0 Features (Current)

- Configurable Content-Defined Chunking (FastCDC + BLAKE3)
- Local encrypted chunk store (encryption **on by default**, toggleable per vault)
- Merkle directory trees + immutable commits (Git-style history)
- Vaults: create, add files/directories, manual snapshots, restore any commit
- Full CLI (clap)
- Property-based tests for chunking determinism, encryption, roundtrips
- Simple file-based storage

## Quick Start

```bash
cargo install --path .   # or use target/debug/soal
soal init
soal vault create photos
soal add ./vacation-photos --vault photos
soal snapshot "Before the big trip" --vault photos
soal status --vault photos

# Restore
soal restore <64-char-commit-hash> --vault photos --to ./restored
```

Your data is stored (encrypted) under `~/.soal/vaults/<name>/`.

## CLI Reference (Phase 0)

```bash
soal init
soal vault create <name> [--no-encrypt]
soal vault list
soal status [--vault <name>]
soal add <path> [--vault <name>] [--message "..."]
soal snapshot "<message>" [--vault <name>]
soal restore <commit-hash> [--to <dir>] [--vault <name>]
```

## Architecture (Phase 0)

- `chunking.rs`: FastCDC + BLAKE3
- `crypto.rs`: XChaCha20-Poly1305 per-vault keys
- `store.rs`: Simple content-addressed file store
- `tree.rs` + `commit.rs`: Merkle manifests + DAG commits
- `vault.rs`: High level operations + on-disk layout
- `main.rs`: CLI

## Next Steps

- Phase 1: Iroh networking, live sync across nodes, replication policy, gossip

## CI

GitHub Actions runs on push and pull requests:

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- Full test suite (including E2E) on **Ubuntu, macOS, and Windows**
- Release binaries are built and uploaded as artifacts

See [.github/workflows/ci.yml](.github/workflows/ci.yml).

## Contributing

We follow standard open source practices. Please read:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Links

- Founder / BDFL: [@soaljack](https://github.com/soaljack)
- License: [MIT OR Apache-2.0](LICENSE)

*Your data, your network, your rules.*
