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

**Phase 0 (Core Local Foundation)** — complete  
**Phase 1 (Multi-Node Live Sync)** — complete  
**Phase 2 (Polish & Reliability)** — complete (policy, retention, health/probes, placement, durable blobs, schedule, API)

See [spec.md](./spec.md) for the Soal Protocol Specification (v0.2 wire + Phase 1/2 ops).

## Features

### Local foundation
- Configurable Content-Defined Chunking (FastCDC + BLAKE3)
- Encrypted chunk store (XChaCha20-Poly1305, **on by default**, toggleable per vault)
- Deterministic encryption → intra-vault deduplication with ciphertext content addressing
- Merkle directory trees + immutable commits (Git-style parent DAG)
- **Incremental `add` merges into the HEAD tree** (does not wipe prior files)
- Vault key stored separately (`vault.key`, mode 0600) — not in `vault.json`
- Optional **passphrase-wrapped** vault key (Argon2id + AEAD, PR-05)
- **Signed VaultConfig** (ed25519) with membership + config_seq
- Stable **vault_id** (16 bytes) per vault for rename-safe gossip topics
- Hash verification on store put/get and on network import
- Wire CIDs: `BLAKE3(DOMAIN ‖ CBOR)` for trees/commits; dual-read legacy JSON
- `log` history walk, `gc` mark-and-sweep for unreferenced chunks

### Networking (Phase 1)
- Persistent node identity under `~/.soal/node.json`
- Persisted peer list with EndpointId / ticket validation
- **Signed** head announcements (ed25519) with per-node seq + clock skew checks
- Gossip topic = `BLAKE3("soal/v1/vault/" ‖ vault_id)` (stable across renames)
- iroh-blobs for verified content transfer; provide reloads from **vault CAS** (survives restart)
- **SyncEngine**: parent DAG walk, peer failover, job checkpoints under `vault/sync/jobs/`
- **Invites** (signed tokens) for secure key + membership share
- **Conflict copies** on multi-head merge (`file (conflict from Peer).ext`)
- **Replication** pins + status + `--push` self-heal provide
- **Live watch** (`soal watch`) with debounced FS events
- Cluster **discovery** gossip (`soal node beacon` / `discover`)

### Phase 2 polish
- **Policy engine** (`policy.json`): min_replicas, snapshot interval, retention, live_mode, head-age warn
- **Snapshot retention**: registry + prune (`--retain N`); GC marks HEAD + registered tips
- **Health** reports (`soal health [--probe]`) with Ok/Warn/Crit + peer liveness
- **Peer probes** (`soal node probe`) update `peer_health.json` for placement
- **Placement-aware sync**: prefer_nodes + alive/fresh peers ordered first
- **Durable blob store**: iroh-blobs `FsStore` under `~/.soal/blobs/`
- **Timed snapshots** via `soal schedule` (single tick, force, or duration loop)
- **Diff** path-level changes between commits (`soal diff`)
- **JSON output** (`--json`) for scripting
- **Embeddable API**: `soal::SoalSession` for apps/agents

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

# Networking
soal node id
soal node add-peer <peer-endpoint-ticket>
# or: soal node beacon & soal node discover --add
soal snapshot "ship it" --vault photos --announce
soal sync --vault photos --head <commit-hash>

# Invite another device
soal invite generate --vault photos --out invite.token
# on other device:
soal invite join invite.token

# Live folder + replication
soal watch ./notes --vault notes --for-secs 3600
soal replicate --vault photos --push

# Phase 2: policy, health, schedule, diff
soal vault policy photos --snapshot-interval 3600 --live true
soal health --vault photos
soal --json health
soal schedule --vault photos --force
soal diff --vault photos
```

Data lives under `~/.soal/vaults/<name>/`. Node identity: `~/.soal/node.json`.

Passphrase-protected vaults: `soal vault protect <name> --passphrase '…'` or  
`SOAL_PASSPHRASE=… soal --passphrase '…' status --vault photos`.

## CLI Reference

```bash
soal init
soal [--json] [--passphrase …] <command>
soal vault create <name> [--no-encrypt] [--replicas N] [--passphrase …]
soal vault list | policy <name> [--replicas N] [--snapshot-interval S] [--live true|false] …
soal vault protect <name> --passphrase …
soal vault add-member | remove-member <name> <node-id>
soal status | health [--vault <name>]
soal add <path> [--vault <name>] [--message "..."]
soal snapshot "<message>" [--vault <name>] [--announce]
soal restore <commit-hash> [--to <dir>] [--vault <name>]
soal log [--vault <name>] [-n N]
soal diff [--from H] [--to H] [--vault <name>]
soal gc [--vault <name>] [--apply]
soal schedule [--vault <name>] [--for-secs N] [--every-secs N] [--force]
soal sync [--vault <name>] [--head <commit>] [--merge] [--from label]
soal merge <commit> [--vault <name>] [--from label] [--fetch]
soal watch <path> [--vault <name>] [--debounce-ms N] [--for-secs N] [--announce]
soal replicate [--vault <name>] [--push]
soal invite generate --vault <name> [--role read|write] [--ttl secs] [--out file]
soal invite join <token|file> [--name local-name]
soal node id | peers | add-peer | remove-peer
soal node announce <vault> <head> | listen <vault>
soal node beacon [--secs N] | discover [--secs N] [--add]
```

## Architecture

| Module | Role |
|--------|------|
| `chunking.rs` | FastCDC + BLAKE3 plaintext chunks |
| `codec.rs` | Domain frames + deterministic CBOR; `CID = BLAKE3(wire)`; head announce wire |
| `crypto.rs` | XChaCha20-Poly1305; Argon2id passphrase wrap |
| `identity.rs` | Node SecretKey load; commit + head sign/verify |
| `invite.rs` | Signed vault invites + join (key share) |
| `store.rs` | CAS with hash check + CID collision reject |
| `tree.rs` | Merkle manifests + conflict-copy merge |
| `commit.rs` | Immutable DAG commits (wire CBOR + optional ed25519 sig) |
| `vault.rs` | Vault ops, signed config, passphrase, merge heads, GC |
| `network.rs` | Identity, peers, signed gossip, vault CAS provide, discovery |
| `sync.rs` | SyncEngine DAG fetch + checkpoints |
| `replication.rs` | Pins, replica estimates, self-heal provide |
| `watch.rs` | Live FS watch + debounced add |
| `policy.rs` | Vault policy + auto-snapshot state |
| `health.rs` | Health reports + tree diff |
| `schedule.rs` | Timed snapshot / pin maintenance loop |
| `api.rs` | Embeddable `SoalSession` façade |
| `main.rs` | clap CLI |

## Design guarantees

1. **Content integrity**: every stored blob is keyed by `BLAKE3(bytes)`; mismatches and CID collisions are rejected.
2. **Encryption model**: plaintext CDC → per-vault AEAD → store/address by ciphertext hash.
3. **History**: each `add` parents to HEAD and merges paths into the existing tree.
4. **Identity**: Node ID is stable across process restarts (persisted secret key).
5. **Path safety**: vault paths reject `..`, absolute forms, and restore path escape.
6. **Wire rule (v0.2)**: typed objects use domain-prefix frames; `CID = BLAKE3(wire)`.
7. **Signed control plane**: commits, heads, configs, and invites carry ed25519 signatures where required.
8. **Durable provide**: announce reloads blobs from vault CAS (not MemStore-only after restart).
9. **Conflicts**: divergent multi-head merges keep both sides via conflict copy paths.
10. **Invites**: vault key never leaves in plaintext; sealed under invite secret inside signed token.

## Testing

```bash
cargo test --all
./scripts/test-phase0.sh   # Linux shell E2E
./scripts/test-phase1-network.sh
```

100+ automated tests: unit (codec/crypto/vault/identity/invite/sync/replication/watch), CLI e2e, multi-node SC-* gates.

## CI

GitHub Actions on push/PR:

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- Full test suite (unit + E2E + multi-node) on Ubuntu, macOS, Windows
- Release binaries as artifacts

## Contributing

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## License

[MIT OR Apache-2.0](LICENSE) · Founder / BDFL: [@soaljack](https://github.com/soaljack)

*Your data, your network, your rules.*
