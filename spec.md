# Soal Protocol Specification

**Version:** 0.2 (Phase 1 complete)  
**Date:** 2026-07-23  
**Status:** Living spec — Phase 0+1 implemented in reference client  
**Project:** Soal (Soal Protocol / SoalFS)  
**Founder / BDFL:** Jeffrey Stewart (@soaljack)  
**License:** MIT OR Apache-2.0 (dual license)  
**Primary Platforms (initial):** macOS, Windows, Linux

---

## 1. Vision & Introduction

**Soal** is a lightweight, sovereign, open-source protocol and reference implementation for secure, redundant, versioned, content-addressed distributed file storage and synchronization.

It is designed primarily for **local networks** (LAN, home, office, off-grid clusters of personal devices) while keeping a clean architectural path for future opt-in internet peering. Soal runs on any computer, works perfectly with a single node, and scales gracefully to n nodes in a trusted cluster.

**Core inspirations**:
- **BitTorrent**: Efficient chunked P2P transfer, verified streaming, resilience through distribution.
- **Git**: Merkle DAG structure, immutable commits/snapshots, explicit history and control.
- **Modern cryptography & P2P**: Strong hashing (BLAKE3), ed25519 identities, authenticated encryption, capability-style access patterns.
- **Iroh** (primary networking foundation): Reliable peer-to-peer connections by public key, excellent LAN support, content-addressed blobs via `iroh-blobs`, gossip, and CRDT-friendly primitives.

**Key differentiators**:
- **Hybrid workflow**: Continuous live working tree synchronization + manual or timed immutable snapshots.
- **Sovereignty first**: Data stays in your cluster by default. No cloud dependency. Encryption on by default.
- **Configurable redundancy**: Replication (minimum 2–3 replicas, grows with cluster size) with future optional erasure coding.
- **Content-defined chunking (CDC)** with BLAKE3 for excellent deduplication across versions, photos, notes, and media.
- **Modular & high-quality foundation**: Clean layers designed for many future modules (media streaming, notes integration, AI hooks, etc.).
- **Lightweight & usable**: Small static binaries, excellent CLI first, embeddable API, easy to plug into other tools.

**Primary use cases** (initial focus):
- Photo and media library backup + versioning.
- Notes and document synchronization.
- Easy network streaming of music/media from the cluster.
- General sovereign data resilience for individuals, families, and small communities.

Soal aims to be the reliable, private foundation for personal and community data infrastructure — a "local cloud" you actually control.

---

## 2. Goals and Non-Goals

### Goals
- Work seamlessly with **1 node** (full local functionality) and scale to **n nodes** in a trusted cluster.
- Provide **live working tree sync** (continuous, low-friction) combined with **explicit snapshots** (git-style history and restore points).
- Strong **security by default**: Encryption at rest and in transit always on; user can disable if desired.
- **Configurable, growing redundancy**: Minimum 2–3 replicas across distinct nodes; policy-driven increase as cluster grows or data importance warrants.
- Excellent **deduplication and efficiency** via CDC + content addressing.
- **Lightweight implementation**: Small resource footprint, fast on LAN, cross-platform static binaries.
- **High-quality, testable code** delivered in manageable, verifiable chunks.
- Clean **modular architecture** so future modules (streaming, FUSE, AI integration, etc.) can hook in reliably.
- **Local/LAN primary** with clean future extension points for optional internet peering.
- Simple, powerful **CLI** + embeddable **API**.
- Open source with clear early governance (BDFL model transitioning to community).

### Non-Goals (for v0.1–v0.3 at least)
- Global public web hosting or Filecoin-style incentives as primary mode.
- Heavy blockchain consensus or mining.
- Automatic conflict resolution for binary files (manual resolution preferred).
- Full FUSE filesystem mount in early phases (CLI + API first).
- Mandatory internet connectivity or global DHT exposure.
- Support for untrusted/public nodes in the initial threat model (trusted cluster members or capability-gated access).

---

## 3. Terminology

- **Node**: A running Soal instance on a device. Identified by ed25519 public key (NodeID).
- **Vault**: A named, policy-controlled collection of data (e.g., `photos`, `notes`, `music-library`). Has replication policy, encryption setting, live/sync mode, and members.
- **Chunk / Blob**: A piece of file data identified by its BLAKE3 hash (content-addressed). Created via Content-Defined Chunking (CDC).
- **Tree**: A Merkle directory manifest mapping paths to chunk or subtree CIDs.
- **Commit**: An immutable snapshot of a tree (or subtree) with parent(s), metadata, and optional signature. Forms a DAG.
- **Pin / Replica**: A node explicitly or automatically keeping a copy of specific chunks/trees/commits to satisfy redundancy policy.
- **Live Working Tree**: The current mutable filesystem view that Soal watches and syncs across nodes.
- **Snapshot**: An explicit immutable commit created manually or on a schedule.
- **Cluster**: A group of nodes that have joined via secure invites and share vault membership.

---

## 4. Data Model

All core data is **content-addressed** and **immutable** where possible.

### 4.1 Chunks (Blobs)
- Files are split using **Content-Defined Chunking (CDC)** (Rabin fingerprint or FastCDC variant) performed on **plaintext**.
- Target average chunk size: **Configurable per vault or globally**. Default starting goal: ~2 MiB average (tunable; system may recommend larger sizes as cluster/data patterns stabilize).
- When encryption is enabled for the vault (default): each plaintext chunk is encrypted with the vault's symmetric key; the chunk is then stored and referenced in Trees/Commits by the **BLAKE3 hash of the ciphertext** (encrypted blob, including nonce).
- When encryption is disabled: the reference is the BLAKE3 hash of the plaintext.
- BLAKE3's internal tree hashing enables efficient verified streaming and range requests.
- Chunks may be compressed (optional, zstd/LZ4) before encryption.
- Reference counting + garbage collection for unreferenced chunks (after configurable retention or explicit GC).

### 4.2 Trees
- Directory manifests: Mapping of relative paths to child chunk CIDs or subtree CIDs.
- Merkle structure for efficient verification and diffing.

### 4.3 Commits
```rust-like
struct Commit {
    tree: ContentHash,       // Root tree of the snapshot (BLAKE3, hex in JSON)
    parents: Vec<ContentHash>, // Parent commit(s) — usually 0 or 1
    author: String,          // NodeID string in later phases
    timestamp: u64,
    message: String,
    // signature: Option<Signature>, // Optional for auditability (future)
}
```
- Commits are immutable and content-addressed: `BLAKE3(canonical compact JSON)`.
- Support linear history or lightweight branching (multiple heads possible; user resolves).
- Each successful `add` creates a commit **parented to the previous HEAD** and **merges** new paths into the existing tree (does not replace the whole tree).

### 4.3.1 ContentHash encoding
- Wire/on-disk JSON representation: **64-character lowercase hex** of the 32-byte BLAKE3 digest.
- Trees, commits, and CLI arguments all use this encoding (never raw JSON number arrays).

### 4.4 Vaults
```rust-like
struct Vault {
    name: String,
    // HEAD file points at current tip commit hash
    min_replicas: u8,               // Default 2; replication policy seed
    encryption_enabled: bool,       // Default: true
    // live_mode: bool,             // Continuous FS watching + sync (Phase 1+)
    // members: Vec<NodeID>,        // Or capability-based access (Phase 1+)
    created_at: u64,
}
```
- Symmetric vault key (when encryption enabled) is stored in a **separate** `vault.key` file (best-effort mode `0600` on Unix), not in `vault.json`.

**ReplicationPolicy** example:
- `min_replicas: u8` (default 2 or 3)
- Placement hints (e.g., prefer always-on nodes, geographic zones if extended)
- Optional future: erasure coding parameters (k-of-n)

### 4.5 Pins & Replication State
Nodes maintain local pin sets and gossip presence/health information. A replication engine ensures the configured minimum replicas exist across distinct nodes.

---

## 5. Node Identity & Security Model

### 5.1 Identity
- Every node has a persistent **ed25519 keypair** (Iroh `SecretKey`).
- NodeID = public key / Iroh EndpointId.
- Used for authentication, signing commits/invites, and dialing via Iroh.
- Reference implementation persists the secret key under `~/.soal/node.json` so the NodeID is stable across process restarts.

### 5.2 Encryption (Default: Always On)
- **At rest**: Chunks encrypted before storage (or key-wrapped). User can disable per vault or globally.
- **In transit**: Iroh QUIC provides authenticated encryption by default.
- Key management: Local keystore (file + optional passphrase or hardware integration later). Simple per-vault master key derivation.

### 5.2.1 Encryption + Content Addressing Approach
Soal combines plaintext chunking with per-vault encryption and ciphertext-based content addressing as follows (the model used in the reference implementation):

1. **Plaintext CDC chunking first**: Files are divided using Content-Defined Chunking on the original *plaintext*. This step is performed before any encryption so that identical content produces identical chunks, enabling deduplication *within a vault*.

2. **Per-vault encryption**: The plaintext chunk is encrypted using a symmetric key that is unique to the vault (XChaCha20-Poly1305 AEAD). A nonce is derived deterministically from the plaintext chunk (e.g., from its BLAKE3 hash) so that identical plaintext + same key always yields identical ciphertext. This preserves the deduplication benefit while keeping encryption secure.

3. **Store and reference by ciphertext hash**: The encrypted blob (nonce + ciphertext) is written to the local store. The *chunk identifier* placed into Merkle Trees (and thus referenced by Commits) is the BLAKE3 hash of the *ciphertext blob*. The on-disk and in-cluster content address is therefore always a hash of ciphertext when encryption is enabled.

When `encryption_enabled=false` for a vault, chunking + hashing uses plaintext directly (no encryption step).

**Deduplication trade-off**:
- Strong intra-vault deduplication: same plaintext chunk → same deterministic ciphertext → same ciphertext hash → stored only once.
- No cross-vault deduplication: different vaults have different keys, so even identical plaintexts produce different ciphertexts and different storage hashes.
- This is the right trade-off for Soal: vaults are the security and membership boundary. All members of a vault receive the same key during secure invite/join, so they all benefit from deduplication while data remains confidential to outsiders. In a trusted local cluster there is no need for convergent encryption schemes that weaken security for the sake of cross-user dedup.

This design keeps the local store simple (keyed by BLAKE3 of whatever is stored) while still delivering the deduplication wins that users expect inside their own data sets.

### 5.3 Integrity
- Everything is content-addressed (BLAKE3). Any tampering is immediately detectable.
- Optional signatures on commits and policy updates for non-repudiation and audit logs.

### 5.4 Access Control
- Vault membership via NodeID lists (initially simple).
- Future: Capability tokens or signed manifests (Tahoe-like read/write caps).
- Invite system: Cryptographically signed tokens/QR codes that grant specific vault membership and permissions.

### 5.5 Threat Model (Initial)
- Trusted cluster participants or properly capability-gated access.
- Protection against tampering, replay, and unauthorized access via hashes, signatures, and encryption.
- Local network reduces many remote attack surfaces.

---

## 6. Networking & Discovery

**Foundation**: Iroh (excellent LAN performance, dial-by-NodeID, QUIC, built-in encryption, `iroh-blobs` for content-addressed transfer, gossip, and docs primitives).

### 6.1 Discovery (Local-First)
- mDNS / Avahi for zero-config LAN node discovery.
- Secure invite/join flow (generate token → recipient verifies fingerprint and joins cluster/vault).
- Manual peer addition by NodeID.

### 6.2 Data Transfer
- Chunk/blob exchange built on `iroh-blobs` patterns: verified, resumable, parallel, range-request friendly (excellent for future media streaming).
- Have-lists / bloom filters or gossip announcements to efficiently discover who has what.

### 6.3 Metadata Synchronization
- Gossip for announcements (new commits, pin updates, health heartbeats).
- Eventually consistent metadata via CRDT-friendly structures (iroh-docs patterns) or simple signed head updates.
- Multiple heads supported; resolution is explicit/manual where needed.

### 6.4 Future Internet Extension (Far Future, Opt-In)
- Iroh already supports relays and hole-punching. Global peering can be added as a clean, optional layer without changing the core local protocol.

---

## 7. Core Operations & Workflows

### 7.1 Live Working Tree Sync
- Soal watches the filesystem (via `notify` or platform equivalents).
- On change: CDC chunking of modified data → new trees/commits (or lightweight updates) → propagation to peers via gossip + direct chunk transfer.
- Peers apply changes to their live working trees.
- Designed to feel seamless for notes, photos, and documents.

### 7.2 Snapshots (Manual or Timed)
- User (or scheduler) creates an explicit immutable commit: `soal snapshot "Before trip" --vault photos`.
- Snapshots are first-class, restorable, and can serve as backup points or branch roots.
- History is queryable and diffable.

### 7.3 Adding Data
- `soal add <path> --vault <name>` → chunks data, updates live tree, optionally creates snapshot.

### 7.4 Replication & Redundancy
- Configurable `min_replicas` (default 2–3).
- Replication engine monitors and re-replicates as needed (self-healing).
- Nodes can be designated as "storage-heavy" or always-on for better placement.
- As cluster grows, policy can automatically suggest or enforce higher replication for important vaults.

### 7.5 Conflict Handling
- Goal: Minimize via live model + snapshots.
- When concurrent edits to the same file occur: Create conflict copies (e.g., `file.txt` and `file (conflict from NodeX).txt`) + clear notification.
- User performs manual resolution (or uses external tools). No surprising auto-merge for binary/general files.

### 7.6 Restore & History
- Restore any commit/tree to a path or new location.
- Full history navigation and diffing.

---

## 8. CLI Specification (Initial Commands)

```bash
# Node & Cluster
soal init [--name <cluster-name>]
soal status
soal peers list
soal invite generate [--vault <name>] [--role read|write]
soal join <invite-token-or-file>

# Vaults
soal vault create <name> [--replicas 3] [--live] [--encrypt true|false]
soal vault list
soal vault policy set <name> --replicas 4

# Data Operations
soal add <path> [--vault <name>] [--snapshot "message"]
soal snapshot "message" [--vault <name>] [--path <subpath>]
soal restore <commit-cid> [--to <path>]

# Maintenance
soal pin <cid-or-vault> [--replicas N]
soal gc [--dry-run]
soal health
```

CLI is built with `clap`, provides excellent help, progress, and JSON output mode for scripting.

---

## 9. API (Embeddable)

- Rust library crate (`soal-core`, `soal-vault`, etc.) with clean traits.
- Optional HTTP/gRPC server for external tools and future modules.
- Key abstractions: `ChunkStore`, `VaultManager`, `SyncEngine`, `ReplicationEngine`.
- Designed for easy integration into notes apps, media players, AI agents, etc.

---

## 10. Redundancy, Self-Healing & Performance

- **Replication first** (simple, fast on LAN). Erasure coding as optional future enhancement for storage-constrained scenarios.
- Health monitoring via gossip heartbeats + periodic verification.
- Self-healing: Automatically re-replicate when replicas fall below policy.
- Performance: Parallel verified chunk transfers, deduplication at chunk level, LAN-optimized (high throughput, low latency).
- Resource awareness: Tunable memory/CPU usage; suitable for always-on low-power devices (Raspberry Pi class) and laptops/desktops.

---

## 11. Implementation Guidelines

### Technology Stack (Initial)
- **Language**: Rust (safety, performance, excellent async ecosystem, cross-compilation to macOS/Windows/Linux).
- **Core crates**:
  - `iroh` + `iroh-blobs` (networking + content-addressed transfer)
  - `blake3` (primary hash)
  - CDC implementation (Rabin or FastCDC; existing crates or careful port)
  - `clap` (CLI)
  - `notify` (filesystem watching)
  - `serde` + CBOR or Protobuf (serialization)
  - Local store: `sled` / RocksDB or custom file-based with iroh-blobs compatibility
- **Testing**: Heavy use of property-based testing (chunking determinism, encryption roundtrips, Merkle verification, replication invariants), integration tests, and simulation for P2P behavior.
- **Cross-compilation**: Prioritize clean `cargo build --target` for x86_64-apple-darwin, aarch64-apple-darwin, x86_64-pc-windows-msvc, etc. from day one.
- **Modularity**: Separate crates for `soal-core`, `soal-chunking`, `soal-vault`, `soal-sync`, `soal-cli`, etc. This enables independent testing and future module development.
- **Encryption in Phase 0**: Implement per-vault symmetric keys with plaintext CDC chunking, followed by AEAD encryption (deterministic nonce from plaintext for dedup), storing and addressing chunks by BLAKE3 hash of the ciphertext blob. Support toggling encryption per-vault at creation. See Security Model §5.2.1 for details.

### Code Quality Standards
- Small, focused functions and modules.
- Comprehensive documentation and examples.
- Test coverage for all core invariants.
- Clear error handling and observability (logs, metrics hooks).
- Incremental delivery: Every phase produces a working, useful artifact.

---

## 12. Roadmap (Phased, Testable Delivery)

**Phase 0 – Core Local Foundation** (manageable first chunk)
- Configurable CDC + BLAKE3 chunk store (local)
- Merkle Trees + Commits
- Basic Vault + Snapshot creation
- Encryption (default on, toggleable)
- CLI skeleton for local operations
- Property tests + cross-compile for macOS + Windows
- **Goal**: Usable local backup/snapshot tool for photos and notes

**Phase 1 – Multi-Node Live Sync**
- Iroh integration + LAN discovery
- 2+ node vault sharing with live working tree
- Replication policy (min 2–3) + basic self-healing
- Gossip for presence and new commits
- Conflict copy + manual resolution flow
- **Goal**: Real cluster syncing your photos/notes across devices

**Phase 2 – Polish & Reliability**
- Full policy engine, timed snapshots, improved observability
- Refined CLI + initial embeddable API
- Better replication placement and health reporting
- More comprehensive testing
- **Goal**: High-quality daily driver for sanctuary use cases

**Phase 3+ (Future Modules)**
- Media streaming module (chunk range requests for music players)
- Notes-specific enhancements
- Optional FUSE mount
- Erasure coding prototype
- Opt-in internet peering (Iroh relays)
- AI / second-brain integration hooks
- Packaging, documentation, and community onboarding

---

## 13. Future Considerations (Post v0.3)

- Erasure coding for efficient redundancy.
- Optional global/internet peering (clean Iroh extension).
- Richer access control (capabilities, fine-grained ACLs).
- FUSE / filesystem mount for seamless application integration.
- Media streaming gateway (HTTP, DLNA/UPnP, or simple range server).
- Hardware security module / key integration.
- Broader platform support (Android, iOS later).
- Governance evolution beyond initial BDFL model.

---

## 14. Governance & Licensing

- **Early stage**: BDFL model with Jeffrey Stewart (@soaljack) as founder making final architectural and directional decisions to maintain high quality and focus.
- Clear documentation of decisions and rationale.
- Transition path to broader community governance (e.g., steering committee, foundation) as the project matures and adoption grows.
- **Licensing**: Dual MIT/Apache-2.0 (permissive, business-friendly). Finalized in the repository (see LICENSE, LICENSE-MIT, LICENSE-APACHE).
- Contribution model: Clear CONTRIBUTING.md emphasizing quality, tests, and incremental delivery.

---

## Appendix: Example Data Flow (Photo Added to Live Vault)

1. User adds photo to watched folder.
2. CDC splits photo into ~2 MiB plaintext chunks (BLAKE3).
3. Each plaintext chunk is encrypted with the vault key (deterministic for dedup); stored under BLAKE3 hash of the ciphertext.
4. New Tree (referencing ciphertext hashes) and lightweight Commit created (or live head updated).
5. Gossip announces new content / head update.
6. Peers pull missing chunks via verified `iroh-blobs` streams.
7. Peers apply to their live working trees.
8. Replication engine ensures min_replicas are satisfied across nodes.
9. User can later create explicit snapshot for backup point.

All steps are verifiable via content hashes (ciphertext hashes when encryption is enabled). Encryption protects data at rest and in flight. Key is per-vault and shared only with vault members.

---

**This specification is a living document.** It will be refined through implementation, testing, and community feedback while maintaining focus on high-quality, reliable, modular code delivered in testable increments.

**Phase 0 status**: Complete (see implementation in `src/` and `tests/`).

**Phase 1 status**: **Complete** (multi-node core + control plane + invites + merge + replication + watch):
- Persistent node identity (Iroh `SecretKey` under `~/.soal/node.json`)
- Persisted peer list with EndpointId / ticket validation
- **vault_id** (16 random bytes) per vault; gossip topic = `BLAKE3("soal/v1/vault/" ‖ vault_id)` (**KD-08**)
- **Signed** HeadAnnouncement CBOR (DOMAIN_HEAD sign preimage); seq + skew + replay checks (**INV-SIG-02**, **INV-REPLAY-01**, **INV-SKEW-01**)
- iroh-blobs provide/fetch with BLAKE3 integrity; **provide_from_vault** reloads CAS after restart (**PR-07a** hybrid)
- **SyncEngine** (`src/sync.rs`): parent DAG walk, peer failover, job checkpoints (**PR-07b**)
- Multi-node gates in `tests/multi_node.rs`: SC-2N-BASIC, SC-IDEM, SC-CORRUPT, SC-SIG, SC-IROH-CID, parent DAG (**PR-07c**)
- Codec: domain frames + deterministic CBOR Tree/Commit/Head (**src/codec.rs**)
- Dual-read: `.bin` wire primary, legacy `.json` still loadable
- Signed commits when node identity present; import rejects bad signatures
- **PR-05**: Argon2id passphrase `WrappedKey` (`vault.wrapped.json`) + signed `VaultConfig` (`config_sig` / `owner` / `config_seq`)
- **PR-12**: Signed invites (`soal invite generate|join`) — vault key sealed under invite secret; membership shared
- **PR-08**: Multi-head tracking (`HEADS`) + `merge_head` conflict copies (`name (conflict from Label).ext`)
- **PR-09**: Replication pins, peer-have estimates, `soal replicate [--push]` self-heal provide
- **PR-11**: Live FS watch (`soal watch`) via `notify` with debounce
- **Discovery**: gossip topic `BLAKE3("soal/v1/discovery")` — `soal node beacon` / `discover [--add]`
- CLI: `log`, `gc`, `merge`, `sync --merge`, `replicate`, invites, watch, snapshot `--announce`

### Implementation quality notes (reference implementation)

These decisions close design gaps found during Phase 0/1 hardening (aligned with design doc v0.2):

| Topic | Decision |
|-------|----------|
| Content hash in JSON | 64-char lowercase hex (not raw byte arrays); uppercase accepted on parse |
| Tree/commit addressing | **Wire CID** = BLAKE3(`DOMAIN \|\| cbor(body)`); store as `.bin`; dual-read legacy JSON via `legacy_json_hash` |
| Incremental `add` | Merges into HEAD tree; commit parents to HEAD (**INV-DAG-01**, **INV-TREE-01**) |
| Vault key storage | Separate `vault.key` (0600); optional Argon2id wrap in `vault.wrapped.json` |
| vault_id | 16-byte OsRng id, 32 hex in `vault.json`; legacy open auto-migrates |
| Store integrity | `put`/`put_verified`/`get` reject BLAKE3 mismatches; **CID collision** is a hard error (**INV-IMPORT-03**) |
| Path safety | Reject `..`, absolute, backslash, NUL on add/restore (**INV-PATH-01**) |
| Wire framing | Domain 16-byte prefix + CBOR body; CID = BLAKE3(wire) (**INV-CID-WIRE-01**) |
| Commit signatures | ed25519 via Iroh `SecretKey`; sign preimage = DOMAIN_COMMIT\|\|cbor(fields 1–6); unsigned allowed for local-only (**INV-SIG-01** on non-zero sigs) |
| Head signatures | DOMAIN_HEAD\|\|cbor(SignAnn fields 1,2,4–8); gossip payload raw CBOR 9 keys (**INV-SIG-02**) |
| Config signatures | DOMAIN_CONFIG\|\|JSON body without `config_sig`; owner NodeID required when signed |
| Invites | DOMAIN_INVITE sign preimage; vault key sealed with invite secret + AAD `soal/invite/key/v1` |
| Conflicts | Merge keeps ours; theirs written to conflict-copy path; multi-parent commit |
| Replication | Local pins + estimated replica counts; `--push` re-provides HEAD DAG |
| Node identity | Persistent across CLI invocations; used as commit author when present |
| Peer list | Persisted; invalid EndpointIds rejected at add time |
| Sync | `--head` or signed gossip heads; never pull local HEAD alone; DAG parents + checkpoints |
| Discovery | Shared gossip topic for ticket beacons (LAN-friendly without mDNS dependency) |

**Phase 2 next**: full policy engine, timed snapshots, richer health UI, embeddable API polish, placement-aware replication, optional native iroh-blobs disk store.

---

*Document written with care for sovereignty, reliability, and long-term usefulness.*  
*Soal — Your data, your network, your rules.*
