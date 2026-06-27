# soal

**Soal** — A lightweight, sovereign, open-source protocol for secure, redundant, versioned, content-addressed distributed file storage and synchronization.

Designed for local networks first (LAN, home clusters, off-grid), with a clean path to opt-in internet peering.

## Status

This is the initial draft of the protocol specification.

See [spec.md](./spec.md) for the full Soal Protocol Specification (v0.1).

## Key Ideas

- Content-defined chunking (CDC) + BLAKE3
- Git-like Merkle DAG commits + live working tree sync
- Iroh-powered peer-to-peer (primary)
- Strong encryption and sovereignty by default
- Configurable replication across trusted nodes

## Next Steps

Proceed to Phase 0 implementation scaffold (Rust project structure, core chunking, CLI skeleton).

## Links

- Founder: [@soaljack](https://github.com/soaljack)
- License: MIT / Apache-2.0 (TBD)

*Your data, your network, your rules.*
