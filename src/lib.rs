//! Soal core library — Phase 0–2.
//!
//! Content-addressed storage, CDC chunking, vault encryption, Merkle trees/commits,
//! Iroh gossip + blob transfer, policy engine, health, and embeddable API.

pub mod api;
pub mod chunking;
pub mod codec;
pub mod commit;
pub mod crypto;
pub mod health;
pub mod identity;
pub mod invite;
pub mod network;
pub mod policy;
pub mod replication;
pub mod schedule;
pub mod store;
pub mod sync;
pub mod tree;
pub mod vault;
pub mod watch;

// Re-export the high-level session API for embedders.
pub use api::SoalSession;

pub use anyhow::Result;
pub use blake3::Hash as Blake3Hash;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// 32-byte BLAKE3 content hash.
///
/// Serialized as a 64-character lowercase hex string in JSON (not a byte array),
/// so manifests are human-readable and CLI/sync code can parse hashes uniformly.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct ContentHash(pub [u8; 32]);

impl ContentHash {
    pub const ZERO: Self = Self([0u8; 32]);

    #[inline]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[inline]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a 64-char hex string into a content hash.
    /// Accepts uppercase or lowercase; rejects non-hex and wrong length.
    pub fn from_hex(s: &str) -> std::result::Result<Self, SoalError> {
        let s = s.trim();
        if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SoalError::InvalidHash);
        }
        let bytes = hex::decode(s).map_err(|_| SoalError::InvalidHash)?;
        if bytes.len() != 32 {
            return Err(SoalError::InvalidHash);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// BLAKE3 hash of arbitrary bytes.
    pub fn of(data: &[u8]) -> Self {
        Self(blake3::hash(data).into())
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({})", self.to_hex())
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl From<[u8; 32]> for ContentHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<blake3::Hash> for ContentHash {
    fn from(h: blake3::Hash) -> Self {
        Self(*h.as_bytes())
    }
}

impl From<ContentHash> for [u8; 32] {
    fn from(h: ContentHash) -> Self {
        h.0
    }
}

impl AsRef<[u8; 32]> for ContentHash {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serialize for ContentHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        ContentHash::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Library error type for Soal operations.
#[derive(thiserror::Error, Debug)]
pub enum SoalError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Invalid hash")]
    InvalidHash,
    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("Vault not found: {0}")]
    VaultNotFound(String),
    #[error("Chunk not found: {0}")]
    ChunkNotFound(String),
    #[error("Commit not found: {0}")]
    CommitNotFound(String),
    #[error("Tree not found: {0}")]
    TreeNotFound(String),
    #[error("CID collision: existing blob under {hash} has different bytes")]
    CidCollision { hash: String },
    #[error("Invalid path: {0}")]
    InvalidPath(String),
    #[error("Verification failed: {0}")]
    Verify(String),
    #[error("{0}")]
    Other(String),
}

impl SoalError {
    pub fn hash_mismatch(expected: &ContentHash, actual: &ContentHash) -> Self {
        Self::HashMismatch {
            expected: expected.to_hex(),
            actual: actual.to_hex(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_hash_hex_roundtrip() {
        let h = ContentHash::of(b"hello soal");
        let hex = h.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(ContentHash::from_hex(&hex).unwrap(), h);
    }

    #[test]
    fn content_hash_json_is_hex_string() {
        let h = ContentHash::of(b"json");
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.starts_with('"'));
        assert_eq!(json.len(), 66); // quotes + 64 hex
        let back: ContentHash = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn content_hash_from_hex_accepts_uppercase() {
        let h = ContentHash::of(b"upper");
        let upper = h.to_hex().to_uppercase();
        assert_eq!(ContentHash::from_hex(&upper).unwrap(), h);
    }

    #[test]
    fn content_hash_from_hex_rejects_bad_length() {
        assert!(ContentHash::from_hex("abcd").is_err());
        assert!(ContentHash::from_hex(&"0".repeat(63)).is_err());
        assert!(ContentHash::from_hex(&"g".repeat(64)).is_err());
    }

    #[test]
    fn content_hash_of_is_blake3() {
        let data = b"soal property";
        let h = ContentHash::of(data);
        assert_eq!(h.0, *blake3::hash(data).as_bytes());
    }

    #[test]
    fn content_hash_ordering_stable() {
        let a = ContentHash::from([0u8; 32]);
        let b = ContentHash::from([1u8; 32]);
        assert!(a < b);
        assert_eq!(ContentHash::ZERO, a);
    }
}
