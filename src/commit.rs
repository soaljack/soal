//! Commit = immutable snapshot (Merkle DAG node).
//!
//! Content addressing (v0.2 wire): `Commit::hash()` = BLAKE3(DOMAIN_COMMIT || cbor(CommitBody)).
//! Legacy JSON form is still readable via `legacy_json_hash` / dual-read in the vault.

use crate::codec::{self, PROTOCOL_VERSION};
use crate::{ContentHash, SoalError};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commit {
    pub tree: ContentHash,
    pub parents: Vec<ContentHash>,
    pub author: String,
    pub timestamp: u64,
    pub message: String,
    /// Wire protocol version (1). Default 0 in JSON means "treat as 1 for wire".
    #[serde(default)]
    pub protocol_version: u16,
    /// Optional ed25519 signature as 128-char hex (64 bytes). Absent/empty = unsigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Commit {
    pub fn new(
        tree: ContentHash,
        parents: Vec<ContentHash>,
        author: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            tree,
            parents,
            author: author.into(),
            timestamp,
            message: message.into(),
            protocol_version: PROTOCOL_VERSION as u16,
            signature: None,
        }
    }

    /// 64-byte signature (zeros if unsigned).
    pub fn signature_bytes(&self) -> [u8; 64] {
        if let Some(ref hex_sig) = self.signature {
            if let Ok(bytes) = hex::decode(hex_sig.trim()) {
                if bytes.len() == 64 {
                    let mut a = [0u8; 64];
                    a.copy_from_slice(&bytes);
                    return a;
                }
            }
        }
        [0u8; 64]
    }

    pub fn is_signed(&self) -> bool {
        self.signature_bytes() != [0u8; 64]
    }

    /// Canonical wire bytes: DOMAIN_COMMIT || CBOR CommitBody.
    pub fn wire_bytes(&self) -> Result<Vec<u8>, SoalError> {
        codec::encode_commit_wire(self)
    }

    /// Content hash of the commit (wire CID).
    pub fn hash(&self) -> Result<ContentHash, SoalError> {
        codec::commit_cid(self)
    }

    /// Legacy JSON content hash (format 0 dual-read).
    pub fn legacy_json_hash(&self) -> Result<ContentHash, SoalError> {
        Ok(ContentHash::of(&self.legacy_json_bytes()?))
    }

    /// Compact JSON used by older vaults (fields without wire-only defaults stripped carefully).
    pub fn legacy_json_bytes(&self) -> Result<Vec<u8>, SoalError> {
        // Stable subset for legacy CIDs: tree, parents, author, timestamp, message only.
        #[derive(Serialize)]
        struct Legacy<'a> {
            tree: &'a ContentHash,
            parents: &'a [ContentHash],
            author: &'a str,
            timestamp: u64,
            message: &'a str,
        }
        serde_json::to_vec(&Legacy {
            tree: &self.tree,
            parents: &self.parents,
            author: &self.author,
            timestamp: self.timestamp,
            message: &self.message,
        })
        .map_err(Into::into)
    }

    /// Prefer wire; fall back to JSON parse for dual-read.
    pub fn from_wire_or_json(data: &[u8]) -> Result<Self, SoalError> {
        if data.len() >= 16 && data[..16] == codec::DOMAIN_COMMIT {
            return codec::decode_commit_wire(data);
        }
        Self::from_bytes(data)
    }

    pub fn to_json(&self) -> Result<String, SoalError> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    pub fn from_json(s: &str) -> Result<Self, SoalError> {
        serde_json::from_str(s).map_err(Into::into)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, SoalError> {
        serde_json::from_slice(data).map_err(Into::into)
    }
}

/// Helper to create an initial (parentless) commit for a tree.
pub fn create_initial_commit(tree_hash: ContentHash, message: &str) -> Commit {
    Commit::new(tree_hash, vec![], "soal-local", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_hash_and_serde() {
        let tree_hash = ContentHash::from([7u8; 32]);
        let mut commit = create_initial_commit(tree_hash, "initial");
        commit.timestamp = 1; // stable for test
        let h = commit.hash().unwrap();
        assert_eq!(commit.tree, tree_hash);

        let wire = commit.wire_bytes().unwrap();
        assert_eq!(ContentHash::of(&wire), h);
        let back = Commit::from_wire_or_json(&wire).unwrap();
        assert_eq!(back.hash().unwrap(), h);
    }

    #[test]
    fn commit_with_parents_forms_chain() {
        let t1 = ContentHash::from([1u8; 32]);
        let mut c1 = create_initial_commit(t1, "c1");
        c1.timestamp = 1;
        let h1 = c1.hash().unwrap();

        let mut c2 = Commit::new(t1, vec![h1], "soal-local", "c2");
        c2.timestamp = 123;
        let h2 = c2.hash().unwrap();

        let mut c3 = Commit::new(t1, vec![h2], "soal-local", "c3");
        c3.timestamp = 456;
        let wire = c3.wire_bytes().unwrap();
        let back = Commit::from_wire_or_json(&wire).unwrap();
        // parents preserved
        assert_eq!(back.parents, vec![h2]);
        assert_ne!(back.hash().unwrap(), h2);
    }

    #[test]
    fn hash_is_stable_for_identical_fields() {
        let t = ContentHash::from([9u8; 32]);
        let c1 = Commit {
            tree: t,
            parents: vec![],
            author: "a".into(),
            timestamp: 42,
            message: "m".into(),
            protocol_version: 1,
            signature: None,
        };
        let c2 = c1.clone();
        assert_eq!(c1.hash().unwrap(), c2.hash().unwrap());
    }

    #[test]
    fn legacy_json_hash_stable() {
        let c = Commit {
            tree: ContentHash::from([1u8; 32]),
            parents: vec![],
            author: "soal-local".into(),
            timestamp: 1,
            message: "x".into(),
            protocol_version: 1,
            signature: None,
        };
        let h1 = c.legacy_json_hash().unwrap();
        let h2 = c.legacy_json_hash().unwrap();
        assert_eq!(h1, h2);
        // wire hash differs from legacy JSON hash
        assert_ne!(c.hash().unwrap(), h1);
    }
}
