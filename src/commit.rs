//! Commit = immutable snapshot (Merkle DAG)
use crate::{ContentHash, SoalError};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit {
    pub tree: ContentHash,
    pub parents: Vec<ContentHash>,
    pub author: String,
    pub timestamp: u64,
    pub message: String,
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
            .unwrap()
            .as_secs();
        Self {
            tree,
            parents,
            author: author.into(),
            timestamp,
            message: message.into(),
        }
    }

    /// Hash of the commit itself (content addressed)
    pub fn hash(&self) -> ContentHash {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        crate::chunking::hash_bytes(&bytes)
    }

    pub fn to_json(&self) -> Result<String, SoalError> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    pub fn from_json(s: &str) -> Result<Self, SoalError> {
        serde_json::from_str(s).map_err(Into::into)
    }
}

/// Helper to create an initial commit for a tree
pub fn create_initial_commit(tree_hash: ContentHash, message: &str) -> Commit {
    Commit::new(tree_hash, vec![], "soal-local", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_hash_and_serde() {
        let tree_hash = [7u8; 32];
        let commit = create_initial_commit(tree_hash, "initial");
        let h = commit.hash();
        assert_eq!(commit.tree, tree_hash);

        let json = commit.to_json().unwrap();
        let back = Commit::from_json(&json).unwrap();
        assert_eq!(back.hash(), h);
    }

    #[test]
    fn commit_with_parents_forms_chain() {
        let t1 = [1u8; 32];
        let c1 = create_initial_commit(t1, "c1");
        let h1 = c1.hash();

        let mut c2 = Commit::new(t1, vec![h1], "soal-local", "c2");
        // simulate timestamp stable for test
        c2.timestamp = 123;
        let h2 = c2.hash();

        let c3 = Commit::new(t1, vec![h2], "soal-local", "c3");
        let json = c3.to_json().unwrap();
        let back: Commit = Commit::from_json(&json).unwrap();
        assert_eq!(back.parents, vec![h2]);
        assert!(back.hash() != h2);
    }
}
