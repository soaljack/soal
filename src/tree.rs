//! Merkle Tree manifests for directories
use crate::chunking::hash_bytes;
use crate::{ContentHash, SoalError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Entry in a directory tree
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TreeEntry {
    File {
        size: u64,
        chunks: Vec<ContentHash>,
    },
    Dir {
        hash: ContentHash,
    },
}

/// A Merkle tree representing a directory snapshot
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tree {
    pub entries: BTreeMap<String, TreeEntry>,
}

impl Tree {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Compute the content hash of this tree manifest (canonical serialization)
    pub fn hash(&self) -> ContentHash {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        hash_bytes(&bytes)
    }

    /// Add a file entry
    pub fn add_file(&mut self, path: &str, size: u64, chunks: Vec<ContentHash>) {
        self.entries.insert(
            path.to_string(),
            TreeEntry::File { size, chunks },
        );
    }

    /// Add a subdirectory reference
    pub fn add_dir(&mut self, path: &str, hash: ContentHash) {
        self.entries.insert(path.to_string(), TreeEntry::Dir { hash });
    }

    /// Serialize to JSON (pretty for human, but we use compact for hash)
    pub fn to_json(&self) -> Result<String, SoalError> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    pub fn from_json(s: &str) -> Result<Self, SoalError> {
        serde_json::from_str(s).map_err(Into::into)
    }
}

impl Default for Tree {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a tree from a filesystem path (recursively).
/// This is a simplified version for Phase 0 (single level + files for MVP).
/// Full recursive tree building will be added.
pub fn build_tree_from_path<P: AsRef<Path>>(
    _base: P,
) -> Result<Tree, SoalError> {
    // Placeholder - we'll implement full walker in vault/add
    // For now return empty tree
    Ok(Tree::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_hash_deterministic() {
        let mut t1 = Tree::new();
        t1.add_file("a.txt", 10, vec![[1u8; 32]]);
        let h1 = t1.hash();

        let mut t2 = Tree::new();
        t2.add_file("a.txt", 10, vec![[1u8; 32]]);
        let h2 = t2.hash();

        assert_eq!(h1, h2);
    }

    #[test]
    fn tree_serde_roundtrip() {
        let mut tree = Tree::new();
        tree.add_file("notes.md", 123, vec![[42u8; 32]]);
        let json = tree.to_json().unwrap();
        let restored = Tree::from_json(&json).unwrap();
        assert_eq!(tree, restored);
    }
}
