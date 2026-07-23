//! Merkle tree manifests for directories.
//!
//! Content addressing (v0.2 wire): `Tree::hash()` = BLAKE3(DOMAIN_TREE || cbor(TreeBody)).
//! Legacy compact JSON remains available via `legacy_json_hash` for dual-read.

use crate::codec;
use crate::{ContentHash, SoalError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Entry in a directory tree.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TreeEntry {
    File { size: u64, chunks: Vec<ContentHash> },
    Dir { hash: ContentHash },
}

/// A Merkle tree representing a directory snapshot.
///
/// Entries use relative paths with `/` separators (normalized). Files may be
/// stored flat (`a/b/c.txt` as a single key) or via nested `Dir` references.
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

    /// Legacy compact JSON bytes (format 0 dual-read).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SoalError> {
        serde_json::to_vec(self).map_err(Into::into)
    }

    /// Wire bytes: DOMAIN_TREE || CBOR TreeBody.
    pub fn wire_bytes(&self) -> Result<Vec<u8>, SoalError> {
        codec::encode_tree_wire(self)
    }

    /// Content hash of this tree (wire CID).
    pub fn hash(&self) -> Result<ContentHash, SoalError> {
        codec::tree_cid(self)
    }

    /// Legacy JSON content hash (format 0 dual-read).
    pub fn legacy_json_hash(&self) -> Result<ContentHash, SoalError> {
        Ok(ContentHash::of(&self.canonical_bytes()?))
    }

    /// Decode from framed wire or legacy JSON.
    pub fn from_wire_or_json(data: &[u8]) -> Result<Self, SoalError> {
        if data.len() >= 16 && data[..16] == codec::DOMAIN_TREE {
            return codec::decode_tree_wire(data);
        }
        Self::from_bytes(data)
    }

    /// Add or replace a file entry. Paths are normalized and validated (INV-PATH-01).
    pub fn add_file(&mut self, path: &str, size: u64, chunks: Vec<ContentHash>) {
        let path = normalize_and_validate(path).unwrap_or_else(|_| normalize_path(path));
        self.entries.insert(path, TreeEntry::File { size, chunks });
    }

    /// Fallible file add with strict path validation.
    pub fn try_add_file(
        &mut self,
        path: &str,
        size: u64,
        chunks: Vec<ContentHash>,
    ) -> Result<(), SoalError> {
        let path = normalize_and_validate(path)?;
        self.entries.insert(path, TreeEntry::File { size, chunks });
        Ok(())
    }

    /// Add or replace a subdirectory reference.
    pub fn add_dir(&mut self, path: &str, hash: ContentHash) {
        let path = normalize_and_validate(path).unwrap_or_else(|_| normalize_path(path));
        self.entries.insert(path, TreeEntry::Dir { hash });
    }

    /// Merge another tree into this one (other wins on path conflicts).
    pub fn merge(&mut self, other: &Tree) {
        for (k, v) in &other.entries {
            self.entries.insert(k.clone(), v.clone());
        }
    }

    /// Merge `theirs` into `self` (ours), writing conflict copies on divergent paths (PR-08).
    ///
    /// For each path present in both trees with different content:
    /// - Keep our entry at the original path
    /// - Write theirs as `{stem} (conflict from {from_label}){ext}`
    ///
    /// Identical entries are left as-is. Paths only in `theirs` are added.
    /// Returns the number of conflict copies created.
    pub fn merge_with_conflicts(&mut self, theirs: &Tree, from_label: &str) -> usize {
        let mut conflicts = 0usize;
        let label = sanitize_conflict_label(from_label);
        for (path, their_entry) in &theirs.entries {
            match self.entries.get(path) {
                None => {
                    self.entries.insert(path.clone(), their_entry.clone());
                }
                Some(our_entry) if our_entry == their_entry => {
                    // identical — keep
                }
                Some(_) => {
                    let conflict_path = conflict_path_name(path, &label);
                    self.entries.insert(conflict_path, their_entry.clone());
                    conflicts += 1;
                }
            }
        }
        conflicts
    }

    /// Collect all file chunk hashes (flat; does not recurse into Dir CIDs).
    pub fn all_chunk_hashes(&self) -> Vec<ContentHash> {
        let mut out = Vec::new();
        for entry in self.entries.values() {
            if let TreeEntry::File { chunks, .. } = entry {
                out.extend(chunks.iter().copied());
            }
        }
        out
    }

    /// Pretty JSON for on-disk human-readable storage.
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

impl Default for Tree {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalize path separators to `/` and strip leading `./`.
/// Does **not** validate safety — use [`validate_path`] / [`normalize_and_validate`].
pub fn normalize_path(path: &str) -> String {
    let s = path.replace('\\', "/");
    let s = s.trim_start_matches("./");
    s.trim_matches('/').to_string()
}

/// Validate a logical vault path (INV-PATH-01).
///
/// Rejects empty paths, `.` / `..` segments, NUL, backslash, absolute forms
/// (`/…`, `C:…`), and empty segments.
pub fn validate_path(path: &str) -> Result<(), SoalError> {
    if path.is_empty() {
        return Err(SoalError::InvalidPath("empty path".into()));
    }
    if path.contains('\0') {
        return Err(SoalError::InvalidPath("NUL in path".into()));
    }
    if path.contains('\\') {
        return Err(SoalError::InvalidPath("backslash not allowed".into()));
    }
    if path.starts_with('/') {
        return Err(SoalError::InvalidPath("absolute path not allowed".into()));
    }
    // Windows drive prefix
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(SoalError::InvalidPath(
            "drive-absolute path not allowed".into(),
        ));
    }
    for seg in path.split('/') {
        if seg.is_empty() {
            return Err(SoalError::InvalidPath("empty path segment".into()));
        }
        if seg == "." || seg == ".." {
            return Err(SoalError::InvalidPath(format!("illegal segment '{seg}'")));
        }
    }
    Ok(())
}

/// Normalize then validate (preferred for add/restore entry points).
///
/// Logical vault paths must use `/`. Backslash is rejected (INV-PATH-01) rather
/// than silently rewritten, so OS-relative paths should be converted by the
/// caller using known-safe relative components only.
pub fn normalize_and_validate(path: &str) -> Result<String, SoalError> {
    if path.contains('\0') {
        return Err(SoalError::InvalidPath("NUL in path".into()));
    }
    if path.contains('\\') {
        return Err(SoalError::InvalidPath("backslash not allowed".into()));
    }
    let n = normalize_path(path);
    validate_path(&n)?;
    Ok(n)
}

/// Build a conflict copy path: `dir/name (conflict from Label).ext`.
pub fn conflict_path_name(path: &str, from_label: &str) -> String {
    let (dir, file) = match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    };
    let (stem, ext) = match file.rfind('.') {
        Some(i) if i > 0 => (&file[..i], &file[i..]),
        _ => (file, ""),
    };
    format!("{dir}{stem} (conflict from {from_label}){ext}")
}

fn sanitize_conflict_label(label: &str) -> String {
    let s: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(32)
        .collect();
    if s.is_empty() {
        "remote".into()
    } else {
        s
    }
}

/// Ensure `target_dir.join(logical)` stays under `target_dir` after canonicalize-ish checks.
pub fn safe_join(
    target_dir: &std::path::Path,
    logical: &str,
) -> Result<std::path::PathBuf, SoalError> {
    let logical = normalize_and_validate(logical)?;
    let joined = target_dir.join(&logical);
    // Lexical check: no component may be ParentDir after join
    use std::path::Component;
    for c in joined.components() {
        if matches!(c, Component::ParentDir) {
            return Err(SoalError::InvalidPath(
                "path escapes target directory".into(),
            ));
        }
    }
    // If target exists, ensure joined stays within it via strip_prefix of canonical roots.
    if target_dir.exists() {
        let base = target_dir.canonicalize()?;
        // Create parent chain conceptually; only check if joined exists
        if joined.exists() {
            let full = joined.canonicalize()?;
            if !full.starts_with(&base) {
                return Err(SoalError::InvalidPath(
                    "path escapes target directory".into(),
                ));
            }
        } else if let Some(parent) = joined.parent() {
            if parent.exists() {
                let parent_c = parent.canonicalize()?;
                if !parent_c.starts_with(&base) {
                    return Err(SoalError::InvalidPath(
                        "path escapes target directory".into(),
                    ));
                }
            }
        }
    }
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_with_conflicts_keeps_both() {
        let mut ours = Tree::new();
        ours.add_file("note.txt", 1, vec![ContentHash::from([1u8; 32])]);
        let mut theirs = Tree::new();
        theirs.add_file("note.txt", 2, vec![ContentHash::from([2u8; 32])]);
        theirs.add_file("only-theirs.txt", 3, vec![ContentHash::from([3u8; 32])]);
        let n = ours.merge_with_conflicts(&theirs, "NodeX");
        assert_eq!(n, 1);
        assert!(ours.entries.contains_key("note.txt"));
        assert!(ours.entries.contains_key("note (conflict from NodeX).txt"));
        assert!(ours.entries.contains_key("only-theirs.txt"));
    }

    #[test]
    fn tree_hash_deterministic() {
        let mut t1 = Tree::new();
        t1.add_file("a.txt", 10, vec![ContentHash::from([1u8; 32])]);
        let h1 = t1.hash().unwrap();

        let mut t2 = Tree::new();
        t2.add_file("a.txt", 10, vec![ContentHash::from([1u8; 32])]);
        let h2 = t2.hash().unwrap();

        assert_eq!(h1, h2);
    }

    #[test]
    fn tree_serde_roundtrip_hex_hashes() {
        let mut tree = Tree::new();
        tree.add_file("notes.md", 123, vec![ContentHash::from([42u8; 32])]);
        let json = tree.to_json().unwrap();
        assert!(json.contains(&ContentHash::from([42u8; 32]).to_hex()));
        let restored = Tree::from_json(&json).unwrap();
        assert_eq!(tree, restored);
        assert_eq!(tree.hash().unwrap(), restored.hash().unwrap());
    }

    #[test]
    fn tree_wire_hash_matches_bytes() {
        let mut tree = Tree::new();
        tree.add_file("a.txt", 1, vec![ContentHash::from([1u8; 32])]);
        let wire = tree.wire_bytes().unwrap();
        assert_eq!(ContentHash::of(&wire), tree.hash().unwrap());
        assert_ne!(tree.hash().unwrap(), tree.legacy_json_hash().unwrap());
    }

    #[test]
    fn tree_multiple_entries_and_hash_change() {
        let mut t1 = Tree::new();
        t1.add_file("a.txt", 10, vec![ContentHash::from([1u8; 32])]);
        t1.add_dir("subdir", ContentHash::from([2u8; 32]));
        let h1 = t1.hash().unwrap();

        let mut t2 = Tree::new();
        t2.add_file("a.txt", 10, vec![ContentHash::from([1u8; 32])]);
        t2.add_dir("subdir", ContentHash::from([99u8; 32]));
        let h2 = t2.hash().unwrap();
        assert_ne!(h1, h2);

        let mut t3 = Tree::new();
        t3.add_file("a.txt", 10, vec![ContentHash::from([1u8; 32])]);
        t3.add_dir("subdir", ContentHash::from([2u8; 32]));
        assert_eq!(t3.hash().unwrap(), h1);
    }

    #[test]
    fn merge_preserves_and_overwrites() {
        let mut base = Tree::new();
        base.add_file("a.txt", 1, vec![ContentHash::from([1u8; 32])]);
        base.add_file("b.txt", 2, vec![ContentHash::from([2u8; 32])]);

        let mut delta = Tree::new();
        delta.add_file("b.txt", 3, vec![ContentHash::from([3u8; 32])]);
        delta.add_file("c.txt", 4, vec![ContentHash::from([4u8; 32])]);

        base.merge(&delta);
        assert_eq!(base.entries.len(), 3);
        match base.entries.get("b.txt").unwrap() {
            TreeEntry::File { size, .. } => assert_eq!(*size, 3),
            _ => panic!("expected file"),
        }
        assert!(base.entries.contains_key("c.txt"));
    }

    #[test]
    fn normalize_path_slashes() {
        assert_eq!(normalize_path(r"a\b\c.txt"), "a/b/c.txt");
        assert_eq!(normalize_path("./foo/bar"), "foo/bar");
        assert_eq!(normalize_path("/x/"), "x");
    }

    #[test]
    fn validate_path_rejects_traversal() {
        assert!(validate_path("a/../b").is_err());
        assert!(validate_path("..").is_err());
        assert!(validate_path("a/./b").is_err());
        assert!(validate_path("/abs").is_err());
        assert!(validate_path("C:/windows").is_err());
        assert!(validate_path("a\\b").is_err());
        assert!(validate_path("").is_err());
        assert!(validate_path("a/\0/b").is_err());
        assert!(validate_path("ok/file.txt").is_ok());
        assert!(normalize_and_validate("./ok/file.txt").unwrap() == "ok/file.txt");
    }

    #[test]
    fn safe_join_blocks_parent_dir() {
        let dir = std::env::temp_dir();
        // Logical path with .. is rejected by validate
        assert!(safe_join(&dir, "a/../../etc/passwd").is_err());
        assert!(safe_join(&dir, "nested/file.txt").is_ok());
    }
}
