//! Local content-addressed chunk store (file based).
//!
//! Every `put` verifies that `BLAKE3(data) == hash` so the store never accepts
//! mislabeled blobs. If a blob already exists under `hash`, bytes must match
//! (INV-IMPORT-03); silent acceptance of CID collisions is rejected.
//! `get` re-verifies on read (detects bit-rot / tampering).

use crate::{ContentHash, SoalError};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// A local chunk store rooted at a directory (e.g. `<vault>/chunks/`).
#[derive(Debug, Clone)]
pub struct ChunkStore {
    root: PathBuf,
}

impl ChunkStore {
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self, SoalError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for(&self, hash: &ContentHash) -> PathBuf {
        self.root.join(format!("{}.chunk", hash.to_hex()))
    }

    /// Store raw bytes under the content hash.
    /// The bytes may already be encrypted by the caller.
    ///
    /// Returns `Ok(true)` if newly written, `Ok(false)` if already present with
    /// identical bytes (dedup). Returns `Err` if the path exists but content
    /// differs (INV-IMPORT-03) or if `BLAKE3(data) != hash`.
    pub fn put(&self, hash: ContentHash, data: &[u8]) -> Result<bool, SoalError> {
        self.put_verified(hash, data)
    }

    /// Alias emphasizing verified import semantics (INV-IMPORT-01..03).
    pub fn put_verified(&self, hash: ContentHash, data: &[u8]) -> Result<bool, SoalError> {
        let actual = ContentHash::of(data);
        if actual != hash {
            return Err(SoalError::hash_mismatch(&hash, &actual));
        }

        let path = self.path_for(&hash);
        if path.exists() {
            let mut existing = Vec::new();
            File::open(&path)?.read_to_end(&mut existing)?;
            if existing.as_slice() != data {
                return Err(SoalError::CidCollision {
                    hash: hash.to_hex(),
                });
            }
            return Ok(false); // dedup: identical bytes
        }

        // Write to a temp file then rename for atomicity on the same filesystem.
        let tmp = path.with_extension("chunk.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(true)
    }

    /// Retrieve stored bytes (encrypted or not), verifying content hash.
    pub fn get(&self, hash: &ContentHash) -> Result<Vec<u8>, SoalError> {
        let path = self.path_for(hash);
        if !path.exists() {
            return Err(SoalError::ChunkNotFound(hash.to_hex()));
        }
        let mut f = File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        let actual = ContentHash::of(&buf);
        if actual != *hash {
            return Err(SoalError::hash_mismatch(hash, &actual));
        }
        Ok(buf)
    }

    /// Check existence (does not verify content).
    pub fn exists(&self, hash: &ContentHash) -> bool {
        self.path_for(hash).exists()
    }

    /// List all chunk hashes (for debug / GC later).
    pub fn list(&self) -> Result<Vec<ContentHash>, SoalError> {
        let mut hashes = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            if let Some(name_str) = name.to_str() {
                if let Some(hexpart) = name_str.strip_suffix(".chunk") {
                    if let Ok(h) = ContentHash::from_hex(hexpart) {
                        hashes.push(h);
                    }
                }
            }
        }
        Ok(hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn store_roundtrip() {
        let dir = tempdir().unwrap();
        let store = ChunkStore::new(dir.path()).unwrap();
        let data = b"test chunk data for soal";
        let hash = ContentHash::of(data);
        assert!(store.put(hash, data).unwrap());
        assert!(!store.put(hash, data).unwrap()); // dedup
        let got = store.get(&hash).unwrap();
        assert_eq!(got, data);
        assert!(store.exists(&hash));
    }

    #[test]
    fn put_rejects_hash_mismatch() {
        let dir = tempdir().unwrap();
        let store = ChunkStore::new(dir.path()).unwrap();
        let data = b"payload";
        let wrong = ContentHash::of(b"other");
        assert!(matches!(
            store.put(wrong, data),
            Err(SoalError::HashMismatch { .. })
        ));
    }

    #[test]
    fn put_rejects_cid_collision_different_bytes() {
        let dir = tempdir().unwrap();
        let store = ChunkStore::new(dir.path()).unwrap();
        let data = b"payload-a";
        let hash = ContentHash::of(data);
        assert!(store.put(hash, data).unwrap());

        // Simulate collision by writing different bytes under same path name
        // (bypass put) then put_verified must hard-error if we force a call
        // with matching hash but we can't create real BLAKE3 collision easily.
        // Instead: write foreign bytes to the path, then put same hash+original
        // data must detect mismatch via read-compare when "exists".
        let path = store.path_for(&hash);
        fs::write(&path, b"tampered-different-content!!!!").unwrap();
        // put with original data: hash matches data, path exists, bytes differ
        let err = store.put_verified(hash, data).unwrap_err();
        assert!(
            matches!(err, SoalError::CidCollision { .. }),
            "expected CidCollision, got {err:?}"
        );
    }

    #[test]
    fn put_verified_idempotent_same_bytes() {
        let dir = tempdir().unwrap();
        let store = ChunkStore::new(dir.path()).unwrap();
        let data = b"idempotent";
        let hash = ContentHash::of(data);
        assert!(store.put_verified(hash, data).unwrap());
        assert!(!store.put_verified(hash, data).unwrap());
    }
}
