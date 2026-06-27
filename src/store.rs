//! Local content-addressed chunk store (file based)
use crate::{ContentHash, SoalError};
use hex;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// A local chunk store rooted at a directory (e.g. <vault>/chunks/)
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

    fn path_for(&self, hash: &ContentHash) -> PathBuf {
        self.root.join(format!("{}.chunk", hex::encode(hash)))
    }

    /// Store raw bytes under the content hash.
    /// The bytes may already be encrypted by caller.
    pub fn put(&self, hash: ContentHash, data: &[u8]) -> Result<(), SoalError> {
        let path = self.path_for(&hash);
        if path.exists() {
            return Ok(()); // dedup
        }
        let mut f = File::create(path)?;
        f.write_all(data)?;
        Ok(())
    }

    /// Retrieve stored bytes (encrypted or not).
    pub fn get(&self, hash: &ContentHash) -> Result<Vec<u8>, SoalError> {
        let path = self.path_for(hash);
        if !path.exists() {
            return Err(SoalError::ChunkNotFound(hex::encode(hash)));
        }
        let mut f = File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Check existence
    pub fn exists(&self, hash: &ContentHash) -> bool {
        self.path_for(hash).exists()
    }

    /// List all chunk hashes (for debug / gc later)
    pub fn list(&self) -> Result<Vec<ContentHash>, SoalError> {
        let mut hashes = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            if let Some(name_str) = name.to_str() {
                if name_str.ends_with(".chunk") {
                    let hexpart = &name_str[..name_str.len() - 6];
                    if let Ok(bytes) = hex::decode(hexpart) {
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            hashes.push(arr);
                        }
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
        let hash = blake3::hash(data).into();
        store.put(hash, data).unwrap();
        let got = store.get(&hash).unwrap();
        assert_eq!(got, data);
        assert!(store.exists(&hash));
    }
}
