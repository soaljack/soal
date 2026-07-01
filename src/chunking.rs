//! Content-Defined Chunking using FastCDC + BLAKE3 hashing
use crate::{ContentHash, SoalError};
use fastcdc::v2020::FastCDC;
use std::fs;
use std::path::Path;

/// Configuration for chunking
#[derive(Clone, Debug)]
pub struct ChunkConfig {
    pub avg_size: u32,
    pub min_size: u32,
    pub max_size: u32,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        // ~2 MiB average target as per spec (tunable)
        Self {
            avg_size: 2 * 1024 * 1024,
            min_size: 256 * 1024,
            max_size: 8 * 1024 * 1024,
        }
    }
}

impl ChunkConfig {
    pub fn new(avg_size: u32) -> Self {
        let min = (avg_size / 4).max(64 * 1024);
        let max = avg_size * 4;
        Self {
            avg_size,
            min_size: min,
            max_size: max,
        }
    }
}

/// A plaintext content chunk produced by CDC.
/// The `hash` here is the BLAKE3 of plaintext (used for internal purposes / tests).
/// The actual storage key in an encrypted vault is the BLAKE3 of the *ciphertext*
/// (see Vault::store_chunk and Security Model).
#[derive(Clone, Debug)]
pub struct Chunk {
    pub hash: ContentHash, // plaintext BLAKE3 (for reference/dedup logic inside chunker)
    pub data: Vec<u8>,     // plaintext
}

impl Chunk {
    pub fn from_data(data: Vec<u8>) -> Self {
        let hash = blake3::hash(&data).into();
        Self { hash, data }
    }
}

/// Split a file into CDC chunks using FastCDC (v2020).
/// Loads entire file (acceptable for Phase 0).
pub fn chunk_file<P: AsRef<Path>>(path: P, config: &ChunkConfig) -> Result<Vec<Chunk>, SoalError> {
    let data = fs::read(path)?;
    Ok(chunk_bytes(&data, config))
}

/// Chunk in-memory bytes using FastCDC v2020.
pub fn chunk_bytes(data: &[u8], config: &ChunkConfig) -> Vec<Chunk> {
    if data.is_empty() {
        return vec![];
    }

    let chunker = FastCDC::new(data, config.min_size, config.avg_size, config.max_size);

    let mut chunks = Vec::new();
    for entry in chunker {
        let start = entry.offset;
        let end = start + entry.length;
        if end <= data.len() {
            let chunk_data = data[start..end].to_vec();
            chunks.push(Chunk::from_data(chunk_data));
        }
    }

    if chunks.is_empty() {
        chunks.push(Chunk::from_data(data.to_vec()));
    }
    chunks
}

/// Compute BLAKE3 of entire data (for tree manifests etc.)
pub fn hash_bytes(data: &[u8]) -> ContentHash {
    blake3::hash(data).into()
}

/// Verify a chunk's hash matches its content
pub fn verify_chunk(chunk: &Chunk) -> bool {
    let computed: ContentHash = blake3::hash(&chunk.data).into();
    computed == chunk.hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn chunk_bytes_roundtrip(data: Vec<u8>) {
            let config = ChunkConfig::default();
            let chunks = chunk_bytes(&data, &config);
            let mut reconstructed = Vec::new();
            for c in &chunks {
                prop_assert!(verify_chunk(c));
                reconstructed.extend_from_slice(&c.data);
            }
            prop_assert_eq!(reconstructed, data);
        }

        #[test]
        fn hash_is_deterministic(data: Vec<u8>) {
            let h1 = hash_bytes(&data);
            let h2 = hash_bytes(&data);
            prop_assert_eq!(h1, h2);
        }
    }
}
