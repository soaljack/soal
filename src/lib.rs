//! Soal core library (Phase 0 - local foundation)
pub mod chunking;
pub mod commit;
pub mod crypto;
pub mod store;
pub mod tree;
pub mod vault;

pub use anyhow::Result;
pub use blake3::Hash as Blake3Hash;

/// 32-byte content hash (BLAKE3)
pub type ContentHash = [u8; 32];

/// Simple error type for Phase 0
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
    #[error("Vault not found: {0}")]
    VaultNotFound(String),
    #[error("Chunk not found: {0}")]
    ChunkNotFound(String),
    #[error("{0}")]
    Other(String),
}
