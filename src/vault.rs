//! Vault management for Phase 0 (local only)
use crate::chunking::{chunk_bytes, Chunk, ChunkConfig};
use crate::commit::{Commit, create_initial_commit};
use crate::crypto::{decrypt_chunk, encrypt_chunk, generate_key, Key};
use crate::store::ChunkStore;
use crate::tree::{Tree, TreeEntry};
use crate::{ContentHash, SoalError};
use hex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const CHUNKS_DIR: &str = "chunks";
const COMMITS_DIR: &str = "commits";
const TREES_DIR: &str = "trees";
const CONFIG_FILE: &str = "vault.json";
const HEAD_FILE: &str = "HEAD";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultConfig {
    pub name: String,
    pub encryption_enabled: bool,
    /// Hex encoded 32-byte key (only present if encryption_enabled)
    pub key_hex: Option<String>,
    pub created_at: u64,
}

#[derive(Debug)]
pub struct Vault {
    pub name: String,
    pub root: PathBuf,
    pub config: VaultConfig,
    chunk_store: ChunkStore,
    key: Option<Key>,
}

impl Vault {
    /// Create a new vault on disk
    pub fn create<P: AsRef<Path>>(
        base_dir: P,
        name: &str,
        encryption_enabled: bool,
    ) -> Result<Self, SoalError> {
        let root = base_dir.as_ref().join(name);
        if root.exists() {
            return Err(SoalError::Other(format!("Vault '{}' already exists", name)));
        }
        fs::create_dir_all(&root)?;

        let key = if encryption_enabled {
            let k = generate_key();
            Some(k)
        } else {
            None
        };

        let key_hex = key.map(|k| hex::encode(k));

        let config = VaultConfig {
            name: name.to_string(),
            encryption_enabled,
            key_hex,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let config_path = root.join(CONFIG_FILE);
        fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;

        // Create subdirs
        fs::create_dir_all(root.join(CHUNKS_DIR))?;
        fs::create_dir_all(root.join(COMMITS_DIR))?;
        fs::create_dir_all(root.join(TREES_DIR))?;

        let store = ChunkStore::new(root.join(CHUNKS_DIR))?;

        Ok(Self {
            name: name.to_string(),
            root,
            config: config.clone(),
            chunk_store: store,
            key,
        })
    }

    /// Open an existing vault
    pub fn open<P: AsRef<Path>>(base_dir: P, name: &str) -> Result<Self, SoalError> {
        let root = base_dir.as_ref().join(name);
        if !root.exists() {
            return Err(SoalError::VaultNotFound(name.to_string()));
        }

        let config_str = fs::read_to_string(root.join(CONFIG_FILE))?;
        let config: VaultConfig = serde_json::from_str(&config_str)?;

        let key = if config.encryption_enabled {
            if let Some(hexkey) = &config.key_hex {
                let bytes = hex::decode(hexkey).map_err(|_| SoalError::InvalidHash)?;
                if bytes.len() != 32 {
                    return Err(SoalError::Other("invalid key length".into()));
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                Some(k)
            } else {
                return Err(SoalError::Other("encryption enabled but no key".into()));
            }
        } else {
            None
        };

        let store = ChunkStore::new(root.join(CHUNKS_DIR))?;

        Ok(Self {
            name: config.name.clone(),
            root,
            config,
            chunk_store: store,
            key,
        })
    }

    /// List all vaults in a base directory
    pub fn list(base_dir: &Path) -> Result<Vec<String>, SoalError> {
        let mut vaults = Vec::new();
        if !base_dir.exists() {
            return Ok(vaults);
        }
        for entry in fs::read_dir(base_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && path.join(CONFIG_FILE).exists() {
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    vaults.push(name.to_string());
                }
            }
        }
        Ok(vaults)
    }

    fn store_chunk(&self, chunk: &Chunk) -> Result<(), SoalError> {
        let data_to_store = if let Some(k) = &self.key {
            encrypt_chunk(&chunk.data, k)?
        } else {
            chunk.data.clone()
        };
        self.chunk_store.put(chunk.hash, &data_to_store)
    }

    fn load_chunk(&self, hash: &ContentHash) -> Result<Vec<u8>, SoalError> {
        let stored = self.chunk_store.get(hash)?;
        if let Some(k) = &self.key {
            decrypt_chunk(&stored, k)
        } else {
            Ok(stored)
        }
    }

    /// Store chunks and return their hashes
    fn store_chunks(&self, chunks: &[Chunk]) -> Result<Vec<ContentHash>, SoalError> {
        let mut hashes = Vec::new();
        for c in chunks {
            self.store_chunk(c)?;
            hashes.push(c.hash);
        }
        Ok(hashes)
    }

    /// Create a simple tree from a list of files (flat for MVP)
    fn build_simple_tree(&self, files: &[(String, u64, Vec<ContentHash>)]) -> Tree {
        let mut tree = Tree::new();
        for (path, size, chunks) in files {
            tree.add_file(path, *size, chunks.clone());
        }
        tree
    }

    /// Save a tree manifest
    fn save_tree(&self, tree: &Tree) -> Result<ContentHash, SoalError> {
        let hash = tree.hash();
        let json = tree.to_json()?;
        let path = self.root.join(TREES_DIR).join(format!("{}.json", hex::encode(hash)));
        fs::write(path, json)?;
        Ok(hash)
    }

    /// Save a commit
    fn save_commit(&self, commit: &Commit) -> Result<ContentHash, SoalError> {
        let hash = commit.hash();
        let json = commit.to_json()?;
        let path = self.root.join(COMMITS_DIR).join(format!("{}.json", hex::encode(hash)));
        fs::write(path, json)?;
        Ok(hash)
    }

    /// Set current HEAD commit
    fn set_head(&self, commit_hash: ContentHash) -> Result<(), SoalError> {
        let path = self.root.join(HEAD_FILE);
        fs::write(path, hex::encode(commit_hash))?;
        Ok(())
    }

    /// Get current HEAD commit hash
    pub fn head(&self) -> Result<Option<ContentHash>, SoalError> {
        let path = self.root.join(HEAD_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let hexstr = fs::read_to_string(path)?;
        let bytes = hex::decode(hexstr.trim()).map_err(|_| SoalError::InvalidHash)?;
        if bytes.len() != 32 {
            return Ok(None);
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes);
        Ok(Some(h))
    }

    /// Add a file or directory recursively (Phase 0)
    pub fn add_path<P: AsRef<Path>>(
        &mut self,
        path: P,
        base_name: &str,
    ) -> Result<ContentHash, SoalError> {
        let path = path.as_ref();
        let mut file_entries: Vec<(String, u64, Vec<ContentHash>)> = Vec::new();

        if path.is_file() {
            let data = fs::read(path)?;
            let config = ChunkConfig::default();
            let chunks = chunk_bytes(&data, &config);
            let hashes = self.store_chunks(&chunks)?;
            file_entries.push((base_name.to_string(), data.len() as u64, hashes));
        } else if path.is_dir() {
            for entry in Self::walkdir_simple(path)? {
                let rel = entry.strip_prefix(path).unwrap_or(&entry);
                let rel_str = rel.to_string_lossy().to_string();
                if rel_str.is_empty() {
                    continue;
                }
                if entry.is_file() {
                    let data = fs::read(&entry)?;
                    let config = ChunkConfig::default();
                    let chunks = chunk_bytes(&data, &config);
                    let hashes = self.store_chunks(&chunks)?;
                    let logical = format!("{}/{}", base_name, rel_str);
                    file_entries.push((logical, data.len() as u64, hashes));
                }
            }
        } else {
            return Err(SoalError::Other("path is neither file nor dir".into()));
        }

        if file_entries.is_empty() {
            return Err(SoalError::Other("nothing to add".into()));
        }

        let tree = self.build_simple_tree(&file_entries);
        let tree_hash = self.save_tree(&tree)?;

        let msg = if path.is_dir() { format!("Add dir {}", base_name) } else { format!("Add {}", base_name) };
        let commit = create_initial_commit(tree_hash, &msg);
        let commit_hash = self.save_commit(&commit)?;
        self.set_head(commit_hash)?;

        Ok(commit_hash)
    }

    /// Backward compat
    pub fn add_file<P: AsRef<Path>>(
        &mut self,
        file_path: P,
        logical_name: &str,
    ) -> Result<ContentHash, SoalError> {
        self.add_path(file_path, logical_name)
    }


/// Simple recursive directory walker (no extra deps)
fn walkdir_simple<P: AsRef<Path>>(dir: P) -> Result<Vec<PathBuf>, SoalError> {
    let mut files = Vec::new();
    fn visit(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), SoalError> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                visit(&p, out)?;
            } else if p.is_file() {
                out.push(p);
            }
        }
        Ok(())
    }
    visit(dir.as_ref(), &mut files)?;
    Ok(files)
}

    /// Create a snapshot commit (manual)
    pub fn snapshot(&mut self, message: &str) -> Result<ContentHash, SoalError> {
        // For Phase 0, if we have HEAD, create a child commit with same tree
        if let Some(current_head) = self.head()? {
            // Load the previous commit to reuse its tree
            let head_commit = self.load_commit(current_head)?;
            let tree_hash = head_commit.tree;

            let new_commit = Commit::new(
                tree_hash,
                vec![current_head],
                "soal-local",
                message,
            );
            let commit_hash = self.save_commit(&new_commit)?;
            self.set_head(commit_hash)?;
            return Ok(commit_hash);
        }

        // No previous state, create empty snapshot
        let empty_tree = Tree::new();
        let tree_hash = self.save_tree(&empty_tree)?;
        let commit = create_initial_commit(tree_hash, message);
        let commit_hash = self.save_commit(&commit)?;
        self.set_head(commit_hash)?;
        Ok(commit_hash)
    }

    fn load_commit(&self, hash: ContentHash) -> Result<Commit, SoalError> {
        let path = self.root.join(COMMITS_DIR).join(format!("{}.json", hex::encode(hash)));
        if !path.exists() {
            return Err(SoalError::Other("commit not found".into()));
        }
        let s = fs::read_to_string(path)?;
        Commit::from_json(&s)
    }

    /// Restore a commit's files into a target directory (very basic Phase 0 impl)
    pub fn restore<P: AsRef<Path>>(
        &self,
        commit_hash: ContentHash,
        target_dir: P,
    ) -> Result<(), SoalError> {
        let commit = self.load_commit(commit_hash)?;
        let tree_path = self.root.join(TREES_DIR).join(format!("{}.json", hex::encode(commit.tree)));
        if !tree_path.exists() {
            return Err(SoalError::Other("tree not found for commit".into()));
        }
        let tree_json = fs::read_to_string(tree_path)?;
        let tree: Tree = Tree::from_json(&tree_json)?;

        fs::create_dir_all(&target_dir)?;

        for (name, entry) in &tree.entries {
            if let TreeEntry::File { size: _, chunks } = entry {
                let mut file_data = Vec::new();
                for h in chunks {
                    let chunk_plain = self.load_chunk(h)?;
                    // verify
                    let computed: ContentHash = blake3::hash(&chunk_plain).into();
                    if computed != *h {
                        return Err(SoalError::Other("chunk hash mismatch on restore".into()));
                    }
                    file_data.extend_from_slice(&chunk_plain);
                }
                let out_path = target_dir.as_ref().join(name);
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(out_path, &file_data)?;
            }
        }
        Ok(())
    }

    /// Basic status
    pub fn status(&self) -> Result<String, SoalError> {
        let head = self.head()?;
        let chunk_count = self.chunk_store.list()?.len();
        let msg = match head {
            Some(h) => format!(
                "Vault '{}' (encrypt={})\nHEAD: {}\nChunks: {}",
                self.name,
                self.config.encryption_enabled,
                hex::encode(h),
                chunk_count
            ),
            None => format!(
                "Vault '{}' (encrypt={}) - no commits yet",
                self.name, self.config.encryption_enabled
            ),
        };
        Ok(msg)
    }
}

/// Get the default base directory for Soal data
pub fn default_soal_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".soal")
        .join("vaults")
}
