//! Vault management: encrypted content-addressed store + Merkle history.
//!
//! Design notes:
//! - Adds **merge** into the existing HEAD tree (incremental history).
//! - Commits always parent to current HEAD when present (real DAG).
//! - Vault key lives in a separate `vault.key` file (not in vault.json).
//! - Imports verify content hashes before accepting remote data.

use crate::chunking::{chunk_bytes, Chunk, ChunkConfig};
use crate::codec::{self, VAULT_ID_LEN};
use crate::commit::Commit;
use crate::crypto::{
    decrypt_chunk, encrypt_deterministic, generate_key, key_from_hex, unwrap_vault_key_passphrase,
    wrap_vault_key_passphrase, Key, WrappedKey,
};
use crate::identity;
use crate::store::ChunkStore;
use crate::tree::{normalize_and_validate, safe_join, Tree, TreeEntry};
use crate::{ContentHash, SoalError};
use iroh::SecretKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const CHUNKS_DIR: &str = "chunks";
const COMMITS_DIR: &str = "commits";
const TREES_DIR: &str = "trees";
const CONFIG_FILE: &str = "vault.json";
const KEY_FILE: &str = "vault.key";
const WRAPPED_KEY_FILE: &str = "vault.wrapped.json";
const HEAD_FILE: &str = "HEAD";
const HEADS_FILE: &str = "HEADS";
const DEFAULT_MIN_REPLICAS: u8 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultConfig {
    pub name: String,
    pub encryption_enabled: bool,
    /// Minimum replica count for Phase 1+ replication policy.
    #[serde(default = "default_min_replicas")]
    pub min_replicas: u8,
    pub created_at: u64,
    /// Stable 16-byte vault identity as 32 hex chars (KD-08 topic key).
    #[serde(default)]
    pub vault_id: String,
    /// Membership / config generation (starts at 1).
    #[serde(default = "default_config_seq")]
    pub config_seq: u64,
    /// Known member NodeIDs (hex). Empty = open/local-only cluster trust.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    /// Owner / config signer NodeID (string form).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// ed25519 signature over config sign preimage (hex). PR-05.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_sig: Option<String>,
    /// True when vault key is passphrase-wrapped (vault.wrapped.json present).
    #[serde(default)]
    pub key_wrapped: bool,
    /// Legacy field: older vaults stored the key in config. Migrated on open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_hex: Option<String>,
}

fn default_min_replicas() -> u8 {
    DEFAULT_MIN_REPLICAS
}

fn default_config_seq() -> u64 {
    1
}

/// Generate a fresh 16-byte vault_id (32 hex chars).
pub fn generate_vault_id() -> String {
    let mut bytes = [0u8; VAULT_ID_LEN];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[derive(Debug)]
pub struct Vault {
    pub name: String,
    pub root: PathBuf,
    pub config: VaultConfig,
    chunk_store: ChunkStore,
    key: Option<Key>,
    /// Optional Soal home for node identity (signing commits). When set and
    /// `node.json` exists, new commits are signed with the local NodeID.
    soal_home: Option<PathBuf>,
}

impl Vault {
    /// Create a new vault on disk.
    pub fn create<P: AsRef<Path>>(
        base_dir: P,
        name: &str,
        encryption_enabled: bool,
    ) -> Result<Self, SoalError> {
        Self::create_with_policy(base_dir, name, encryption_enabled, DEFAULT_MIN_REPLICAS)
    }

    pub fn create_with_policy<P: AsRef<Path>>(
        base_dir: P,
        name: &str,
        encryption_enabled: bool,
        min_replicas: u8,
    ) -> Result<Self, SoalError> {
        let root = base_dir.as_ref().join(name);
        if root.exists() {
            return Err(SoalError::Other(format!("Vault '{name}' already exists")));
        }
        fs::create_dir_all(&root)?;

        let key = if encryption_enabled {
            Some(generate_key())
        } else {
            None
        };

        let mut members = Vec::new();
        let home = default_soal_home();
        if let Ok(author) = identity::local_author_sync(&home) {
            members.push(author);
        }

        let owner = members.first().cloned();
        let mut config = VaultConfig {
            name: name.to_string(),
            encryption_enabled,
            min_replicas: min_replicas.max(1),
            created_at: now_secs(),
            vault_id: generate_vault_id(),
            config_seq: 1,
            members,
            owner,
            config_sig: None,
            key_wrapped: false,
            key_hex: None,
        };

        // Best-effort sign config if we have node identity.
        if let Ok(sk) = identity::load_secret_key(&home) {
            let _ = sign_vault_config(&sk, &mut config);
        }

        write_config(&root, &config)?;
        if let Some(k) = &key {
            write_key_file(&root, k)?;
        }

        fs::create_dir_all(root.join(CHUNKS_DIR))?;
        fs::create_dir_all(root.join(COMMITS_DIR))?;
        fs::create_dir_all(root.join(TREES_DIR))?;

        let store = ChunkStore::new(root.join(CHUNKS_DIR))?;

        Ok(Self {
            name: name.to_string(),
            root,
            config,
            chunk_store: store,
            key,
            soal_home: Some(home),
        })
    }

    /// Create a vault with fixed key + vault_id (multi-node test fixture / SC-KEY-SHARE).
    ///
    /// Not a production CLI path — used so two nodes share encryption material
    /// without the invite flow (PR-12).
    pub fn create_for_test<P: AsRef<Path>>(
        base_dir: P,
        name: &str,
        encryption_enabled: bool,
        vault_id: [u8; VAULT_ID_LEN],
        key: Option<Key>,
        members: Vec<String>,
    ) -> Result<Self, SoalError> {
        let root = base_dir.as_ref().join(name);
        if root.exists() {
            return Err(SoalError::Other(format!("Vault '{name}' already exists")));
        }
        fs::create_dir_all(&root)?;
        let key = if encryption_enabled {
            Some(key.unwrap_or_else(generate_key))
        } else {
            None
        };
        let owner = members.first().cloned();
        let config = VaultConfig {
            name: name.to_string(),
            encryption_enabled,
            min_replicas: DEFAULT_MIN_REPLICAS,
            created_at: now_secs(),
            vault_id: hex::encode(vault_id),
            config_seq: 1,
            members,
            owner,
            config_sig: None,
            key_wrapped: false,
            key_hex: None,
        };
        write_config(&root, &config)?;
        if let Some(k) = &key {
            write_key_file(&root, k)?;
        }
        fs::create_dir_all(root.join(CHUNKS_DIR))?;
        fs::create_dir_all(root.join(COMMITS_DIR))?;
        fs::create_dir_all(root.join(TREES_DIR))?;
        let store = ChunkStore::new(root.join(CHUNKS_DIR))?;
        Ok(Self {
            name: name.to_string(),
            root,
            config,
            chunk_store: store,
            key,
            soal_home: None,
        })
    }

    /// Parse vault_id bytes from config (generates and persists if missing — legacy open).
    pub fn vault_id_bytes(&self) -> Result<[u8; VAULT_ID_LEN], SoalError> {
        if self.config.vault_id.is_empty() {
            return Err(SoalError::Other(
                "vault_id missing (recreate vault or run migration)".into(),
            ));
        }
        codec::vault_id_from_hex(&self.config.vault_id)
    }

    /// Open an existing vault (migrates legacy key-in-config if needed).
    pub fn open<P: AsRef<Path>>(base_dir: P, name: &str) -> Result<Self, SoalError> {
        Self::open_with_passphrase(base_dir, name, None)
    }

    /// Open vault; if the key is passphrase-wrapped, `passphrase` is required.
    pub fn open_with_passphrase<P: AsRef<Path>>(
        base_dir: P,
        name: &str,
        passphrase: Option<&str>,
    ) -> Result<Self, SoalError> {
        let root = base_dir.as_ref().join(name);
        if !root.exists() {
            return Err(SoalError::VaultNotFound(name.to_string()));
        }

        let config_str = fs::read_to_string(root.join(CONFIG_FILE))?;
        let mut config: VaultConfig = serde_json::from_str(&config_str)?;

        // Migrate legacy vaults missing vault_id.
        let mut rewritten = false;
        if config.vault_id.is_empty() {
            config.vault_id = generate_vault_id();
            rewritten = true;
        }
        if config.config_seq == 0 {
            config.config_seq = 1;
            rewritten = true;
        }

        let key = if config.encryption_enabled {
            Some(load_or_migrate_key(&root, &mut config, passphrase)?)
        } else {
            None
        };

        if rewritten {
            write_config(&root, &config)?;
        }

        let store = ChunkStore::new(root.join(CHUNKS_DIR))?;

        Ok(Self {
            name: config.name.clone(),
            root,
            config,
            chunk_store: store,
            key,
            soal_home: Some(default_soal_home()),
        })
    }

    /// Bind a Soal home directory used for commit signing (tests / custom homes).
    pub fn with_soal_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.soal_home = Some(home.into());
        self
    }

    /// Access the loaded vault encryption key (if any).
    pub fn vault_key(&self) -> Option<&Key> {
        self.key.as_ref()
    }

    /// Persist current config to disk.
    pub fn persist_config(&self) -> Result<(), SoalError> {
        write_config(&self.root, &self.config)
    }

    /// Protect the vault key with a passphrase (PR-05). Removes plaintext vault.key.
    pub fn enable_passphrase(&mut self, passphrase: &str) -> Result<(), SoalError> {
        if !self.config.encryption_enabled {
            return Err(SoalError::Other(
                "cannot wrap key: encryption disabled".into(),
            ));
        }
        let key = *self
            .key
            .as_ref()
            .ok_or_else(|| SoalError::Other("vault key not loaded".into()))?;
        let vault_id = self.vault_id_bytes()?;
        let wrapped = wrap_vault_key_passphrase(&key, passphrase, &vault_id)?;
        write_wrapped_key(&self.root, &wrapped)?;
        // Remove plaintext key file if present.
        let key_path = self.root.join(KEY_FILE);
        if key_path.exists() {
            fs::remove_file(&key_path)?;
        }
        self.config.key_wrapped = true;
        self.config.key_hex = None;
        self.bump_and_sign_config()?;
        Ok(())
    }

    /// Change / set policy fields and re-sign config.
    pub fn set_min_replicas(&mut self, n: u8) -> Result<(), SoalError> {
        self.config.min_replicas = n.max(1);
        self.bump_and_sign_config()
    }

    /// Add a member NodeID and re-sign.
    pub fn add_member(&mut self, node_id: &str) -> Result<(), SoalError> {
        let n = node_id.trim().to_string();
        if n.is_empty() {
            return Err(SoalError::Other("empty member id".into()));
        }
        if !self
            .config
            .members
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&n))
        {
            self.config.members.push(n);
            self.bump_and_sign_config()?;
        }
        Ok(())
    }

    /// Remove a member NodeID and re-sign.
    pub fn remove_member(&mut self, node_id: &str) -> Result<bool, SoalError> {
        let before = self.config.members.len();
        self.config
            .members
            .retain(|m| !m.eq_ignore_ascii_case(node_id));
        if self.config.members.len() != before {
            self.bump_and_sign_config()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn bump_and_sign_config(&mut self) -> Result<(), SoalError> {
        self.config.config_seq = self.config.config_seq.saturating_add(1);
        if let Some(home) = &self.soal_home {
            if let Ok(sk) = identity::load_secret_key(home) {
                sign_vault_config(&sk, &mut self.config)?;
            }
        }
        write_config(&self.root, &self.config)
    }

    /// Verify config_sig if present.
    pub fn verify_config_signature(&self) -> Result<(), SoalError> {
        verify_vault_config(&self.config)
    }

    /// List all vaults in a base directory.
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
        vaults.sort();
        Ok(vaults)
    }

    fn store_chunk(&self, chunk: &Chunk) -> Result<ContentHash, SoalError> {
        let plain = &chunk.data;
        let data_to_store = if let Some(k) = &self.key {
            encrypt_deterministic(plain, k)?
        } else {
            plain.clone()
        };
        // Storage key is always BLAKE3 of what we actually store (ciphertext when encrypted).
        let store_hash = ContentHash::of(&data_to_store);
        self.chunk_store.put(store_hash, &data_to_store)?;
        Ok(store_hash)
    }

    fn load_chunk(&self, hash: &ContentHash) -> Result<Vec<u8>, SoalError> {
        let stored = self.chunk_store.get(hash)?;
        if let Some(k) = &self.key {
            decrypt_chunk(&stored, k)
        } else {
            Ok(stored)
        }
    }

    /// Store chunks (plaintext) and return storage hashes (ciphertext hash when encrypted).
    fn store_chunks(&self, chunks: &[Chunk]) -> Result<Vec<ContentHash>, SoalError> {
        let mut store_hashes = Vec::with_capacity(chunks.len());
        for c in chunks {
            store_hashes.push(self.store_chunk(c)?);
        }
        Ok(store_hashes)
    }

    fn save_tree(&self, tree: &Tree) -> Result<ContentHash, SoalError> {
        // Format ≥1 wire: DOMAIN_TREE || CBOR; CID = BLAKE3(wire).
        let hash = tree.hash()?;
        let bytes = tree.wire_bytes()?;
        debug_assert_eq!(ContentHash::of(&bytes), hash);
        let path = self
            .root
            .join(TREES_DIR)
            .join(format!("{}.bin", hash.to_hex()));
        fs::write(path, bytes)?;
        Ok(hash)
    }

    fn save_commit(&self, commit: &Commit) -> Result<ContentHash, SoalError> {
        let hash = commit.hash()?;
        let bytes = commit.wire_bytes()?;
        debug_assert_eq!(ContentHash::of(&bytes), hash);
        let path = self
            .root
            .join(COMMITS_DIR)
            .join(format!("{}.bin", hash.to_hex()));
        fs::write(path, bytes)?;
        Ok(hash)
    }

    /// Build a commit, optionally signed with the local node key.
    fn make_commit(
        &self,
        tree: ContentHash,
        parents: Vec<ContentHash>,
        message: &str,
    ) -> Result<Commit, SoalError> {
        let author = self
            .soal_home
            .as_ref()
            .and_then(|h| identity::local_author_sync(h).ok())
            .unwrap_or_else(|| "soal-local".to_string());
        let mut commit = Commit::new(tree, parents, author, message);
        if let Some(home) = &self.soal_home {
            if let Ok(sk) = identity::load_secret_key(home) {
                identity::sign_commit(&sk, &mut commit)?;
            }
        }
        Ok(commit)
    }

    fn tree_path_bin(&self, hash: &ContentHash) -> PathBuf {
        self.root
            .join(TREES_DIR)
            .join(format!("{}.bin", hash.to_hex()))
    }

    fn tree_path_json(&self, hash: &ContentHash) -> PathBuf {
        self.root
            .join(TREES_DIR)
            .join(format!("{}.json", hash.to_hex()))
    }

    fn commit_path_bin(&self, hash: &ContentHash) -> PathBuf {
        self.root
            .join(COMMITS_DIR)
            .join(format!("{}.bin", hash.to_hex()))
    }

    fn commit_path_json(&self, hash: &ContentHash) -> PathBuf {
        self.root
            .join(COMMITS_DIR)
            .join(format!("{}.json", hash.to_hex()))
    }

    pub fn has_commit_object(&self, hash: &ContentHash) -> bool {
        self.commit_path_bin(hash).exists() || self.commit_path_json(hash).exists()
    }

    pub fn has_tree_object(&self, hash: &ContentHash) -> bool {
        self.tree_path_bin(hash).exists() || self.tree_path_json(hash).exists()
    }

    fn set_head(&self, commit_hash: ContentHash) -> Result<(), SoalError> {
        fs::write(self.root.join(HEAD_FILE), commit_hash.to_hex())?;
        Ok(())
    }

    /// Read alternate tips from HEADS file only (does not inject current HEAD).
    fn list_heads_file_only(&self) -> Result<BTreeSet<ContentHash>, SoalError> {
        let mut heads = BTreeSet::new();
        let path = self.root.join(HEADS_FILE);
        if path.exists() {
            for line in fs::read_to_string(path)?.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(h) = ContentHash::from_hex(line) {
                    heads.insert(h);
                }
            }
        }
        Ok(heads)
    }

    /// Get current HEAD commit hash.
    pub fn head(&self) -> Result<Option<ContentHash>, SoalError> {
        let path = self.root.join(HEAD_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let hexstr = fs::read_to_string(path)?;
        let h = ContentHash::from_hex(hexstr.trim())?;
        Ok(Some(h))
    }

    pub fn load_commit(&self, hash: ContentHash) -> Result<Commit, SoalError> {
        // Prefer wire .bin; dual-read legacy .json (legacy_json_hash).
        let bin = self.commit_path_bin(&hash);
        if bin.exists() {
            let data = fs::read(&bin)?;
            if ContentHash::of(&data) != hash {
                return Err(SoalError::hash_mismatch(&hash, &ContentHash::of(&data)));
            }
            let commit = Commit::from_wire_or_json(&data)?;
            let actual = commit.hash()?;
            if actual != hash {
                return Err(SoalError::hash_mismatch(&hash, &actual));
            }
            return Ok(commit);
        }
        let json_path = self.commit_path_json(&hash);
        if json_path.exists() {
            let data = fs::read(&json_path)?;
            let commit = Commit::from_bytes(&data)?;
            let actual = commit.legacy_json_hash()?;
            if actual != hash {
                // Also accept if file bytes themselves hash (pretty vs compact edge)
                if ContentHash::of(&data) != hash {
                    return Err(SoalError::hash_mismatch(&hash, &actual));
                }
            }
            return Ok(commit);
        }
        Err(SoalError::CommitNotFound(hash.to_hex()))
    }

    pub fn load_tree(&self, hash: ContentHash) -> Result<Tree, SoalError> {
        let bin = self.tree_path_bin(&hash);
        if bin.exists() {
            let data = fs::read(&bin)?;
            if ContentHash::of(&data) != hash {
                return Err(SoalError::hash_mismatch(&hash, &ContentHash::of(&data)));
            }
            let tree = Tree::from_wire_or_json(&data)?;
            let actual = tree.hash()?;
            if actual != hash {
                return Err(SoalError::hash_mismatch(&hash, &actual));
            }
            return Ok(tree);
        }
        let json_path = self.tree_path_json(&hash);
        if json_path.exists() {
            let data = fs::read(&json_path)?;
            let tree = Tree::from_bytes(&data)?;
            let actual = tree.legacy_json_hash()?;
            if actual != hash && ContentHash::of(&data) != hash {
                return Err(SoalError::hash_mismatch(&hash, &actual));
            }
            return Ok(tree);
        }
        Err(SoalError::TreeNotFound(hash.to_hex()))
    }

    /// Load the tree at HEAD, or empty tree if no commits yet.
    pub fn head_tree(&self) -> Result<Tree, SoalError> {
        match self.head()? {
            Some(h) => {
                let commit = self.load_commit(h)?;
                self.load_tree(commit.tree)
            }
            None => Ok(Tree::new()),
        }
    }

    /// Add a file or directory, merging into the current HEAD tree.
    ///
    /// Creates a new commit parented to HEAD (if any). Previous files remain
    /// unless overwritten by the same logical path.
    pub fn add_path<P: AsRef<Path>>(
        &mut self,
        path: P,
        base_name: &str,
    ) -> Result<ContentHash, SoalError> {
        let path = path.as_ref();
        // base_name is a logical vault path segment/prefix — validate strictly.
        let base_name = if base_name.is_empty() {
            String::new()
        } else {
            normalize_and_validate(base_name)?
        };
        let config = ChunkConfig::default();
        let mut file_entries: Vec<(String, u64, Vec<ContentHash>)> = Vec::new();

        if path.is_file() {
            if base_name.is_empty() {
                return Err(SoalError::InvalidPath("logical file name required".into()));
            }
            let data = fs::read(path)?;
            let chunks = chunk_bytes(&data, &config);
            let hashes = self.store_chunks(&chunks)?;
            file_entries.push((base_name.clone(), data.len() as u64, hashes));
        } else if path.is_dir() {
            for entry in Self::walkdir_simple(path)? {
                if !entry.is_file() {
                    continue;
                }
                let rel = entry.strip_prefix(path).unwrap_or(&entry);
                // Convert OS path to vault path using `/` only, then validate.
                let rel_str = rel
                    .components()
                    .filter_map(|c| c.as_os_str().to_str())
                    .collect::<Vec<_>>()
                    .join("/");
                let rel_str = normalize_and_validate(&rel_str)?;
                if rel_str.is_empty() {
                    continue;
                }
                let data = fs::read(&entry)?;
                let chunks = chunk_bytes(&data, &config);
                let hashes = self.store_chunks(&chunks)?;
                let logical = if base_name.is_empty() {
                    rel_str
                } else {
                    format!("{base_name}/{rel_str}")
                };
                let logical = normalize_and_validate(&logical)?;
                file_entries.push((logical, data.len() as u64, hashes));
            }
        } else {
            return Err(SoalError::Other("path is neither file nor dir".into()));
        }

        if file_entries.is_empty() {
            return Err(SoalError::Other("nothing to add".into()));
        }

        // Merge into existing HEAD tree (critical: do not replace entire history).
        let mut tree = self.head_tree()?;
        for (p, size, chunks) in file_entries {
            tree.try_add_file(&p, size, chunks)?;
        }
        let tree_hash = self.save_tree(&tree)?;

        let msg = if path.is_dir() {
            format!("Add dir {base_name}")
        } else {
            format!("Add {base_name}")
        };

        let parents: Vec<ContentHash> = self.head()?.into_iter().collect();
        let commit = self.make_commit(tree_hash, parents, &msg)?;
        let commit_hash = self.save_commit(&commit)?;
        self.set_head(commit_hash)?;

        Ok(commit_hash)
    }

    /// Backward-compatible alias.
    pub fn add_file<P: AsRef<Path>>(
        &mut self,
        file_path: P,
        logical_name: &str,
    ) -> Result<ContentHash, SoalError> {
        self.add_path(file_path, logical_name)
    }

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
        files.sort();
        Ok(files)
    }

    /// Create an explicit snapshot commit (labels current tree; parents to HEAD).
    ///
    /// Registers the tip in the snapshot log for retention policy.
    pub fn snapshot(&mut self, message: &str) -> Result<ContentHash, SoalError> {
        let commit_hash = if let Some(current_head) = self.head()? {
            let head_commit = self.load_commit(current_head)?;
            let new_commit = self.make_commit(head_commit.tree, vec![current_head], message)?;
            let commit_hash = self.save_commit(&new_commit)?;
            self.set_head(commit_hash)?;
            commit_hash
        } else {
            let empty_tree = Tree::new();
            let tree_hash = self.save_tree(&empty_tree)?;
            let commit = self.make_commit(tree_hash, vec![], message)?;
            let commit_hash = self.save_commit(&commit)?;
            self.set_head(commit_hash)?;
            commit_hash
        };
        // Best-effort registry (avoid circular dependency issues in tests without policy).
        let _ = crate::policy::register_snapshot(self, commit_hash, message, false);
        if let Ok(pol) = crate::policy::load_policy(self) {
            let _ = crate::policy::apply_retention(self, &pol);
        }
        Ok(commit_hash)
    }

    /// Restore a commit's files into a target directory.
    pub fn restore<P: AsRef<Path>>(
        &self,
        commit_hash: ContentHash,
        target_dir: P,
    ) -> Result<(), SoalError> {
        let commit = self.load_commit(commit_hash)?;
        let tree = self.load_tree(commit.tree)?;

        let target = target_dir.as_ref();
        fs::create_dir_all(target)?;

        for (name, entry) in &tree.entries {
            if let TreeEntry::File { chunks, size, .. } = entry {
                // INV-PATH-01: reject unsafe paths on restore
                let out_path = safe_join(target, name)?;
                let mut file_data = Vec::new();
                for h in chunks {
                    let chunk_plain = self.load_chunk(h)?;
                    // Integrity: re-derive storage hash from plaintext.
                    let derived = if let Some(k) = &self.key {
                        let re_blob = encrypt_deterministic(&chunk_plain, k)?;
                        ContentHash::of(&re_blob)
                    } else {
                        ContentHash::of(&chunk_plain)
                    };
                    if derived != *h {
                        return Err(SoalError::hash_mismatch(h, &derived));
                    }
                    file_data.extend_from_slice(&chunk_plain);
                }
                // INV-TREE-02: reconstructed size matches manifest
                if file_data.len() as u64 != *size {
                    return Err(SoalError::Verify(format!(
                        "file size mismatch for '{name}': manifest {size}, got {}",
                        file_data.len()
                    )));
                }
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(out_path, &file_data)?;
            }
        }
        Ok(())
    }

    /// Basic status string.
    pub fn status(&self) -> Result<String, SoalError> {
        let head = self.head()?;
        let chunk_count = self.chunk_store.list()?.len();
        let file_count = match &head {
            Some(h) => {
                let c = self.load_commit(*h)?;
                self.load_tree(c.tree)?.entries.len()
            }
            None => 0,
        };
        let msg = match head {
            Some(h) => format!(
                "Vault '{}' (encrypt={}, min_replicas={}, vault_id={}, config_seq={})\nHEAD: {}\nFiles: {}\nChunks: {}\nMembers: {}",
                self.name,
                self.config.encryption_enabled,
                self.config.min_replicas,
                self.config.vault_id,
                self.config.config_seq,
                h.to_hex(),
                file_count,
                chunk_count,
                self.config.members.len()
            ),
            None => format!(
                "Vault '{}' (encrypt={}, min_replicas={}, vault_id={}) - no commits yet",
                self.name,
                self.config.encryption_enabled,
                self.config.min_replicas,
                self.config.vault_id
            ),
        };
        Ok(msg)
    }

    /// Walk commit parents from HEAD (or `start`) up to `limit` entries (newest first).
    pub fn history(
        &self,
        start: Option<ContentHash>,
        limit: usize,
    ) -> Result<Vec<(ContentHash, Commit)>, SoalError> {
        let mut out = Vec::new();
        let mut cur = match start {
            Some(h) => Some(h),
            None => self.head()?,
        };
        while let Some(h) = cur {
            if out.len() >= limit {
                break;
            }
            let c = self.load_commit(h)?;
            let parent = c.parents.first().copied();
            out.push((h, c));
            cur = parent;
        }
        Ok(out)
    }

    /// Whether commit + tree + all chunks are present and loadable.
    pub fn is_complete(&self, commit_hash: ContentHash) -> Result<bool, SoalError> {
        if !self.has_commit_object(&commit_hash) {
            return Ok(false);
        }
        let commit = self.load_commit(commit_hash)?;
        if !self.has_tree_object(&commit.tree) {
            return Ok(false);
        }
        let tree = self.load_tree(commit.tree)?;
        for ch in tree.all_chunk_hashes() {
            if !self.has_chunk(&ch) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Resolve any vault CAS object by content hash (chunk / tree / commit wire).
    /// Used by durable blob serve (VaultCas hybrid) and SC-IROH-CID.
    pub fn resolve_blob(&self, hash: ContentHash) -> Result<Vec<u8>, SoalError> {
        if self.has_chunk(&hash) {
            return self.export_stored_chunk(hash);
        }
        if self.has_tree_object(&hash) {
            return self.export_tree_bytes(hash);
        }
        if self.has_commit_object(&hash) {
            return self.export_commit_bytes(hash);
        }
        Err(SoalError::ChunkNotFound(hash.to_hex()))
    }

    /// True if `node_id_hex` is in the members list, or members is empty (open trust).
    pub fn is_member(&self, node_id_hex: &str) -> bool {
        if self.config.members.is_empty() {
            return true;
        }
        let n = node_id_hex.to_ascii_lowercase();
        self.config
            .members
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&n))
    }

    /// Collect all chunk hashes reachable from HEAD (for GC mark phase).
    pub fn live_chunk_hashes(&self) -> Result<BTreeSet<ContentHash>, SoalError> {
        let roots = crate::policy::protected_commit_roots(self)
            .unwrap_or_else(|_| self.head().ok().flatten().into_iter().collect());
        self.live_chunk_hashes_from_roots(&roots)
    }

    /// Mark-phase: all chunks reachable from the given commit roots (and parents).
    pub fn live_chunk_hashes_from_roots(
        &self,
        roots: &[ContentHash],
    ) -> Result<BTreeSet<ContentHash>, SoalError> {
        let mut live = BTreeSet::new();
        let mut queue: Vec<ContentHash> = roots.to_vec();
        let mut seen = BTreeSet::new();
        while let Some(h) = queue.pop() {
            if !seen.insert(h) {
                continue;
            }
            if !self.has_commit_object(&h) {
                continue;
            }
            let c = self.load_commit(h)?;
            queue.extend(c.parents.iter().copied());
            if self.has_tree_object(&c.tree) {
                let tree = self.load_tree(c.tree)?;
                for ch in tree.all_chunk_hashes() {
                    live.insert(ch);
                }
            }
        }
        Ok(live)
    }

    /// Commit + tree CIDs reachable from protected roots (for object GC).
    pub fn live_object_hashes(&self) -> Result<BTreeSet<ContentHash>, SoalError> {
        let roots = crate::policy::protected_commit_roots(self)
            .unwrap_or_else(|_| self.head().ok().flatten().into_iter().collect());
        let mut live = BTreeSet::new();
        let mut queue: Vec<ContentHash> = roots;
        let mut seen = BTreeSet::new();
        while let Some(h) = queue.pop() {
            if !seen.insert(h) {
                continue;
            }
            if !self.has_commit_object(&h) {
                continue;
            }
            live.insert(h);
            let c = self.load_commit(h)?;
            live.insert(c.tree);
            queue.extend(c.parents.iter().copied());
        }
        Ok(live)
    }

    /// Number of chunk objects currently on disk.
    pub fn chunk_count(&self) -> Result<usize, SoalError> {
        Ok(self.chunk_store.list()?.len())
    }

    /// Delete unreferenced chunk files (mark-and-sweep from protected roots).
    /// Returns number of chunks removed.
    pub fn gc_unreachable_chunks(&self) -> Result<usize, SoalError> {
        let live = self.live_chunk_hashes()?;
        let mut removed = 0;
        for h in self.chunk_store.list()? {
            if !live.contains(&h) {
                let path = self
                    .root
                    .join(CHUNKS_DIR)
                    .join(format!("{}.chunk", h.to_hex()));
                if path.exists() {
                    fs::remove_file(path)?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    /// Delete unreferenced commit/tree objects not reachable from protected roots.
    /// Returns (commits_removed, trees_removed).
    pub fn gc_unreachable_objects(&self) -> Result<(usize, usize), SoalError> {
        let live = self.live_object_hashes()?;
        let mut commits_removed = 0usize;
        let mut trees_removed = 0usize;

        for dir_name in [COMMITS_DIR, TREES_DIR] {
            let dir = self.root.join(dir_name);
            if !dir.exists() {
                continue;
            }
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                // stems are 64-char hex
                if stem.len() != 64 {
                    continue;
                }
                let Ok(h) = ContentHash::from_hex(stem) else {
                    continue;
                };
                if live.contains(&h) {
                    continue;
                }
                fs::remove_file(&path)?;
                if dir_name == COMMITS_DIR {
                    commits_removed += 1;
                } else {
                    trees_removed += 1;
                }
            }
        }
        Ok((commits_removed, trees_removed))
    }

    /// Full GC: chunks + orphaned commits/trees. Returns total objects removed.
    pub fn gc_all(&self) -> Result<usize, SoalError> {
        let chunks = self.gc_unreachable_chunks()?;
        let (c, t) = self.gc_unreachable_objects()?;
        Ok(chunks + c + t)
    }

    // --- Sync / transfer helpers ---

    /// Read raw stored bytes for a chunk (ct or plain).
    pub fn export_stored_chunk(&self, hash: ContentHash) -> Result<Vec<u8>, SoalError> {
        self.chunk_store.get(&hash)
    }

    /// Write raw received stored bytes under the given storage hash (verified).
    /// Idempotent for identical bytes; hard-errors on CID collision (INV-IMPORT-03).
    pub fn import_stored_chunk(&self, hash: ContentHash, data: &[u8]) -> Result<(), SoalError> {
        self.chunk_store.put_verified(hash, data)?;
        Ok(())
    }

    pub fn has_chunk(&self, hash: &ContentHash) -> bool {
        self.chunk_store.exists(hash)
    }

    /// Export tree wire bytes that content-address to `hash`.
    /// Prefer on-disk `.bin`; else re-encode loaded tree as wire.
    pub fn export_tree_bytes(&self, hash: ContentHash) -> Result<Vec<u8>, SoalError> {
        let bin = self.tree_path_bin(&hash);
        if bin.exists() {
            let data = fs::read(&bin)?;
            if ContentHash::of(&data) == hash {
                return Ok(data);
            }
        }
        let tree = self.load_tree(hash)?;
        // If this was a legacy JSON object, export may use legacy bytes if hash matches
        let wire = tree.wire_bytes()?;
        if ContentHash::of(&wire) == hash {
            return Ok(wire);
        }
        let legacy = tree.canonical_bytes()?;
        if ContentHash::of(&legacy) == hash {
            return Ok(legacy);
        }
        Err(SoalError::hash_mismatch(&hash, &ContentHash::of(&wire)))
    }

    /// Import a tree; accepts framed wire or legacy JSON. Stores as `.bin` wire when possible.
    pub fn import_tree_bytes(&self, hash: ContentHash, data: &[u8]) -> Result<(), SoalError> {
        if ContentHash::of(data) != hash {
            return Err(SoalError::hash_mismatch(&hash, &ContentHash::of(data)));
        }
        // Prefer storing exact wire bytes when framed
        if data.len() >= 16 && data[..16] == crate::codec::DOMAIN_TREE {
            let tree = Tree::from_wire_or_json(data)?;
            if tree.hash()? != hash {
                return Err(SoalError::hash_mismatch(&hash, &tree.hash()?));
            }
            fs::write(self.tree_path_bin(&hash), data)?;
            return Ok(());
        }
        // Legacy JSON: verify legacy hash, store as-is under .json
        let tree = Tree::from_bytes(data)?;
        if tree.legacy_json_hash()? != hash && ContentHash::of(data) != hash {
            return Err(SoalError::hash_mismatch(&hash, &tree.legacy_json_hash()?));
        }
        fs::write(self.tree_path_json(&hash), data)?;
        Ok(())
    }

    /// Export commit wire bytes that content-address to `hash`.
    pub fn export_commit_bytes(&self, hash: ContentHash) -> Result<Vec<u8>, SoalError> {
        let bin = self.commit_path_bin(&hash);
        if bin.exists() {
            let data = fs::read(&bin)?;
            if ContentHash::of(&data) == hash {
                return Ok(data);
            }
        }
        let commit = self.load_commit(hash)?;
        let wire = commit.wire_bytes()?;
        if ContentHash::of(&wire) == hash {
            return Ok(wire);
        }
        let legacy = commit.legacy_json_bytes()?;
        if ContentHash::of(&legacy) == hash {
            return Ok(legacy);
        }
        Err(SoalError::hash_mismatch(&hash, &ContentHash::of(&wire)))
    }

    /// Import a commit; accepts framed wire or legacy JSON.
    pub fn import_commit_bytes(&self, hash: ContentHash, data: &[u8]) -> Result<(), SoalError> {
        if ContentHash::of(data) != hash {
            return Err(SoalError::hash_mismatch(&hash, &ContentHash::of(data)));
        }
        if data.len() >= 16 && data[..16] == crate::codec::DOMAIN_COMMIT {
            let commit = Commit::from_wire_or_json(data)?;
            if commit.hash()? != hash {
                return Err(SoalError::hash_mismatch(&hash, &commit.hash()?));
            }
            // INV-SIG-01 / SC-SIG-IMPORT: reject invalid non-zero signatures
            identity::verify_commit_signature(&commit)?;
            fs::write(self.commit_path_bin(&hash), data)?;
            return Ok(());
        }
        let commit = Commit::from_bytes(data)?;
        if commit.legacy_json_hash()? != hash && ContentHash::of(data) != hash {
            return Err(SoalError::hash_mismatch(&hash, &commit.legacy_json_hash()?));
        }
        fs::write(self.commit_path_json(&hash), data)?;
        Ok(())
    }

    /// Adopt a remote commit as HEAD after it (and its tree) are imported.
    pub fn set_head_public(&self, commit_hash: ContentHash) -> Result<(), SoalError> {
        // Ensure commit exists and is valid
        let _ = self.load_commit(commit_hash)?;
        self.set_head(commit_hash)?;
        self.record_head(commit_hash)?;
        Ok(())
    }

    /// Record an alternate head (multi-head support, PR-08).
    pub fn record_head(&self, commit_hash: ContentHash) -> Result<(), SoalError> {
        let mut heads = self.list_heads()?;
        heads.insert(commit_hash);
        self.write_heads(&heads)
    }

    /// All known heads (HEAD plus HEADS file).
    pub fn list_heads(&self) -> Result<BTreeSet<ContentHash>, SoalError> {
        let mut heads = self.list_heads_file_only()?;
        if let Some(h) = self.head()? {
            heads.insert(h);
        }
        Ok(heads)
    }

    fn write_heads(&self, heads: &BTreeSet<ContentHash>) -> Result<(), SoalError> {
        let path = self.root.join(HEADS_FILE);
        let mut body = String::new();
        for h in heads {
            body.push_str(&h.to_hex());
            body.push('\n');
        }
        fs::write(path, body)?;
        Ok(())
    }

    /// Merge a remote head into local HEAD with conflict copies (PR-08).
    ///
    /// Creates a multi-parent merge commit. Divergent paths become
    /// `name (conflict from <label>).ext` copies. Returns merge commit hash
    /// and number of conflict copies.
    pub fn merge_head(
        &mut self,
        remote_head: ContentHash,
        from_label: &str,
    ) -> Result<(ContentHash, usize), SoalError> {
        let _ = self.load_commit(remote_head)?; // must exist
        let remote_commit = self.load_commit(remote_head)?;
        let remote_tree = self.load_tree(remote_commit.tree)?;

        let local_head = self.head()?;
        let mut merged = match local_head {
            Some(h) => {
                let lc = self.load_commit(h)?;
                self.load_tree(lc.tree)?
            }
            None => Tree::new(),
        };

        let conflicts = merged.merge_with_conflicts(&remote_tree, from_label);
        let tree_hash = self.save_tree(&merged)?;

        let mut parents = Vec::new();
        if let Some(h) = local_head {
            parents.push(h);
        }
        if !parents.contains(&remote_head) {
            parents.push(remote_head);
        }

        let msg = if conflicts > 0 {
            format!(
                "Merge {} ({} conflict{})",
                from_label,
                conflicts,
                if conflicts == 1 { "" } else { "s" }
            )
        } else {
            format!("Merge {from_label}")
        };
        let commit = self.make_commit(tree_hash, parents, &msg)?;
        let commit_hash = self.save_commit(&commit)?;
        self.set_head(commit_hash)?;
        // Collapse multi-heads to the merge result
        let mut heads = BTreeSet::new();
        heads.insert(commit_hash);
        self.write_heads(&heads)?;
        Ok((commit_hash, conflicts))
    }

    /// If we have multiple heads, leave them recorded; promote one as HEAD.
    pub fn set_divergent_head(&self, commit_hash: ContentHash) -> Result<(), SoalError> {
        let _ = self.load_commit(commit_hash)?;
        self.record_head(commit_hash)?;
        // Do not auto-overwrite HEAD if we already have a different one —
        // caller decides. Still update HEAD only when empty.
        if self.head()?.is_none() {
            self.set_head(commit_hash)?;
        }
        Ok(())
    }

    /// Collect all blob hashes needed to fully serve a commit **and its parent DAG**.
    ///
    /// Walks parents (bounded by `MAX_JOB_COMMITS`) so a single announce/provide
    /// can satisfy SyncEngine parent fetches (closes the tip-only provide gap).
    pub fn collect_provide_hashes(
        &self,
        commit_hash: ContentHash,
    ) -> Result<Vec<(ContentHash, Vec<u8>)>, SoalError> {
        use std::collections::VecDeque;
        let mut out = Vec::new();
        let mut seen_commits = BTreeSet::new();
        let mut seen_blobs = BTreeSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(commit_hash);

        while let Some(cid) = queue.pop_front() {
            if !seen_commits.insert(cid) {
                continue;
            }
            if seen_commits.len() > crate::codec::MAX_JOB_COMMITS {
                return Err(SoalError::Other(
                    "provide DAG too deep (MAX_JOB_COMMITS)".into(),
                ));
            }
            if !self.has_commit_object(&cid) {
                continue;
            }
            let commit_bytes = self.export_commit_bytes(cid)?;
            if seen_blobs.insert(cid) {
                out.push((cid, commit_bytes));
            }

            let commit = self.load_commit(cid)?;
            for p in &commit.parents {
                queue.push_back(*p);
            }

            if self.has_tree_object(&commit.tree) && seen_blobs.insert(commit.tree) {
                let tree_bytes = self.export_tree_bytes(commit.tree)?;
                out.push((commit.tree, tree_bytes));
                let tree = self.load_tree(commit.tree)?;
                for ch in tree.all_chunk_hashes() {
                    if seen_blobs.insert(ch) {
                        if let Ok(bytes) = self.export_stored_chunk(ch) {
                            out.push((ch, bytes));
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// Ingest a full snapshot from a peer: commit → tree → missing chunks.
    ///
    /// If local HEAD is empty, adopts remote as HEAD. If local already has a
    /// different HEAD, records remote as an alternate head (multi-head) instead
    /// of silently overwriting — use `merge_head` to resolve.
    pub async fn ingest_commit_from_peer<F, Fut>(
        &self,
        peer: &str,
        commit_hash: ContentHash,
        mut fetch: F,
    ) -> Result<bool, SoalError>
    where
        F: FnMut(&str, ContentHash) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<u8>, SoalError>>,
    {
        // Commit
        if !self.has_commit_object(&commit_hash) {
            let bytes = fetch(peer, commit_hash).await?;
            self.import_commit_bytes(commit_hash, &bytes)?;
        }

        let commit = self.load_commit(commit_hash)?;

        // Tree
        if !self.has_tree_object(&commit.tree) {
            let bytes = fetch(peer, commit.tree).await?;
            self.import_tree_bytes(commit.tree, &bytes)?;
        }

        let tree = self.load_tree(commit.tree)?;

        // Chunks
        for ch in tree.all_chunk_hashes() {
            if !self.has_chunk(&ch) {
                let bytes = fetch(peer, ch).await?;
                self.import_stored_chunk(ch, &bytes)?;
            }
        }

        match self.head()? {
            None => {
                self.set_head(commit_hash)?;
                Ok(true)
            }
            Some(local) if local == commit_hash => {
                self.record_head(commit_hash)?;
                Ok(false)
            }
            Some(_) => {
                // Divergent: keep local HEAD, record remote tip for merge.
                self.record_head(commit_hash)?;
                Ok(false)
            }
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn write_config(root: &Path, config: &VaultConfig) -> Result<(), SoalError> {
    let path = root.join(CONFIG_FILE);
    fs::write(path, serde_json::to_string_pretty(config)?)?;
    Ok(())
}

fn write_key_file(root: &Path, key: &Key) -> Result<(), SoalError> {
    let path = root.join(KEY_FILE);
    fs::write(&path, hex::encode(key))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn write_wrapped_key(root: &Path, wrapped: &WrappedKey) -> Result<(), SoalError> {
    let path = root.join(WRAPPED_KEY_FILE);
    fs::write(&path, serde_json::to_string_pretty(wrapped)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn load_wrapped_key(root: &Path) -> Result<WrappedKey, SoalError> {
    let path = root.join(WRAPPED_KEY_FILE);
    if !path.exists() {
        return Err(SoalError::Other("vault.wrapped.json missing".into()));
    }
    let s = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&s)?)
}

fn load_or_migrate_key(
    root: &Path,
    config: &mut VaultConfig,
    passphrase: Option<&str>,
) -> Result<Key, SoalError> {
    // Passphrase-wrapped path (PR-05).
    let wrapped_path = root.join(WRAPPED_KEY_FILE);
    if wrapped_path.exists() || config.key_wrapped {
        let pass = passphrase.ok_or_else(|| {
            SoalError::Other("vault key is passphrase-protected; provide passphrase".into())
        })?;
        let wrapped = load_wrapped_key(root)?;
        let vault_id = if config.vault_id.is_empty() {
            return Err(SoalError::Other(
                "vault_id required to unwrap passphrase key".into(),
            ));
        } else {
            codec::vault_id_from_hex(&config.vault_id)?
        };
        config.key_wrapped = true;
        return unwrap_vault_key_passphrase(&wrapped, pass, &vault_id);
    }

    let key_path = root.join(KEY_FILE);
    if key_path.exists() {
        let hexstr = fs::read_to_string(key_path)?;
        return key_from_hex(&hexstr);
    }

    // Legacy: key embedded in vault.json
    if let Some(hexkey) = config.key_hex.take() {
        let k = key_from_hex(&hexkey)?;
        write_key_file(root, &k)?;
        // Rewrite config without key_hex
        write_config(root, config)?;
        return Ok(k);
    }

    Err(SoalError::Other(
        "encryption enabled but vault key file missing".into(),
    ))
}

/// Canonical config sign preimage: DOMAIN_CONFIG || compact JSON (no config_sig).
///
/// Keys are sorted (BTreeMap) so the sign bytes are deterministic across platforms.
pub fn config_sign_preimage(config: &VaultConfig) -> Result<Vec<u8>, SoalError> {
    use serde_json::{Map, Value};
    let mut map = Map::new();
    map.insert("config_seq".into(), Value::from(config.config_seq));
    map.insert("created_at".into(), Value::from(config.created_at));
    map.insert(
        "encryption_enabled".into(),
        Value::from(config.encryption_enabled),
    );
    map.insert("key_wrapped".into(), Value::from(config.key_wrapped));
    map.insert(
        "members".into(),
        Value::Array(config.members.iter().cloned().map(Value::String).collect()),
    );
    map.insert("min_replicas".into(), Value::from(config.min_replicas));
    map.insert("name".into(), Value::String(config.name.clone()));
    map.insert(
        "owner".into(),
        match &config.owner {
            Some(o) => Value::String(o.clone()),
            None => Value::Null,
        },
    );
    map.insert("vault_id".into(), Value::String(config.vault_id.clone()));
    let json = serde_json::to_vec(&Value::Object(map))?;
    Ok(codec::frame(&codec::DOMAIN_CONFIG, &json))
}

/// Sign vault config in place (PR-05).
pub fn sign_vault_config(sk: &SecretKey, config: &mut VaultConfig) -> Result<(), SoalError> {
    config.owner = Some(sk.public().to_string());
    let msg = config_sign_preimage(config)?;
    let sig = sk.sign(&msg);
    config.config_sig = Some(hex::encode(sig.to_bytes()));
    Ok(())
}

/// Verify config signature when present.
pub fn verify_vault_config(config: &VaultConfig) -> Result<(), SoalError> {
    let Some(sig_hex) = &config.config_sig else {
        return Ok(()); // unsigned allowed for local-only
    };
    if sig_hex.is_empty() {
        return Ok(());
    }
    let owner = config
        .owner
        .as_ref()
        .ok_or_else(|| SoalError::Verify("config signed but owner missing".into()))?;
    let pk = owner
        .parse::<iroh::PublicKey>()
        .map_err(|e| SoalError::Verify(format!("bad config owner: {e}")))?;
    let sig_bytes =
        hex::decode(sig_hex.trim()).map_err(|_| SoalError::Verify("bad config_sig hex".into()))?;
    if sig_bytes.len() != 64 {
        return Err(SoalError::Verify("config_sig must be 64 bytes".into()));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let msg = config_sign_preimage(config)?;
    let sig = iroh::Signature::from_bytes(&arr);
    pk.verify(&msg, &sig)
        .map_err(|_| SoalError::Verify("vault config signature invalid".into()))?;
    Ok(())
}

/// Default base directory for vault data: `~/.soal/vaults`.
pub fn default_soal_dir() -> PathBuf {
    default_soal_home().join("vaults")
}

/// Soal home directory: `~/.soal` (respects HOME / USERPROFILE).
pub fn default_soal_home() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".soal")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn passphrase_wrap_and_open() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        // Ensure node identity for config signing
        let sk = iroh::SecretKey::generate();
        let state = serde_json::json!({
            "secret_key_hex": hex::encode(sk.to_bytes()),
            "peers": [],
        });
        std::fs::write(home.join("node.json"), state.to_string()).unwrap();

        let mut v = Vault::create(dir.path(), "pw", true)
            .unwrap()
            .with_soal_home(home.clone());
        v.enable_passphrase("s3cret-pass").unwrap();
        assert!(v.config.key_wrapped);
        assert!(!dir.path().join("pw").join(KEY_FILE).exists());
        assert!(dir.path().join("pw").join(WRAPPED_KEY_FILE).exists());

        assert!(Vault::open(dir.path(), "pw").is_err());
        let v2 = Vault::open_with_passphrase(dir.path(), "pw", Some("s3cret-pass")).unwrap();
        assert_eq!(v2.vault_key(), v.vault_key());
        v2.verify_config_signature().unwrap();
    }

    #[test]
    fn merge_head_creates_conflict_copy() {
        let dir = tempdir().unwrap();
        let mut a = Vault::create(dir.path(), "ma", false).unwrap();
        let f1 = dir.path().join("f1.txt");
        fs::write(&f1, b"version-a").unwrap();
        let ha = a.add_path(&f1, "shared.txt").unwrap();

        let mut b = Vault::create(dir.path(), "mb", false).unwrap();
        let f2 = dir.path().join("f2.txt");
        fs::write(&f2, b"version-b").unwrap();
        let hb = b.add_path(&f2, "shared.txt").unwrap();

        // Import B's objects into A
        for (h, bytes) in b.collect_provide_hashes(hb).unwrap() {
            if bytes.len() >= 16 && bytes[..16] == crate::codec::DOMAIN_COMMIT {
                a.import_commit_bytes(h, &bytes).unwrap();
            } else if bytes.len() >= 16 && bytes[..16] == crate::codec::DOMAIN_TREE {
                a.import_tree_bytes(h, &bytes).unwrap();
            } else {
                a.import_stored_chunk(h, &bytes).unwrap();
            }
        }

        let (merge, conflicts) = a.merge_head(hb, "NodeB").unwrap();
        assert!(conflicts >= 1);
        let tree = a.head_tree().unwrap();
        assert!(tree.entries.contains_key("shared.txt"));
        assert!(tree
            .entries
            .keys()
            .any(|k| k.contains("conflict from NodeB")));
        let mc = a.load_commit(merge).unwrap();
        assert!(mc.parents.contains(&ha));
        assert!(mc.parents.contains(&hb));
    }

    #[test]
    fn vault_create_and_open_roundtrip() {
        let dir = tempdir().unwrap();
        let base = dir.path();

        let v = Vault::create(base, "testvault", true).unwrap();
        assert!(v.config.encryption_enabled);
        assert!(v.key.is_some());
        assert!(base.join("testvault").join(KEY_FILE).exists());
        // Key must not be in vault.json
        let cfg = fs::read_to_string(base.join("testvault/vault.json")).unwrap();
        assert!(!cfg.contains("key_hex") || cfg.contains("\"key_hex\": null"));

        let opened = Vault::open(base, "testvault").unwrap();
        assert_eq!(opened.name, "testvault");
        assert!(opened.config.encryption_enabled);
        assert_eq!(opened.key, v.key);
    }

    #[test]
    fn vault_create_no_encrypt() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let v = Vault::create(base, "plain", false).unwrap();
        assert!(!v.config.encryption_enabled);
        assert!(v.key.is_none());
    }

    #[test]
    fn vault_add_file_and_head_and_restore_basic() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let mut v = Vault::create(base, "rf", true).unwrap();

        let srcdir = dir.path().join("src");
        std::fs::create_dir(&srcdir).unwrap();
        std::fs::write(srcdir.join("hi.txt"), b"hello vault unit test").unwrap();

        let commit = v.add_path(&srcdir, "hi").unwrap();
        assert!(v.head().unwrap().is_some());

        let restore_to = dir.path().join("out");
        v.restore(commit, &restore_to).unwrap();
        let restored = std::fs::read_to_string(restore_to.join("hi/hi.txt")).unwrap();
        assert_eq!(restored, "hello vault unit test");
    }

    #[test]
    fn incremental_add_merges_tree() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let mut v = Vault::create(base, "merge", true).unwrap();

        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        fs::write(&a, b"file A").unwrap();
        fs::write(&b, b"file B").unwrap();

        let c1 = v.add_path(&a, "a.txt").unwrap();
        let c2 = v.add_path(&b, "b.txt").unwrap();
        assert_ne!(c1, c2);

        // HEAD tree must contain both files
        let tree = v.head_tree().unwrap();
        assert!(tree.entries.contains_key("a.txt"));
        assert!(tree.entries.contains_key("b.txt"));

        // c2 parents to c1
        let commit = v.load_commit(c2).unwrap();
        assert_eq!(commit.parents, vec![c1]);

        let restore_to = dir.path().join("both");
        v.restore(c2, &restore_to).unwrap();
        assert_eq!(
            fs::read_to_string(restore_to.join("a.txt")).unwrap(),
            "file A"
        );
        assert_eq!(
            fs::read_to_string(restore_to.join("b.txt")).unwrap(),
            "file B"
        );
    }

    #[test]
    fn add_and_list_chunks_after_add() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let mut v = Vault::create(base, "ct", true).unwrap();

        let srcdir = dir.path().join("s2");
        std::fs::create_dir(&srcdir).unwrap();
        std::fs::write(srcdir.join("sec.txt"), b"another secret for chunks ct").unwrap();

        let _c = v.add_path(&srcdir, "s2").unwrap();

        let chunks_dir = base.join("ct/chunks");
        let chunk_files: Vec<_> = std::fs::read_dir(&chunks_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(!chunk_files.is_empty(), "chunks should be stored");

        let any_plain = chunk_files.iter().any(|e| {
            if let Ok(data) = std::fs::read(e.path()) {
                std::str::from_utf8(&data).is_ok_and(|s| s.contains("secret"))
            } else {
                false
            }
        });
        assert!(!any_plain, "encrypted storage must not leak plaintext");
    }

    #[test]
    fn export_import_roundtrip_for_sync() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let mut v = Vault::create(base, "syncv", true).unwrap();

        let src = dir.path().join("f");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("x.txt"), b"sync test content 123").unwrap();
        let c = v.add_path(&src, "f").unwrap();

        let commit_bytes = v.export_commit_bytes(c).expect("commit export");
        // On-disk / export bytes must be content-addressed (iroh-blobs compatible)
        assert_eq!(ContentHash::of(&commit_bytes), c);

        let v2_dir = tempdir().unwrap();
        let v2 = Vault::create(v2_dir.path(), "syncv", true).unwrap();
        v2.import_commit_bytes(c, &commit_bytes)
            .expect("import commit");

        let imported_path = v2_dir
            .path()
            .join("syncv/commits")
            .join(format!("{}.bin", c.to_hex()));
        assert!(imported_path.exists());
        assert_eq!(ContentHash::of(&fs::read(&imported_path).unwrap()), c);
    }

    #[test]
    fn provide_hashes_match_blob_bytes() {
        let dir = tempdir().unwrap();
        let mut v = Vault::create(dir.path(), "pv", false).unwrap();
        let f = dir.path().join("x.txt");
        fs::write(&f, b"provide me").unwrap();
        let c = v.add_path(&f, "x.txt").unwrap();
        let items = v.collect_provide_hashes(c).unwrap();
        assert!(!items.is_empty());
        for (h, bytes) in items {
            assert_eq!(
                ContentHash::of(&bytes),
                h,
                "every provided blob must content-address match"
            );
        }
    }

    #[test]
    fn import_rejects_tampered_commit() {
        let dir = tempdir().unwrap();
        let mut v = Vault::create(dir.path(), "t", false).unwrap();
        let f = dir.path().join("x");
        fs::write(&f, b"data").unwrap();
        let c = v.add_path(&f, "x").unwrap();
        let mut bytes = v.export_commit_bytes(c).unwrap();
        // Tamper
        if let Some(b) = bytes.last_mut() {
            *b ^= 0xff;
        }
        let v2 = Vault::create(dir.path(), "t2", false).unwrap();
        assert!(v2.import_commit_bytes(c, &bytes).is_err());
    }

    #[test]
    fn legacy_key_migration() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("legacy");
        fs::create_dir_all(root.join("chunks")).unwrap();
        fs::create_dir_all(root.join("commits")).unwrap();
        fs::create_dir_all(root.join("trees")).unwrap();
        let key = generate_key();
        let cfg = serde_json::json!({
            "name": "legacy",
            "encryption_enabled": true,
            "min_replicas": 2,
            "created_at": 1,
            "key_hex": hex::encode(key),
        });
        fs::write(root.join("vault.json"), cfg.to_string()).unwrap();

        let v = Vault::open(dir.path(), "legacy").unwrap();
        assert_eq!(v.key.unwrap(), key);
        assert!(root.join(KEY_FILE).exists());
        let new_cfg: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(root.join("vault.json")).unwrap()).unwrap();
        assert!(new_cfg.get("key_hex").is_none() || new_cfg["key_hex"].is_null());
    }

    #[test]
    fn reject_unsafe_logical_path_on_add() {
        let dir = tempdir().unwrap();
        let mut v = Vault::create(dir.path(), "pathv", false).unwrap();
        let f = dir.path().join("x.txt");
        fs::write(&f, b"x").unwrap();
        assert!(v.add_path(&f, "../escape").is_err());
        assert!(v.add_path(&f, "a/../../b").is_err());
        assert!(v.add_path(&f, "ok.txt").is_ok());
    }

    #[test]
    fn import_chunk_idempotent_and_collision() {
        let dir = tempdir().unwrap();
        let v = Vault::create(dir.path(), "imp", false).unwrap();
        let data = b"chunk-data-xyz";
        let h = ContentHash::of(data);
        v.import_stored_chunk(h, data).unwrap();
        v.import_stored_chunk(h, data).unwrap(); // idempotent
                                                 // force collision via raw file rewrite
        let path = dir
            .path()
            .join("imp/chunks")
            .join(format!("{}.chunk", h.to_hex()));
        fs::write(&path, b"different-bytes-not-matching-hash!!").unwrap();
        let err = v.import_stored_chunk(h, data).unwrap_err();
        assert!(matches!(err, SoalError::CidCollision { .. }));
    }

    #[test]
    fn vault_id_generated_and_stable() {
        let dir = tempdir().unwrap();
        let v = Vault::create(dir.path(), "idv", true).unwrap();
        assert_eq!(v.config.vault_id.len(), 32);
        assert_eq!(v.config.config_seq, 1);
        let opened = Vault::open(dir.path(), "idv").unwrap();
        assert_eq!(opened.config.vault_id, v.config.vault_id);
        assert_eq!(
            opened.vault_id_bytes().unwrap(),
            v.vault_id_bytes().unwrap()
        );
    }

    #[test]
    fn history_walks_parents() {
        let dir = tempdir().unwrap();
        let mut v = Vault::create(dir.path(), "hist", false).unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        fs::write(&a, b"A").unwrap();
        fs::write(&b, b"B").unwrap();
        let c1 = v.add_path(&a, "a.txt").unwrap();
        let c2 = v.add_path(&b, "b.txt").unwrap();
        let hist = v.history(None, 10).unwrap();
        assert!(hist.len() >= 2);
        assert_eq!(hist[0].0, c2);
        assert_eq!(hist[1].0, c1);
    }

    #[test]
    fn gc_removes_orphans_keeps_live() {
        let dir = tempdir().unwrap();
        let mut v = Vault::create(dir.path(), "gc", false).unwrap();
        let f = dir.path().join("live.txt");
        fs::write(&f, b"live data").unwrap();
        let _c = v.add_path(&f, "live.txt").unwrap();
        let live_before = v.live_chunk_hashes().unwrap();
        assert!(!live_before.is_empty());

        // Inject orphan chunk
        let orphan = b"orphan-chunk-not-in-tree";
        let oh = ContentHash::of(orphan);
        v.import_stored_chunk(oh, orphan).unwrap();
        assert!(v.has_chunk(&oh));
        assert!(!live_before.contains(&oh));

        let removed = v.gc_unreachable_chunks().unwrap();
        assert!(removed >= 1);
        assert!(!v.has_chunk(&oh));
        // live still present
        for h in live_before {
            assert!(v.has_chunk(&h));
        }
    }

    #[test]
    fn resolve_blob_finds_commit_tree_chunk() {
        let dir = tempdir().unwrap();
        let mut v = Vault::create(dir.path(), "res", false).unwrap();
        let f = dir.path().join("r.txt");
        fs::write(&f, b"resolve me").unwrap();
        let c = v.add_path(&f, "r.txt").unwrap();
        let commit_bytes = v.resolve_blob(c).unwrap();
        assert_eq!(ContentHash::of(&commit_bytes), c);
        let commit = v.load_commit(c).unwrap();
        let tree_bytes = v.resolve_blob(commit.tree).unwrap();
        assert_eq!(ContentHash::of(&tree_bytes), commit.tree);
    }

    #[test]
    fn create_for_test_shared_key() {
        let dir = tempdir().unwrap();
        let key = generate_key();
        let id = [0xABu8; 16];
        let a = Vault::create_for_test(dir.path(), "a", true, id, Some(key), vec!["n1".into()])
            .unwrap();
        let b = Vault::create_for_test(
            dir.path(),
            "b",
            true,
            id,
            Some(key),
            vec!["n1".into(), "n2".into()],
        )
        .unwrap();
        assert_eq!(a.vault_id_bytes().unwrap(), b.vault_id_bytes().unwrap());
        assert_eq!(a.key, b.key);
        assert!(a.is_member("n1"));
        assert!(!a.is_member("n2"));
        assert!(b.is_member("n2"));
    }
}
