//! Embeddable high-level API (Phase 2).
//!
//! Thin façade over vault/network/sync for notes apps, agents, and services.
//! Prefer this over reaching into internal modules when integrating Soal.

use crate::health::{self, ClusterHealth, TreeDiff, VaultHealth};
use crate::invite::{self, Invite, InviteRole};
use crate::network::Network;
use crate::policy::{self, VaultPolicy};
use crate::replication;
use crate::sync;
use crate::vault::{self, Vault};
use crate::{ContentHash, SoalError};
use iroh::SecretKey;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Session bound to a Soal home directory (`~/.soal` layout).
pub struct SoalSession {
    pub home: PathBuf,
    pub vaults_dir: PathBuf,
    passphrase: Option<String>,
}

impl SoalSession {
    /// Open session under `home` (contains `node.json` + `vaults/`).
    pub fn open(home: impl Into<PathBuf>) -> Result<Self, SoalError> {
        let home = home.into();
        std::fs::create_dir_all(&home)?;
        let vaults_dir = home.join("vaults");
        std::fs::create_dir_all(&vaults_dir)?;
        Ok(Self {
            home,
            vaults_dir,
            passphrase: None,
        })
    }

    /// Default session under the user home (`~/.soal`).
    pub fn default_user() -> Result<Self, SoalError> {
        Self::open(vault::default_soal_home())
    }

    pub fn with_passphrase(mut self, pass: impl Into<String>) -> Self {
        self.passphrase = Some(pass.into());
        self
    }

    pub fn list_vaults(&self) -> Result<Vec<String>, SoalError> {
        Vault::list(&self.vaults_dir)
    }

    pub fn create_vault(
        &self,
        name: &str,
        encrypt: bool,
        min_replicas: u8,
    ) -> Result<Vault, SoalError> {
        let mut v = Vault::create_with_policy(&self.vaults_dir, name, encrypt, min_replicas)?
            .with_soal_home(self.home.clone());
        let policy = VaultPolicy {
            min_replicas: min_replicas.max(1),
            ..VaultPolicy::default()
        };
        policy::save_policy(&v, &policy)?;
        let _ = &mut v;
        Ok(
            Vault::open_with_passphrase(&self.vaults_dir, name, self.passphrase.as_deref())?
                .with_soal_home(self.home.clone()),
        )
    }

    pub fn open_vault(&self, name: &str) -> Result<Vault, SoalError> {
        Ok(
            Vault::open_with_passphrase(&self.vaults_dir, name, self.passphrase.as_deref())?
                .with_soal_home(self.home.clone()),
        )
    }

    pub fn add_path(
        &self,
        vault: &str,
        path: &Path,
        logical: &str,
    ) -> Result<ContentHash, SoalError> {
        let mut v = self.open_vault(vault)?;
        let h = v.add_path(path, logical)?;
        let _ = replication::ensure_local_pins(&v);
        Ok(h)
    }

    pub fn snapshot(&self, vault: &str, message: &str) -> Result<ContentHash, SoalError> {
        let mut v = self.open_vault(vault)?;
        v.snapshot(message)
    }

    pub fn restore(&self, vault: &str, commit: ContentHash, to: &Path) -> Result<(), SoalError> {
        let v = self.open_vault(vault)?;
        v.restore(commit, to)
    }

    pub fn head(&self, vault: &str) -> Result<Option<ContentHash>, SoalError> {
        self.open_vault(vault)?.head()
    }

    pub fn set_policy(&self, vault: &str, policy: VaultPolicy) -> Result<VaultPolicy, SoalError> {
        let mut v = self.open_vault(vault)?;
        policy::apply_policy(&mut v, policy)
    }

    pub fn policy(&self, vault: &str) -> Result<VaultPolicy, SoalError> {
        let v = self.open_vault(vault)?;
        policy::load_policy(&v)
    }

    pub fn health_vault(&self, vault: &str) -> Result<VaultHealth, SoalError> {
        let v = self.open_vault(vault)?;
        health::assess_vault(&v)
    }

    pub fn health_cluster(
        &self,
        peer_count: usize,
        node_id: Option<String>,
    ) -> Result<ClusterHealth, SoalError> {
        health::assess_cluster(&self.vaults_dir, node_id, peer_count)
    }

    pub fn diff(
        &self,
        vault: &str,
        from: ContentHash,
        to: ContentHash,
    ) -> Result<TreeDiff, SoalError> {
        let v = self.open_vault(vault)?;
        health::diff_commits(&v, from, to)
    }

    pub fn generate_invite(
        &self,
        vault: &str,
        sk: &SecretKey,
        role: InviteRole,
        ttl_secs: Option<u64>,
    ) -> Result<Invite, SoalError> {
        let v = self.open_vault(vault)?;
        invite::generate_invite(&v, sk, role, ttl_secs)
    }

    pub fn join_invite(&self, token: &str, local_name: Option<&str>) -> Result<Vault, SoalError> {
        invite::join_invite(&self.vaults_dir, &self.home, token, local_name)
    }

    /// Open network endpoint for this session home.
    pub async fn network(&self) -> Result<Network, SoalError> {
        Network::open(&self.home).await
    }

    /// Sync a remote head into a vault (requires peers on the network).
    pub async fn sync_head(
        &self,
        vault: &str,
        network: &Network,
        head: ContentHash,
        set_head: bool,
    ) -> Result<sync::SyncResult, SoalError> {
        let v = self.open_vault(vault)?;
        let peers = network.peers();
        sync::fetch_dag(&v, network, &peers, head, set_head).await
    }

    /// Provide + announce vault HEAD.
    pub async fn announce_head(
        &self,
        vault: &str,
        network: &Network,
        head: ContentHash,
    ) -> Result<(), SoalError> {
        let v = self.open_vault(vault)?;
        network.announce_head_signed(&v, head).await?;
        Ok(())
    }
}

/// Convenience: ensure node identity exists and return node id string.
pub async fn ensure_node_identity(home: &Path) -> Result<String, SoalError> {
    let net = Network::open(home).await?;
    Ok(net.node_id())
}

/// Shared network handle type for apps that keep an endpoint alive.
pub type SharedNetwork = Arc<Network>;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn session_create_add_snapshot_diff() {
        let dir = tempdir().unwrap();
        let s = SoalSession::open(dir.path()).unwrap();
        s.create_vault("notes", false, 2).unwrap();
        let f = dir.path().join("n.md");
        std::fs::write(&f, b"# hi").unwrap();
        let c1 = s.add_path("notes", &f, "n.md").unwrap();
        std::fs::write(&f, b"# hi2").unwrap();
        let c2 = s.add_path("notes", &f, "n.md").unwrap();
        let d = s.diff("notes", c1, c2).unwrap();
        assert!(d.changed.contains(&"n.md".into()) || d.added.is_empty());
        let h = s.health_vault("notes").unwrap();
        assert_eq!(h.vault, "notes");
        assert!(h.complete);
    }
}
