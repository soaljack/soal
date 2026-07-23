//! SyncEngine: DAG fetch with peer failover and checkpoint resume (PR-07b).
//!
//! Walks commit parents → trees → chunks, verifying every blob
//! (`BLAKE3(bytes) == cid`) before import. Checkpoints under
//! `vault/sync/jobs/{head}.json` so interrupted syncs can resume (INV-SYNC-02).

use crate::codec::MAX_JOB_COMMITS;
use crate::commit::Commit;
use crate::identity;
use crate::network::Network;
use crate::vault::Vault;
use crate::{ContentHash, SoalError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const SYNC_DIR: &str = "sync";
const JOBS_DIR: &str = "jobs";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    Fetching,
    Verifying,
    Done,
    Failed,
}

/// Checkpoint for a single target-head sync job.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncJob {
    pub target: ContentHash,
    pub epoch: u64,
    pub state: SyncState,
    pub done_commits: BTreeSet<ContentHash>,
    pub done_trees: BTreeSet<ContentHash>,
    pub done_chunks: BTreeSet<ContentHash>,
    pub updated_at: u64,
    #[serde(default)]
    pub error: Option<String>,
}

impl SyncJob {
    fn new(target: ContentHash) -> Self {
        Self {
            target,
            epoch: now_secs(),
            state: SyncState::Fetching,
            done_commits: BTreeSet::new(),
            done_trees: BTreeSet::new(),
            done_chunks: BTreeSet::new(),
            updated_at: now_secs(),
            error: None,
        }
    }

    fn touch(&mut self) {
        self.updated_at = now_secs();
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn job_path(vault: &Vault, target: &ContentHash) -> PathBuf {
    vault
        .root
        .join(SYNC_DIR)
        .join(JOBS_DIR)
        .join(format!("{}.json", target.to_hex()))
}

fn load_or_create_job(vault: &Vault, target: ContentHash) -> Result<SyncJob, SoalError> {
    let path = job_path(vault, &target);
    if path.exists() {
        let s = fs::read_to_string(&path)?;
        if let Ok(job) = serde_json::from_str::<SyncJob>(&s) {
            if job.target == target && job.state != SyncState::Done {
                return Ok(job);
            }
        }
    }
    Ok(SyncJob::new(target))
}

fn persist_job(vault: &Vault, job: &SyncJob) -> Result<(), SoalError> {
    let path = job_path(vault, &job.target);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(job)?)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Result of a successful DAG sync.
#[derive(Debug)]
pub struct SyncResult {
    pub target: ContentHash,
    pub commits_imported: usize,
    pub trees_imported: usize,
    pub chunks_imported: usize,
    pub head_updated: bool,
}

/// Fetch a complete commit DAG (target + parents) with peer failover.
pub async fn fetch_dag(
    vault: &Vault,
    network: &Network,
    peers: &[String],
    target: ContentHash,
    set_head: bool,
) -> Result<SyncResult, SoalError> {
    if peers.is_empty() {
        return Err(SoalError::Other("no peers for sync".into()));
    }

    // Fast path: already complete
    if vault.is_complete(target)? {
        if set_head {
            vault.set_head_public(target)?;
        }
        return Ok(SyncResult {
            target,
            commits_imported: 0,
            trees_imported: 0,
            chunks_imported: 0,
            head_updated: set_head,
        });
    }

    let mut job = load_or_create_job(vault, target)?;
    job.state = SyncState::Fetching;
    job.touch();
    persist_job(vault, &job)?;

    let mut queue: VecDeque<ContentHash> = VecDeque::new();
    queue.push_back(target);
    let mut visited = BTreeSet::new();
    let mut commits_imported = 0usize;
    let mut trees_imported = 0usize;
    let mut chunks_imported = 0usize;

    let result = async {
        while let Some(c) = queue.pop_front() {
            if visited.len() > MAX_JOB_COMMITS {
                return Err(SoalError::Other("DAG too deep (MAX_JOB_COMMITS)".into()));
            }
            if !visited.insert(c) {
                continue;
            }

            // Commit
            if !job.done_commits.contains(&c) {
                if !vault.has_commit_object(&c) {
                    let (_peer, bytes) = network.get_blob_with_failover(peers, c).await?;
                    // verify checklist via import (CID + domain + sig)
                    vault.import_commit_bytes(c, &bytes)?;
                    commits_imported += 1;
                } else {
                    // still verify signature on existing
                    let commit = vault.load_commit(c)?;
                    identity::verify_commit_signature(&commit)?;
                }
                job.done_commits.insert(c);
                job.touch();
                persist_job(vault, &job)?;
            }

            let commit: Commit = vault.load_commit(c)?;
            for p in &commit.parents {
                queue.push_back(*p);
            }

            // Tree
            let tree_cid = commit.tree;
            if !job.done_trees.contains(&tree_cid) {
                if !vault.has_tree_object(&tree_cid) {
                    let (_peer, bytes) = network.get_blob_with_failover(peers, tree_cid).await?;
                    vault.import_tree_bytes(tree_cid, &bytes)?;
                    trees_imported += 1;
                }
                job.done_trees.insert(tree_cid);
                job.touch();
                persist_job(vault, &job)?;
            }

            let tree = vault.load_tree(tree_cid)?;
            for ch in tree.all_chunk_hashes() {
                if job.done_chunks.contains(&ch) {
                    continue;
                }
                if !vault.has_chunk(&ch) {
                    let (_peer, bytes) = network.get_blob_with_failover(peers, ch).await?;
                    vault.import_stored_chunk(ch, &bytes)?;
                    chunks_imported += 1;
                }
                job.done_chunks.insert(ch);
                // checkpoint every 32 chunks
                if job.done_chunks.len() % 32 == 0 {
                    job.touch();
                    persist_job(vault, &job)?;
                }
            }
        }

        job.state = SyncState::Verifying;
        job.touch();
        persist_job(vault, &job)?;

        if !vault.is_complete(target)? {
            return Err(SoalError::Verify(
                "sync finished but target not complete".into(),
            ));
        }

        let mut head_updated = false;
        if set_head {
            vault.set_head_public(target)?;
            head_updated = true;
        }

        job.state = SyncState::Done;
        job.touch();
        persist_job(vault, &job)?;

        Ok(SyncResult {
            target,
            commits_imported,
            trees_imported,
            chunks_imported,
            head_updated,
        })
    }
    .await;

    if let Err(ref e) = result {
        job.state = SyncState::Failed;
        job.error = Some(e.to_string());
        job.touch();
        let _ = persist_job(vault, &job);
    }
    result
}

/// Convenience: sync one head from network peers into vault.
pub async fn sync_head(
    vault: &Vault,
    network: &Network,
    target: ContentHash,
) -> Result<SyncResult, SoalError> {
    let peers = network.peers();
    fetch_dag(vault, network, &peers, target, true).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn job_checkpoint_roundtrip() {
        let dir = tempdir().unwrap();
        let v = Vault::create(dir.path(), "j", false).unwrap();
        let target = ContentHash::from([1u8; 32]);
        let mut job = SyncJob::new(target);
        job.done_commits.insert(target);
        persist_job(&v, &job).unwrap();
        let loaded = load_or_create_job(&v, target).unwrap();
        assert!(loaded.done_commits.contains(&target));
        assert_eq!(loaded.target, target);
    }

    #[test]
    fn is_complete_false_empty() {
        let dir = tempdir().unwrap();
        let v = Vault::create(dir.path(), "c", false).unwrap();
        assert!(!v.is_complete(ContentHash::from([2u8; 32])).unwrap());
    }

    #[tokio::test]
    async fn local_export_import_complete_via_resolve() {
        let dir = tempdir().unwrap();
        let mut a = Vault::create(dir.path(), "a", false).unwrap();
        let f = dir.path().join("f.txt");
        fs::write(&f, b"sync engine local").unwrap();
        let c = a.add_path(&f, "f.txt").unwrap();
        assert!(a.is_complete(c).unwrap());

        // Create B with shared empty key path (no encrypt)
        let bdir = tempdir().unwrap();
        let b = Vault::create_for_test(bdir.path(), "b", false, [1u8; 16], None, vec![]).unwrap();
        // Manual transfer of all provide hashes
        let items = a.collect_provide_hashes(c).unwrap();
        for (h, bytes) in items {
            if h == c {
                b.import_commit_bytes(h, &bytes).unwrap();
            } else if bytes.len() >= 16 && bytes[..16] == crate::codec::DOMAIN_TREE {
                b.import_tree_bytes(h, &bytes).unwrap();
            } else if bytes.len() >= 16 && bytes[..16] == crate::codec::DOMAIN_COMMIT {
                b.import_commit_bytes(h, &bytes).unwrap();
            } else {
                b.import_stored_chunk(h, &bytes).unwrap();
            }
        }
        assert!(b.is_complete(c).unwrap());
    }
}
