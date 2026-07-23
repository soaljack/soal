//! Replication engine (PR-09): ensure min_replicas policy via provide + pin tracking.
//!
//! Phase 1 model:
//! - Local pin set under `vault/pins.json` (chunk CIDs we commit to keep).
//! - `ensure_local_pins` marks all live HEAD chunks as pinned.
//! - `replicate_head` re-provides the full commit DAG to the network so peers
//!   can pull (self-heal distribution). Peer-side replica counts are estimated
//!   from last-known have-announcements when available.
//! - `replication_status` reports live chunk counts vs `min_replicas`.

use crate::network::Network;
use crate::vault::Vault;
use crate::{ContentHash, SoalError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const PINS_FILE: &str = "pins.json";
const REPLICA_DIR: &str = "replication";

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PinSet {
    /// Chunk / object CIDs this node pins.
    pub pins: BTreeSet<String>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct PeerHave {
    /// peer_id → set of hex CIDs they announced having.
    peers: BTreeMap<String, BTreeSet<String>>,
    updated_at: u64,
}

#[derive(Clone, Debug)]
pub struct ReplicationStatus {
    pub min_replicas: u8,
    pub live_chunks: usize,
    pub pinned_chunks: usize,
    pub missing_local: usize,
    pub estimated_under_replicated: usize,
    pub peers_known: usize,
}

fn pins_path(vault: &Vault) -> PathBuf {
    vault.root.join(PINS_FILE)
}

fn have_path(vault: &Vault) -> PathBuf {
    vault.root.join(REPLICA_DIR).join("peer_have.json")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn load_pins(vault: &Vault) -> Result<PinSet, SoalError> {
    let path = pins_path(vault);
    if !path.exists() {
        return Ok(PinSet::default());
    }
    let s = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&s)?)
}

pub fn save_pins(vault: &Vault, pins: &PinSet) -> Result<(), SoalError> {
    let path = pins_path(vault);
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(pins)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

/// Pin every chunk reachable from HEAD (mark phase of local retention).
pub fn ensure_local_pins(vault: &Vault) -> Result<usize, SoalError> {
    let live = vault.live_chunk_hashes()?;
    let mut pins = load_pins(vault)?;
    let before = pins.pins.len();
    for h in &live {
        pins.pins.insert(h.to_hex());
    }
    pins.updated_at = now_secs();
    save_pins(vault, &pins)?;
    Ok(pins.pins.len().saturating_sub(before))
}

/// Record that a peer has a set of CIDs (from gossip / sync).
pub fn note_peer_has(vault: &Vault, peer_id: &str, cids: &[ContentHash]) -> Result<(), SoalError> {
    let path = have_path(vault);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut have = if path.exists() {
        serde_json::from_str(&fs::read_to_string(&path)?)?
    } else {
        PeerHave::default()
    };
    let entry = have.peers.entry(peer_id.to_string()).or_default();
    for c in cids {
        entry.insert(c.to_hex());
    }
    have.updated_at = now_secs();
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(&have)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn load_have(vault: &Vault) -> PeerHave {
    let path = have_path(vault);
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Estimate replica count for a CID: local + peers who announced it.
pub fn estimated_replicas(vault: &Vault, cid: &ContentHash) -> usize {
    let mut n =
        if vault.has_chunk(cid) || vault.has_tree_object(cid) || vault.has_commit_object(cid) {
            1
        } else {
            0
        };
    let have = load_have(vault);
    let hex = cid.to_hex();
    for set in have.peers.values() {
        if set.contains(&hex) {
            n += 1;
        }
    }
    n
}

/// Status summary for CLI / health.
pub fn replication_status(vault: &Vault) -> Result<ReplicationStatus, SoalError> {
    let live = vault.live_chunk_hashes()?;
    let pins = load_pins(vault)?;
    let have = load_have(vault);
    let min = vault.config.min_replicas as usize;
    let mut under = 0usize;
    let mut missing_local = 0usize;
    for h in &live {
        if !vault.has_chunk(h) {
            missing_local += 1;
        }
        if estimated_replicas(vault, h) < min {
            under += 1;
        }
    }
    Ok(ReplicationStatus {
        min_replicas: vault.config.min_replicas,
        live_chunks: live.len(),
        pinned_chunks: pins.pins.len(),
        missing_local,
        estimated_under_replicated: under,
        peers_known: have.peers.len(),
    })
}

/// Self-heal: pin live data and re-provide HEAD DAG so peers can pull replicas.
///
/// Returns number of blobs provided to the network.
pub async fn replicate_head(vault: &Vault, network: &Network) -> Result<usize, SoalError> {
    ensure_local_pins(vault)?;
    let Some(head) = vault.head()? else {
        return Ok(0);
    };
    // Record ourselves as having these CIDs.
    let items = vault.collect_provide_hashes(head)?;
    let cids: Vec<ContentHash> = items.iter().map(|(h, _)| *h).collect();
    note_peer_has(vault, &network.node_id(), &cids)?;

    let n = network.provide_from_vault(vault, head).await?;

    // Best-effort signed announce so peers know to pull.
    let _ = network.announce_head_signed(vault, head).await;
    Ok(n)
}

/// Check which live chunks are below min_replicas.
pub fn under_replicated_chunks(vault: &Vault) -> Result<Vec<ContentHash>, SoalError> {
    let live = vault.live_chunk_hashes()?;
    let min = vault.config.min_replicas as usize;
    let mut out = Vec::new();
    for h in live {
        if estimated_replicas(vault, &h) < min {
            out.push(h);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn pin_and_status_local() {
        let dir = tempdir().unwrap();
        let mut v = Vault::create(dir.path(), "r", false).unwrap();
        let f = dir.path().join("a.txt");
        fs::write(&f, b"replica data").unwrap();
        let _ = v.add_path(&f, "a.txt").unwrap();
        let added = ensure_local_pins(&v).unwrap();
        assert!(added >= 1);
        let st = replication_status(&v).unwrap();
        assert_eq!(st.min_replicas, 2);
        assert!(st.live_chunks >= 1);
        assert!(st.pinned_chunks >= 1);
        // Only local replica → under-replicated vs min=2
        assert!(st.estimated_under_replicated >= 1);
    }

    #[test]
    fn note_peer_increases_estimate() {
        let dir = tempdir().unwrap();
        let mut v = Vault::create(dir.path(), "r2", false).unwrap();
        let f = dir.path().join("b.txt");
        fs::write(&f, b"more").unwrap();
        let _ = v.add_path(&f, "b.txt").unwrap();
        let live: Vec<_> = v.live_chunk_hashes().unwrap().into_iter().collect();
        assert!(!live.is_empty());
        let h = live[0];
        assert_eq!(estimated_replicas(&v, &h), 1);
        note_peer_has(&v, "peer-aaa", &[h]).unwrap();
        assert_eq!(estimated_replicas(&v, &h), 2);
    }
}
