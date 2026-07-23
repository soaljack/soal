//! Replication engine (PR-09 / Phase 2 placement): ensure min_replicas policy
//! via provide + pin tracking + peer scoring.
//!
//! - Local pin set under `vault/pins.json` (chunk CIDs we commit to keep).
//! - `ensure_local_pins` marks all live HEAD chunks as pinned.
//! - `replicate_head` re-provides the full commit DAG so peers can pull.
//! - Placement: rank peers by prefer_nodes, recency, and content possession.

use crate::network::Network;
use crate::policy::VaultPolicy;
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

// ---------------------------------------------------------------------------
// Placement-aware peer scoring (Phase 2)
// ---------------------------------------------------------------------------

/// Ranked peer for pull/push placement.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PeerScore {
    pub peer: String,
    pub score: i64,
    pub preferred: bool,
    pub last_seen_secs_ago: Option<u64>,
    pub has_head: bool,
    pub alive: Option<bool>,
}

/// Score peers for a vault given policy prefer_nodes + have-lists + health.
///
/// Higher score is better. Sort is descending by score.
pub fn rank_peers(
    vault: &Vault,
    policy: &VaultPolicy,
    peers: &[String],
    peer_last_seen: &BTreeMap<String, u64>,
    peer_alive: &BTreeMap<String, bool>,
    now: u64,
) -> Vec<PeerScore> {
    let have = load_have(vault);
    let head_hex = vault
        .head()
        .ok()
        .flatten()
        .map(|h| h.to_hex())
        .unwrap_or_default();

    let mut ranked: Vec<PeerScore> = peers
        .iter()
        .map(|peer| {
            let id_part = peer_id_key(peer);
            let preferred = policy.prefer_nodes.iter().any(|p| {
                peer.eq_ignore_ascii_case(p)
                    || id_part.eq_ignore_ascii_case(p)
                    || peer.contains(p.as_str())
            });
            let mut score: i64 = 0;
            if preferred {
                score += 1000;
            }
            let last = peer_last_seen
                .get(peer)
                .or_else(|| peer_last_seen.get(&id_part))
                .copied();
            let last_seen_secs_ago = last.map(|t| now.saturating_sub(t));
            if let Some(ago) = last_seen_secs_ago {
                // Fresher is better; 0s → +100, 1h → ~0, older negative.
                score += 100 - (ago as i64 / 36).min(200);
            } else {
                score -= 20; // never seen
            }
            let alive = peer_alive
                .get(peer)
                .or_else(|| peer_alive.get(&id_part))
                .copied();
            match alive {
                Some(true) => score += 200,
                Some(false) => score -= 300,
                None => {}
            }
            let has_head = !head_hex.is_empty()
                && have
                    .peers
                    .get(&id_part)
                    .or_else(|| have.peers.get(peer))
                    .map(|s| s.contains(&head_hex))
                    .unwrap_or(false);
            if has_head {
                score += 50;
            }
            PeerScore {
                peer: peer.clone(),
                score,
                preferred,
                last_seen_secs_ago,
                has_head,
                alive,
            }
        })
        .collect();

    ranked.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.peer.cmp(&b.peer)));
    ranked
}

/// Extract a stable key from ticket or bare id (prefer bare hex/id if present).
fn peer_id_key(peer: &str) -> String {
    // Tickets are long; bare EndpointId is 64 hex. Keep as-is for matching.
    peer.trim().to_string()
}

/// Order a peer list for failover using placement scores.
pub fn ordered_peers_for_sync(
    vault: &Vault,
    policy: &VaultPolicy,
    peers: &[String],
    peer_last_seen: &BTreeMap<String, u64>,
    peer_alive: &BTreeMap<String, bool>,
) -> Vec<String> {
    rank_peers(vault, policy, peers, peer_last_seen, peer_alive, now_secs())
        .into_iter()
        .map(|p| p.peer)
        .collect()
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

    #[test]
    fn rank_peers_prefers_policy_and_alive() {
        let dir = tempdir().unwrap();
        let v = Vault::create(dir.path(), "r3", false).unwrap();
        let policy = VaultPolicy {
            prefer_nodes: vec!["preferred-peer".into()],
            ..VaultPolicy::default()
        };
        let peers = vec![
            "other-peer".into(),
            "preferred-peer".into(),
            "dead-peer".into(),
        ];
        let mut last = BTreeMap::new();
        last.insert("preferred-peer".into(), now_secs());
        last.insert("other-peer".into(), now_secs().saturating_sub(10_000));
        let mut alive = BTreeMap::new();
        alive.insert("preferred-peer".into(), true);
        alive.insert("other-peer".into(), true);
        alive.insert("dead-peer".into(), false);
        let ranked = rank_peers(&v, &policy, &peers, &last, &alive, now_secs());
        assert_eq!(ranked[0].peer, "preferred-peer");
        assert!(ranked[0].score > ranked[1].score);
        assert_eq!(ranked.last().unwrap().peer, "dead-peer");
    }
}
