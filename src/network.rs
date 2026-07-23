//! Phase 1 networking: persistent node identity, peer list, signed head
//! announcements (vault_id topics), and iroh-blobs content transfer.
//!
//! Design (v0.2):
//! - Node identity (ed25519 / Iroh SecretKey) is **persistent** under `~/.soal/`.
//! - Peers are **persisted** across CLI invocations.
//! - HeadAnnouncement is **signed** CBOR (INV-SIG-02); topic = vault_id (KD-08).
//! - Per-node announce `seq` persists for INV-REPLAY-01.
//! - `provide` verifies BLAKE3 of data matches the claimed content hash.
//! - Vault CAS hybrid: re-load wire objects from vault disk into the blob store
//!   before announce (PR-07a durable serve without empty MemStore after restart).

use crate::codec::{
    self, decode_head_announcement, encode_head_announcement, vault_topic_hash, HeadAnnouncement,
    VAULT_ID_LEN,
};
use crate::identity;
use crate::vault::Vault;
use crate::{ContentHash, SoalError};
use futures_lite::StreamExt;
use iroh::endpoint::presets::N0;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, SecretKey};
use iroh_blobs::get::request::get_blob;
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::BlobsProtocol;
use iroh_gossip::api::Event as GossipEvent;
use iroh_gossip::net::Gossip;
use iroh_tickets::endpoint::EndpointTicket;
use iroh_tickets::Ticket;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NODE_STATE_FILE: &str = "node.json";
const SEQ_DIR: &str = "seq";

/// On-disk node state: secret key + known peers + last announce seqs we **sent**.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct NodeState {
    /// Hex-encoded 32-byte secret key.
    secret_key_hex: String,
    /// Sorted unique peer endpoint IDs (string form).
    peers: BTreeSet<String>,
    /// vault_id_hex → last seq we announced (local outbound).
    #[serde(default)]
    announce_seq: BTreeMap<String, u64>,
}

impl NodeState {
    fn path(home: &Path) -> PathBuf {
        home.join(NODE_STATE_FILE)
    }

    fn load_or_create(home: &Path) -> Result<Self, SoalError> {
        fs::create_dir_all(home)?;
        let path = Self::path(home);
        if path.exists() {
            let s = fs::read_to_string(&path)?;
            let state: NodeState = serde_json::from_str(&s)?;
            if state.secret_key_hex.is_empty() {
                return Err(SoalError::Other("node.json missing secret key".into()));
            }
            return Ok(state);
        }
        let sk = SecretKey::generate();
        let state = NodeState {
            secret_key_hex: hex::encode(sk.to_bytes()),
            peers: BTreeSet::new(),
            announce_seq: BTreeMap::new(),
        };
        state.save(home)?;
        Ok(state)
    }

    fn save(&self, home: &Path) -> Result<(), SoalError> {
        fs::create_dir_all(home)?;
        let path = Self::path(home);
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        fs::rename(&tmp, &path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn secret_key(&self) -> Result<SecretKey, SoalError> {
        let bytes = hex::decode(&self.secret_key_hex)
            .map_err(|_| SoalError::Other("invalid secret key hex".into()))?;
        if bytes.len() != 32 {
            return Err(SoalError::Other("secret key must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(SecretKey::from_bytes(&arr))
    }
}

/// Persist last **received** announce seq for (vault_id, node_id) — INV-REPLAY-01.
fn last_recv_seq_path(home: &Path, vault_id_hex: &str, node_id_hex: &str) -> PathBuf {
    home.join(SEQ_DIR)
        .join(vault_id_hex)
        .join(format!("{node_id_hex}.seq"))
}

fn load_last_recv_seq(home: &Path, vault_id_hex: &str, node_id_hex: &str) -> u64 {
    let path = last_recv_seq_path(home, vault_id_hex, node_id_hex);
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn store_last_recv_seq(
    home: &Path,
    vault_id_hex: &str,
    node_id_hex: &str,
    seq: u64,
) -> Result<(), SoalError> {
    let path = last_recv_seq_path(home, vault_id_hex, node_id_hex);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("seq.tmp");
    fs::write(&tmp, seq.to_string())?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

pub struct Network {
    pub endpoint: Endpoint,
    pub gossip: Arc<Gossip>,
    home: PathBuf,
    peers: BTreeSet<String>,
    blobs: BlobsProtocol,
    // Keep router alive to serve blobs protocol
    _router: Arc<Router>,
    secret: SecretKey,
}

impl Network {
    /// Open (or create) a network endpoint with persistent identity under `soal_home`.
    pub async fn open(soal_home: &Path) -> Result<Self, SoalError> {
        let state = NodeState::load_or_create(soal_home)?;
        let secret = state.secret_key()?;

        let endpoint = Endpoint::builder(N0)
            .secret_key(secret.clone())
            .bind()
            .await
            .map_err(|e| SoalError::Other(format!("endpoint: {e}")))?;

        // Best-effort: wait briefly for relay/home so tickets include dialable addrs.
        let _ = tokio::time::timeout(Duration::from_secs(3), endpoint.online()).await;

        let gossip = Gossip::builder().spawn(endpoint.clone());

        // MemStore holds currently provided blobs; vault CAS is re-loaded via
        // `provide_from_vault` before announce (durable hybrid — PR-07a).
        let mem_store = MemStore::new();
        let blobs = BlobsProtocol::new(&mem_store, None);

        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs.clone())
            .spawn();

        Ok(Self {
            endpoint,
            gossip: Arc::new(gossip),
            home: soal_home.to_path_buf(),
            peers: state.peers,
            blobs,
            _router: Arc::new(router),
            secret,
        })
    }

    /// Ephemeral network (tests / one-shots that do not need persistence).
    pub async fn ephemeral() -> Result<Self, SoalError> {
        let dir = std::env::temp_dir().join(format!(
            "soal-ephemeral-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        Self::open(&dir).await
    }

    pub fn node_id(&self) -> String {
        self.endpoint.id().to_string()
    }

    /// Current dialable address as an iroh EndpointTicket string.
    ///
    /// Prefer exchanging **tickets** (includes relay/direct addrs) over bare
    /// EndpointIds so multi-process / LAN peers can connect without discovery.
    pub fn ticket(&self) -> String {
        let addr = self.endpoint.addr();
        EndpointTicket::new(addr).encode_string()
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    fn persist_peers(&self) -> Result<(), SoalError> {
        let mut state = NodeState::load_or_create(&self.home)?;
        state.peers = self.peers.clone();
        state.save(&self.home)
    }

    /// Parse a peer string as EndpointTicket or bare EndpointId → EndpointAddr.
    pub fn parse_peer_addr(peer: &str) -> Result<EndpointAddr, SoalError> {
        let peer = peer.trim();
        if peer.is_empty() {
            return Err(SoalError::Other("empty peer id".into()));
        }
        if let Ok(ticket) = peer.parse::<EndpointTicket>() {
            return Ok(ticket.endpoint_addr().clone());
        }
        let id: iroh::EndpointId = peer
            .parse()
            .map_err(|e| SoalError::Other(format!("invalid peer id or ticket: {e}")))?;
        Ok(EndpointAddr::from(id))
    }

    pub fn add_peer(&mut self, peer: String) -> Result<(), SoalError> {
        let peer = peer.trim().to_string();
        // Validate early
        let _addr = Self::parse_peer_addr(&peer)?;
        self.peers.insert(peer);
        self.persist_peers()?;
        Ok(())
    }

    pub fn remove_peer(&mut self, peer: &str) -> Result<bool, SoalError> {
        let removed = self.peers.remove(peer);
        if removed {
            self.persist_peers()?;
        }
        Ok(removed)
    }

    pub fn peers(&self) -> Vec<String> {
        self.peers.iter().cloned().collect()
    }

    /// Resolved dial addresses for configured peers (ticket → EndpointAddr).
    pub fn peer_addrs(&self) -> Vec<EndpointAddr> {
        self.peers
            .iter()
            .filter_map(|p| Self::parse_peer_addr(p).ok())
            .collect()
    }

    /// Make bytes available for peers via iroh-blobs.
    /// Verifies `ContentHash::of(data) == hash` before providing (INV-IROH-01).
    pub async fn provide(&self, hash: ContentHash, data: &[u8]) -> Result<(), SoalError> {
        if data.len() > codec::MAX_BLOB_BYTES {
            return Err(SoalError::Verify(format!(
                "blob exceeds MAX_BLOB_BYTES ({})",
                codec::MAX_BLOB_BYTES
            )));
        }
        let actual = ContentHash::of(data);
        if actual != hash {
            return Err(SoalError::hash_mismatch(&hash, &actual));
        }
        let _tag = self
            .blobs
            .add_bytes(data.to_vec())
            .await
            .map_err(|e| SoalError::Other(format!("blobs provide: {e}")))?;
        Ok(())
    }

    /// Provide many (hash, bytes) pairs.
    pub async fn provide_many(&self, items: &[(ContentHash, Vec<u8>)]) -> Result<usize, SoalError> {
        let mut n = 0;
        for (h, data) in items {
            self.provide(*h, data).await?;
            n += 1;
        }
        Ok(n)
    }

    /// Load vault CAS objects for a commit DAG tip into the blob store (durable hybrid).
    ///
    /// Always re-reads from vault disk so a process restart can re-serve content
    /// without relying solely on MemStore contents.
    pub async fn provide_from_vault(
        &self,
        vault: &Vault,
        commit_hash: ContentHash,
    ) -> Result<usize, SoalError> {
        let items = vault.collect_provide_hashes(commit_hash)?;
        self.provide_many(&items).await
    }

    fn next_announce_seq(&self, vault_id_hex: &str) -> Result<u64, SoalError> {
        let mut state = NodeState::load_or_create(&self.home)?;
        let next = state.announce_seq.get(vault_id_hex).copied().unwrap_or(0) + 1;
        state.announce_seq.insert(vault_id_hex.to_string(), next);
        state.save(&self.home)?;
        Ok(next)
    }

    /// Announce a vault HEAD with a signed HeadAnnouncement (INV-SIG-02).
    ///
    /// Topic = BLAKE3("soal/v1/vault/" || vault_id) (KD-08).
    pub async fn announce_head_signed(
        &self,
        vault: &Vault,
        head: ContentHash,
    ) -> Result<HeadAnnouncement, SoalError> {
        // Durable provide first so peers can fetch immediately after gossip.
        let n = self.provide_from_vault(vault, head).await?;
        println!("[network] Provided {n} blobs from vault CAS");

        let vault_id = vault.vault_id_bytes()?;
        let vault_id_hex = hex::encode(vault_id);
        let seq = self.next_announce_seq(&vault_id_hex)?;
        let ann = identity::sign_head_announcement(
            &self.secret,
            vault_id,
            &vault.name,
            head,
            seq,
            vault.config.config_seq,
        )?;

        self.broadcast_announcement(&ann).await?;
        println!(
            "[network] Broadcast signed head for {} (vault_id={}, seq={}): {}",
            vault.name,
            &vault_id_hex[..8.min(vault_id_hex.len())],
            seq,
            head.to_hex()
        );
        Ok(ann)
    }

    /// Low-level broadcast of an already-signed announcement.
    pub async fn broadcast_announcement(&self, ann: &HeadAnnouncement) -> Result<(), SoalError> {
        let topic_hash = vault_topic_hash(&ann.vault_id);
        let topic_id: iroh_gossip::proto::TopicId = topic_hash.0.into();

        let bootstrap: Vec<_> = self.peers.iter().filter_map(|s| s.parse().ok()).collect();
        let mut topic = self
            .gossip
            .subscribe(topic_id, bootstrap)
            .await
            .map_err(|e| SoalError::Other(format!("subscribe: {e}")))?;

        let msg = encode_head_announcement(ann)
            .map_err(|e| SoalError::Other(e.to_string()))?
            .into();

        topic
            .broadcast(msg)
            .await
            .map_err(|e| SoalError::Other(format!("broadcast: {e}")))?;
        Ok(())
    }

    /// Backward-compatible announce by vault name string + head hex (loads vault externally).
    pub async fn announce_head(&self, vault_name: &str, head: &str) -> Result<(), SoalError> {
        // Minimal path for CLI when only name/head given: build unsigned-era
        // topic from name hash for legacy listeners, but prefer signed path.
        let topic_id: iroh_gossip::proto::TopicId = blake3::hash(vault_name.as_bytes()).into();
        let bootstrap: Vec<_> = self.peers.iter().filter_map(|s| s.parse().ok()).collect();
        let mut topic = self
            .gossip
            .subscribe(topic_id, bootstrap)
            .await
            .map_err(|e| SoalError::Other(format!("subscribe: {e}")))?;

        // Prefer signed CBOR if we can parse head + have a synthetic vault_id from name
        let head_hash = ContentHash::from_hex(head).unwrap_or(ContentHash::ZERO);
        let vault_id = {
            let h = blake3::hash(vault_name.as_bytes());
            let mut id = [0u8; VAULT_ID_LEN];
            id.copy_from_slice(&h.as_bytes()[..VAULT_ID_LEN]);
            id
        };
        let vault_id_hex = hex::encode(vault_id);
        let seq = self.next_announce_seq(&vault_id_hex)?;
        let ann = identity::sign_head_announcement(
            &self.secret,
            vault_id,
            vault_name,
            head_hash,
            seq,
            1,
        )?;
        let msg = encode_head_announcement(&ann)?.into();
        topic
            .broadcast(msg)
            .await
            .map_err(|e| SoalError::Other(format!("broadcast: {e}")))?;
        println!("[network] Broadcast head for {vault_name}: {head}");
        Ok(())
    }

    /// Validate a received announcement (sig, skew, replay, optional membership).
    pub fn validate_announcement(
        &self,
        ann: &HeadAnnouncement,
        vault: Option<&Vault>,
    ) -> Result<(), SoalError> {
        identity::verify_head_announcement(ann)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        identity::check_head_skew(ann, now)?;

        if let Some(v) = vault {
            let local_id = v.vault_id_bytes()?;
            if local_id != ann.vault_id {
                return Err(SoalError::Verify("vault_id mismatch".into()));
            }
            let node_hex = ann.node_id_hex();
            if !v.is_member(&node_hex) {
                return Err(SoalError::Verify("announcer not a vault member".into()));
            }
        }

        let vault_id_hex = ann.vault_id_hex();
        let node_hex = ann.node_id_hex();
        let last = load_last_recv_seq(&self.home, &vault_id_hex, &node_hex);
        if ann.seq <= last {
            return Err(SoalError::Verify(format!(
                "replay: seq {} <= last {last}",
                ann.seq
            )));
        }
        store_last_recv_seq(&self.home, &vault_id_hex, &node_hex, ann.seq)?;
        Ok(())
    }

    /// Listen briefly for head announcements on a vault_id topic.
    pub async fn listen_for_heads_vault(
        &self,
        vault: &Vault,
    ) -> Result<Vec<HeadAnnouncement>, SoalError> {
        let vault_id = vault.vault_id_bytes()?;
        let topic_hash = vault_topic_hash(&vault_id);
        let topic_id: iroh_gossip::proto::TopicId = topic_hash.0.into();
        let bootstrap: Vec<_> = self.peers.iter().filter_map(|s| s.parse().ok()).collect();
        let topic = self
            .gossip
            .subscribe(topic_id, bootstrap)
            .await
            .map_err(|e| SoalError::Other(format!("listen subscribe: {e}")))?;

        println!(
            "[network] Listening for heads on vault {} (id={})",
            vault.name,
            &vault.config.vault_id[..8.min(vault.config.vault_id.len())]
        );

        let (_sender, mut receiver) = topic.split();
        let mut received = Vec::new();

        let short_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while tokio::time::Instant::now() < short_deadline {
            if let Ok(Some(Ok(GossipEvent::Received(ev)))) =
                tokio::time::timeout(std::time::Duration::from_millis(300), receiver.next()).await
            {
                match decode_head_announcement(&ev.content) {
                    Ok(ann) => match self.validate_announcement(&ann, Some(vault)) {
                        Ok(()) => {
                            println!(
                                "[network] RECEIVED signed head from {} for {}: {}",
                                ann.node_id_hex(),
                                ann.vault_name,
                                ann.head_hex()
                            );
                            if ann.node_id_hex() != self.node_id() {
                                println!(
                                    "[network]   (add peer with: soal node add-peer {})",
                                    ann.node_id_hex()
                                );
                            }
                            received.push(ann);
                        }
                        Err(e) => {
                            println!("[network] rejected announcement: {e}");
                        }
                    },
                    Err(e) => {
                        println!("[network] bad announcement CBOR: {e}");
                    }
                }
            }
        }
        Ok(received)
    }

    /// Legacy listen by vault **name** (name-hash topic) for older peers.
    pub async fn listen_for_heads(&self, vault: &str) -> Result<Vec<HeadAnnouncement>, SoalError> {
        let topic_id: iroh_gossip::proto::TopicId = blake3::hash(vault.as_bytes()).into();
        let bootstrap: Vec<_> = self.peers.iter().filter_map(|s| s.parse().ok()).collect();
        let topic = self
            .gossip
            .subscribe(topic_id, bootstrap)
            .await
            .map_err(|e| SoalError::Other(format!("listen subscribe: {e}")))?;

        println!("[network] Listening for heads on vault name {vault}");

        let (_sender, mut receiver) = topic.split();
        let mut received = Vec::new();

        let short_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while tokio::time::Instant::now() < short_deadline {
            if let Ok(Some(Ok(GossipEvent::Received(ev)))) =
                tokio::time::timeout(std::time::Duration::from_millis(300), receiver.next()).await
            {
                if let Ok(ann) = decode_head_announcement(&ev.content) {
                    if identity::verify_head_announcement(&ann).is_ok() {
                        println!(
                            "[network] RECEIVED head from {} for {}: {}",
                            ann.node_id_hex(),
                            ann.vault_name,
                            ann.head_hex()
                        );
                        received.push(ann);
                    }
                }
            }
        }
        Ok(received)
    }

    pub async fn sync_vault(&self, vault: &str) -> Result<(), SoalError> {
        println!("[network] Sync status for vault {vault}");
        if self.peers.is_empty() {
            println!("  (no peers; use `soal node add-peer <id>`)");
            return Ok(());
        }
        for peer in &self.peers {
            println!("  peer: {peer}");
        }
        Ok(())
    }

    /// Fetch a blob by content hash from a peer via iroh-blobs.
    ///
    /// `peer` may be an EndpointTicket (preferred) or bare EndpointId.
    pub async fn get_chunk_from_peer(
        &self,
        peer: &str,
        hash: ContentHash,
    ) -> Result<Vec<u8>, SoalError> {
        let addr = Self::parse_peer_addr(peer)?;

        let conn = self
            .endpoint
            .connect(addr, iroh_blobs::ALPN)
            .await
            .map_err(|e| SoalError::Other(format!("connect for blobs: {e}")))?;

        let bhash = iroh_blobs::Hash::from_bytes(hash.0);

        let bytes = get_blob(conn, bhash)
            .bytes()
            .await
            .map_err(|e| SoalError::Other(format!("get_blob: {e}")))?;

        let data = bytes.to_vec();
        if data.len() > codec::MAX_BLOB_BYTES {
            return Err(SoalError::Verify(
                "fetched blob exceeds MAX_BLOB_BYTES".into(),
            ));
        }
        let actual = ContentHash::of(&data);
        if actual != hash {
            return Err(SoalError::hash_mismatch(&hash, &actual));
        }
        Ok(data)
    }

    /// Fetch a blob trying peers in order until one succeeds (failover).
    pub async fn get_blob_with_failover(
        &self,
        peers: &[String],
        hash: ContentHash,
    ) -> Result<(String, Vec<u8>), SoalError> {
        let mut last_err = SoalError::Other("no peers".into());
        for peer in peers {
            match self.get_chunk_from_peer(peer, hash).await {
                Ok(data) => return Ok((peer.clone(), data)),
                Err(e) => {
                    last_err = e;
                }
            }
        }
        Err(SoalError::Other(format!(
            "unavailable {}: {last_err}",
            hash.to_hex()
        )))
    }

    /// Parse endpoint id string (for validation helpers).
    pub fn parse_endpoint_id(s: &str) -> Result<iroh::EndpointId, SoalError> {
        iroh::EndpointId::from_str(s).map_err(|e| SoalError::Other(format!("bad endpoint id: {e}")))
    }

    /// Well-known discovery topic: BLAKE3("soal/v1/discovery").
    fn discovery_topic_id() -> iroh_gossip::proto::TopicId {
        let h = blake3::hash(b"soal/v1/discovery");
        h.into()
    }

    /// Broadcast this node's ticket on the LAN/cluster discovery topic.
    pub async fn discovery_beacon(&self, duration: Duration) -> Result<(), SoalError> {
        let topic_id = Self::discovery_topic_id();
        let bootstrap: Vec<_> = self.peers.iter().filter_map(|s| s.parse().ok()).collect();
        let mut topic = self
            .gossip
            .subscribe(topic_id, bootstrap)
            .await
            .map_err(|e| SoalError::Other(format!("discovery subscribe: {e}")))?;

        let payload = format!("soal/discover/v1\n{}", self.ticket());
        let deadline = tokio::time::Instant::now() + duration;
        println!(
            "[network] Discovery beacon for {}s as {}",
            duration.as_secs(),
            self.node_id()
        );
        while tokio::time::Instant::now() < deadline {
            topic
                .broadcast(payload.clone().into())
                .await
                .map_err(|e| SoalError::Other(format!("beacon: {e}")))?;
            tokio::time::sleep(Duration::from_millis(800)).await;
        }
        Ok(())
    }

    /// Listen for discovery beacons; returns ticket strings of remote peers.
    pub async fn discovery_listen(&self, duration: Duration) -> Result<Vec<String>, SoalError> {
        let topic_id = Self::discovery_topic_id();
        let bootstrap: Vec<_> = self.peers.iter().filter_map(|s| s.parse().ok()).collect();
        let topic = self
            .gossip
            .subscribe(topic_id, bootstrap)
            .await
            .map_err(|e| SoalError::Other(format!("discovery listen: {e}")))?;

        println!("[network] Discovering peers for {}s…", duration.as_secs());
        let (_sender, mut receiver) = topic.split();
        let mut found = BTreeSet::new();
        let my_ticket = self.ticket();
        let my_id = self.node_id();
        let deadline = tokio::time::Instant::now() + duration;

        while tokio::time::Instant::now() < deadline {
            let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remain.is_zero() {
                break;
            }
            if let Ok(Some(Ok(GossipEvent::Received(ev)))) =
                tokio::time::timeout(remain.min(Duration::from_millis(500)), receiver.next()).await
            {
                if let Ok(text) = std::str::from_utf8(&ev.content) {
                    if let Some(ticket) = text.strip_prefix("soal/discover/v1\n") {
                        let ticket = ticket.trim();
                        if ticket != my_ticket
                            && !ticket.contains(&my_id)
                            && Self::parse_peer_addr(ticket).is_ok()
                        {
                            found.insert(ticket.to_string());
                        }
                    }
                }
            }
        }
        Ok(found.into_iter().collect())
    }

    /// Resolve a blob preferring in-memory provide, falling back to vault CAS (PR-07a native hybrid).
    pub async fn provide_resolved(
        &self,
        vault: &Vault,
        hash: ContentHash,
    ) -> Result<(), SoalError> {
        let data = vault.resolve_blob(hash)?;
        self.provide(hash, &data).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;
    use tempfile::tempdir;

    #[test]
    fn node_state_persists_identity() {
        let dir = tempdir().unwrap();
        let s1 = NodeState::load_or_create(dir.path()).unwrap();
        let s2 = NodeState::load_or_create(dir.path()).unwrap();
        assert_eq!(s1.secret_key_hex, s2.secret_key_hex);
        assert!(!s1.secret_key_hex.is_empty());
    }

    #[tokio::test]
    async fn network_open_stable_node_id() {
        let dir = tempdir().unwrap();
        let id1 = {
            let net = Network::open(dir.path()).await.unwrap();
            net.node_id()
        };
        let id2 = {
            let net = Network::open(dir.path()).await.unwrap();
            net.node_id()
        };
        assert_eq!(id1, id2, "node id must be stable across restarts");
        assert!(!id1.is_empty());
    }

    #[tokio::test]
    async fn provide_rejects_hash_mismatch() {
        let dir = tempdir().unwrap();
        let net = Network::open(dir.path()).await.unwrap();
        let data = b"hello";
        let wrong = ContentHash::of(b"nope");
        assert!(matches!(
            net.provide(wrong, data).await,
            Err(SoalError::HashMismatch { .. })
        ));
    }

    #[test]
    fn seq_store_atomic_and_replay() {
        let dir = tempdir().unwrap();
        store_last_recv_seq(dir.path(), "aabb", "node1", 5).unwrap();
        assert_eq!(load_last_recv_seq(dir.path(), "aabb", "node1"), 5);
        store_last_recv_seq(dir.path(), "aabb", "node1", 6).unwrap();
        assert_eq!(load_last_recv_seq(dir.path(), "aabb", "node1"), 6);
    }

    #[tokio::test]
    async fn validate_announcement_sig_and_replay() {
        let dir = tempdir().unwrap();
        let net = Network::open(dir.path()).await.unwrap();
        let sk = net.secret_key().clone();
        let head = ContentHash::from([3u8; 32]);
        let ann = identity::sign_head_announcement(&sk, [9u8; 16], "v", head, 1, 1).unwrap();
        net.validate_announcement(&ann, None).unwrap();
        // same seq again → replay
        assert!(net.validate_announcement(&ann, None).is_err());
        let ann2 = identity::sign_head_announcement(&sk, [9u8; 16], "v", head, 2, 1).unwrap();
        net.validate_announcement(&ann2, None).unwrap();
    }

    #[tokio::test]
    async fn ticket_roundtrip_and_peer_parse() {
        let dir = tempdir().unwrap();
        let net = Network::open(dir.path()).await.unwrap();
        let ticket = net.ticket();
        assert!(ticket.starts_with("endpoint"));
        let addr = Network::parse_peer_addr(&ticket).unwrap();
        assert_eq!(addr.id.to_string(), net.node_id());
        // bare id still works
        let addr2 = Network::parse_peer_addr(&net.node_id()).unwrap();
        assert_eq!(addr2.id.to_string(), net.node_id());
    }
}
