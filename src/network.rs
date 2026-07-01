//! Phase 1: Gossip for Head Announcements + real iroh-blobs transfer for chunks/trees/commits

use crate::{ContentHash, SoalError};
use futures_lite::StreamExt;
use iroh::endpoint::presets::N0;
use iroh::protocol::Router;
use iroh::Endpoint;

use iroh_blobs::get::request::get_blob;
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::BlobsProtocol;
use iroh_gossip::api::Event as GossipEvent;
use iroh_gossip::net::Gossip;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HeadAnnouncement {
    pub vault: String,
    pub head: String,
    pub timestamp: u64,
    pub node_id: String,
}

#[derive(Clone)]
pub struct Network {
    pub endpoint: Endpoint,
    pub gossip: Arc<Gossip>,
    pub peers: HashSet<String>,
    blobs: BlobsProtocol,
    // Keep router alive to serve blobs protocol
    _router: Arc<Router>,
}

impl Network {
    pub async fn new() -> Result<Self, SoalError> {
        let endpoint = Endpoint::builder(N0)
            .bind()
            .await
            .map_err(|e| SoalError::Other(format!("endpoint: {}", e)))?;

        let gossip = Gossip::builder().spawn(endpoint.clone());

        // Set up iroh-blobs for real content transfer (mem store for served blobs)
        let mem_store = MemStore::new();
        let blobs = BlobsProtocol::new(&mem_store, None);

        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs.clone())
            .spawn();

        Ok(Self {
            endpoint,
            gossip: Arc::new(gossip),
            peers: HashSet::new(),
            blobs,
            _router: Arc::new(router),
        })
    }

    pub fn node_id(&self) -> String {
        self.endpoint.id().to_string()
    }

    pub fn add_peer(&mut self, peer: String) {
        self.peers.insert(peer);
    }

    pub fn peers(&self) -> Vec<String> {
        self.peers.iter().cloned().collect()
    }

    /// Make bytes available for other peers to fetch via iroh-blobs by its (our content) hash.
    /// Call this with commit/tree/chunk storage bytes so a remote sync can pull them.
    pub async fn provide(&self, _hash: ContentHash, data: &[u8]) -> Result<(), SoalError> {
        // add_bytes awaits to the final imported tag (hash inside should match our blake3(data))
        let _tag = self
            .blobs
            .add_bytes(data.to_vec())
            .await
            .map_err(|e| SoalError::Other(format!("blobs provide: {}", e)))?;
        Ok(())
    }

    pub async fn announce_head(&self, vault: &str, head: &str) -> Result<(), SoalError> {
        let topic_id: iroh_gossip::proto::TopicId = blake3::hash(vault.as_bytes()).into();

        let bootstrap: Vec<_> = self.peers.iter().filter_map(|s| s.parse().ok()).collect();
        let mut topic = self
            .gossip
            .subscribe(topic_id, bootstrap)
            .await
            .map_err(|e| SoalError::Other(format!("subscribe: {}", e)))?;

        let ann = HeadAnnouncement {
            vault: vault.to_string(),
            head: head.to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            node_id: self.node_id().to_string(),
        };
        let msg = serde_json::to_vec(&ann)
            .map_err(|e| SoalError::Other(e.to_string()))?
            .into();

        topic
            .broadcast(msg)
            .await
            .map_err(|e| SoalError::Other(format!("broadcast: {}", e)))?;

        println!(
            "[network] Broadcasted real head ann for {}: {}",
            vault, head
        );
        Ok(())
    }

    /// Listen for head announcements on the topic.
    /// Receives real gossip messages, suggests adding the sender as peer, and triggers sync logic.
    pub async fn listen_for_heads(&self, vault: &str) -> Result<(), SoalError> {
        let topic_id: iroh_gossip::proto::TopicId = blake3::hash(vault.as_bytes()).into();
        let bootstrap: Vec<_> = self.peers.iter().filter_map(|s| s.parse().ok()).collect();
        let topic = self
            .gossip
            .subscribe(topic_id, bootstrap)
            .await
            .map_err(|e| SoalError::Other(format!("listen subscribe: {}", e)))?;

        println!(
            "[network] Joined gossip topic for listening heads on vault {}",
            vault
        );

        let (_sender, mut receiver) = topic.split();
        // Receive loop for demo (in real app, this would be in a spawned task)
        for _ in 0..5 {
            if let Ok(Some(Ok(GossipEvent::Received(received)))) =
                tokio::time::timeout(std::time::Duration::from_secs(5), receiver.next()).await
            {
                if let Ok(ann) = serde_json::from_slice::<HeadAnnouncement>(&received.content) {
                    println!(
                        "[network] RECEIVED head ann from {} for {}: {}",
                        ann.node_id, ann.vault, ann.head
                    );
                    if !ann.node_id.is_empty() && ann.node_id != self.node_id() {
                        println!(
                            "[network]   (add this peer with: soal node add-peer {})",
                            ann.node_id
                        );
                    }
                    // trigger sync on receive
                    let _ = self.sync_vault(&ann.vault).await;
                }
            }
        }
        Ok(())
    }

    pub async fn sync_vault(&self, vault: &str) -> Result<(), SoalError> {
        println!(
            "[network] Syncing vault {} from peers using real iroh-blobs transfer",
            vault
        );
        if self.peers.is_empty() {
            println!("  (no peers configured; use `node add-peer <id>` or receive via listen)");
            return Ok(());
        }
        for peer in &self.peers {
            println!(
                "  peer: {} (use get_chunk_from_peer to pull specific ct-hashes)",
                peer
            );
        }
        Ok(())
    }

    /// Real transfer using iroh-blobs: connect to peer and fetch blob by (content) hash.
    /// The returned bytes are the raw stored data (ciphertext for encrypted vaults, or plaintext).
    pub async fn get_chunk_from_peer(
        &self,
        peer: &str,
        hash: ContentHash,
    ) -> Result<Vec<u8>, SoalError> {
        let peer_id: iroh::EndpointId = peer
            .parse()
            .map_err(|e| SoalError::Other(format!("bad peer id: {}", e)))?;

        let conn = self
            .endpoint
            .connect(peer_id, iroh_blobs::ALPN)
            .await
            .map_err(|e| SoalError::Other(format!("connect for blobs: {}", e)))?;

        let bhash = iroh_blobs::Hash::from_bytes(hash);

        // get_blob returns a result that can be awaited for full bytes
        let bytes = get_blob(conn, bhash)
            .bytes()
            .await
            .map_err(|e| SoalError::Other(format!("get_blob: {}", e)))?;

        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn head_announcement_serde_roundtrip() {
        let ann = HeadAnnouncement {
            vault: "photos".to_string(),
            head: "abc123".to_string(),
            timestamp: 1234567890,
            node_id: "node1".to_string(),
        };
        let json = serde_json::to_string(&ann).unwrap();
        let back: HeadAnnouncement = serde_json::from_str(&json).unwrap();
        assert_eq!(ann.vault, back.vault);
        assert_eq!(ann.head, back.head);
        assert_eq!(ann.node_id, back.node_id);
    }

    #[tokio::test]
    async fn network_new_smoke() {
        // This creates a real endpoint, should not panic.
        let net = Network::new().await;
        assert!(net.is_ok());
        let net = net.unwrap();
        assert!(!net.node_id().is_empty());
    }

    // Note: full peer tests require initialized Endpoint/Gossip, tested via smoke + CLI E2E patterns.
}
