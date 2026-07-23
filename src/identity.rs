//! Persistent node identity helpers (Iroh SecretKey under `~/.soal/node.json`).
//!
//! Used for commit author strings and ed25519 sign/verify of commits (INV-SIG-01)
//! and head announcements (INV-SIG-02).

use crate::codec::{self, HeadAnnouncement};
use crate::commit::Commit;
use crate::SoalError;
use iroh::SecretKey;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct NodeStateFile {
    secret_key_hex: String,
}

/// Load the persistent Iroh secret key from `soal_home/node.json`.
pub fn load_secret_key(soal_home: &Path) -> Result<SecretKey, SoalError> {
    let path = soal_home.join("node.json");
    if !path.exists() {
        return Err(SoalError::Other("node identity not initialized".into()));
    }
    let s = fs::read_to_string(path)?;
    let state: NodeStateFile = serde_json::from_str(&s)?;
    let bytes = hex::decode(state.secret_key_hex.trim())
        .map_err(|_| SoalError::Other("invalid secret key hex".into()))?;
    if bytes.len() != 32 {
        return Err(SoalError::Other("secret key must be 32 bytes".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SecretKey::from_bytes(&arr))
}

/// Public key hex (author string / NodeID display form).
pub fn local_author_sync(soal_home: &Path) -> Result<String, SoalError> {
    let sk = load_secret_key(soal_home)?;
    Ok(sk.public().to_string())
}

/// Sign a commit in place (sets author, protocol_version, signature).
///
/// Sign message = DOMAIN_COMMIT || cbor(SignBody fields 1–6) per design KD-07.
pub fn sign_commit(sk: &SecretKey, commit: &mut Commit) -> Result<(), SoalError> {
    commit.author = sk.public().to_string();
    commit.protocol_version = codec::PROTOCOL_VERSION as u16;
    commit.signature = None; // sign preimage excludes signature
    let msg = codec::commit_sign_message(commit)?;
    let sig = sk.sign(&msg);
    commit.signature = Some(hex::encode(sig.to_bytes()));
    Ok(())
}

/// Verify commit signature when present (non-zero).
///
/// Unsigned commits (64 zero bytes) are accepted for local/legacy use.
/// Non-zero signatures must verify under the author public key (INV-SIG-01).
pub fn verify_commit_signature(commit: &Commit) -> Result<(), SoalError> {
    let sig_bytes = commit.signature_bytes();
    if sig_bytes == [0u8; 64] {
        return Ok(()); // unsigned
    }
    let pk_bytes = codec::author_to_bytes(&commit.author);
    let pk = iroh::PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| SoalError::Verify(format!("bad author pubkey: {e}")))?;
    let msg = codec::commit_sign_message(commit)?;
    let sig = iroh::Signature::from_bytes(&sig_bytes);
    pk.verify(&msg, &sig)
        .map_err(|_| SoalError::Verify("commit signature invalid".into()))?;
    Ok(())
}

/// Build and sign a head announcement (INV-SIG-02).
pub fn sign_head_announcement(
    sk: &SecretKey,
    vault_id: [u8; codec::VAULT_ID_LEN],
    vault_name: &str,
    head: crate::ContentHash,
    seq: u64,
    config_seq: u64,
) -> Result<HeadAnnouncement, SoalError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut ann = HeadAnnouncement {
        protocol_version: codec::PROTOCOL_VERSION,
        vault_id,
        vault_name: vault_name.to_string(),
        head,
        timestamp,
        node_id: *sk.public().as_bytes(),
        seq,
        config_seq,
        signature: [0u8; 64],
    };
    let msg = codec::head_sign_message(&ann)?;
    let sig = sk.sign(&msg);
    ann.signature = sig.to_bytes();
    Ok(ann)
}

/// Verify head announcement signature (INV-SIG-02). Requires non-zero signature.
pub fn verify_head_announcement(ann: &HeadAnnouncement) -> Result<(), SoalError> {
    if !ann.is_signed() {
        return Err(SoalError::Verify("head announcement unsigned".into()));
    }
    if ann.protocol_version != codec::PROTOCOL_VERSION {
        return Err(SoalError::Verify(format!(
            "unsupported head protocol_version {}",
            ann.protocol_version
        )));
    }
    let pk = iroh::PublicKey::from_bytes(&ann.node_id)
        .map_err(|e| SoalError::Verify(format!("bad node_id pubkey: {e}")))?;
    let msg = codec::head_sign_message(ann)?;
    let sig = iroh::Signature::from_bytes(&ann.signature);
    pk.verify(&msg, &sig)
        .map_err(|_| SoalError::Verify("head announcement signature invalid".into()))?;
    Ok(())
}

/// INV-SKEW-01: reject announcements outside MAX_SKEW_SECS of local clock.
pub fn check_head_skew(ann: &HeadAnnouncement, now_secs: u64) -> Result<(), SoalError> {
    let skew = now_secs.abs_diff(ann.timestamp);
    if skew > codec::MAX_SKEW_SECS {
        return Err(SoalError::Verify(format!(
            "head timestamp skew {skew}s exceeds MAX_SKEW_SECS"
        )));
    }
    Ok(())
}

/// Public key bytes from a SecretKey.
pub fn public_key_bytes(sk: &SecretKey) -> [u8; 32] {
    *sk.public().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContentHash;
    use tempfile::tempdir;

    fn write_node(home: &Path, sk: &SecretKey) {
        fs::create_dir_all(home).unwrap();
        let json = serde_json::json!({
            "secret_key_hex": hex::encode(sk.to_bytes()),
            "peers": [],
        });
        fs::write(home.join("node.json"), json.to_string()).unwrap();
    }

    #[test]
    fn sign_and_verify_commit() {
        let dir = tempdir().unwrap();
        let sk = SecretKey::generate();
        write_node(dir.path(), &sk);

        let mut c = Commit::new(
            ContentHash::from([1u8; 32]),
            vec![],
            "placeholder",
            "signed",
        );
        c.timestamp = 99;
        sign_commit(&sk, &mut c).unwrap();
        assert!(c.is_signed());
        assert_eq!(c.author, sk.public().to_string());
        verify_commit_signature(&c).unwrap();

        // Tamper message → verify fails
        c.message = "tampered".into();
        // signature still old; verify should fail
        assert!(verify_commit_signature(&c).is_err());
    }

    #[test]
    fn unsigned_commit_verify_ok() {
        let c = Commit::new(ContentHash::from([2u8; 32]), vec![], "soal-local", "u");
        assert!(!c.is_signed());
        verify_commit_signature(&c).unwrap();
    }

    #[test]
    fn author_roundtrip_from_node() {
        let dir = tempdir().unwrap();
        let sk = SecretKey::generate();
        write_node(dir.path(), &sk);
        let a = local_author_sync(dir.path()).unwrap();
        assert_eq!(a, sk.public().to_string());
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn sign_and_verify_head() {
        let sk = SecretKey::generate();
        let head = ContentHash::from([5u8; 32]);
        let ann = sign_head_announcement(&sk, [1u8; 16], "photos", head, 1, 1).unwrap();
        assert!(ann.is_signed());
        assert_eq!(ann.node_id, *sk.public().as_bytes());
        verify_head_announcement(&ann).unwrap();
        check_head_skew(&ann, ann.timestamp).unwrap();
        check_head_skew(&ann, ann.timestamp + codec::MAX_SKEW_SECS).unwrap();
        assert!(check_head_skew(&ann, ann.timestamp + codec::MAX_SKEW_SECS + 1).is_err());

        // Tamper head → verify fails
        let mut bad = ann.clone();
        bad.head = ContentHash::from([9u8; 32]);
        assert!(verify_head_announcement(&bad).is_err());
    }

    #[test]
    fn unsigned_head_rejected() {
        let ann = HeadAnnouncement {
            protocol_version: 1,
            vault_id: [0u8; 16],
            vault_name: "x".into(),
            head: ContentHash::ZERO,
            timestamp: 1,
            node_id: [1u8; 32],
            seq: 1,
            config_seq: 1,
            signature: [0u8; 64],
        };
        assert!(verify_head_announcement(&ann).is_err());
    }
}
