//! Secure vault invites and join (PR-12).
//!
//! Invite tokens are signed CBOR payloads (base64url) carrying vault_id,
//! membership metadata, and (when encryption is on) the vault key sealed under
//! an invite secret embedded in the token. Joining materializes a local vault
//! with the same vault_id + key so multi-node SC-KEY-SHARE is production-ready.

use crate::codec::{self, DOMAIN_INVITE, VAULT_ID_LEN};
use crate::crypto::{generate_key, unwrap_key, wrap_key, Key};
use crate::identity;
use crate::vault::Vault;
use crate::SoalError;
use iroh::SecretKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const INVITE_AAD: &[u8] = b"soal/invite/key/v1";
const DEFAULT_TTL_SECS: u64 = 7 * 24 * 3600; // 7 days

/// Role granted by an invite.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InviteRole {
    Read,
    Write,
}

impl InviteRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            InviteRole::Read => "read",
            InviteRole::Write => "write",
        }
    }

    pub fn parse(s: &str) -> Result<Self, SoalError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "read" | "r" => Ok(InviteRole::Read),
            "write" | "w" | "rw" => Ok(InviteRole::Write),
            other => Err(SoalError::Other(format!("unknown invite role: {other}"))),
        }
    }
}

/// Signed vault invite (wire + token body).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invite {
    pub protocol_version: u64,
    pub vault_id_hex: String,
    pub vault_name: String,
    pub encryption_enabled: bool,
    pub min_replicas: u8,
    pub config_seq: u64,
    pub members: Vec<String>,
    pub role: InviteRole,
    /// Issuer NodeID (hex / iroh string form).
    pub issuer: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// Random 32-byte invite secret (hex) used to seal the vault key.
    pub invite_secret_hex: String,
    /// Sealed vault key (hex of nonce||ct), empty when encryption disabled.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sealed_key_hex: String,
    /// ed25519 signature over sign preimage (hex).
    pub signature_hex: String,
}

impl Invite {
    pub fn vault_id_bytes(&self) -> Result<[u8; VAULT_ID_LEN], SoalError> {
        codec::vault_id_from_hex(&self.vault_id_hex)
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }

    /// Encode as base64url (no pad) token for CLI exchange.
    pub fn to_token(&self) -> Result<String, SoalError> {
        let json = serde_json::to_vec(self)?;
        Ok(base64_url_encode(&json))
    }

    /// Decode token (base64url or raw JSON).
    pub fn from_token(token: &str) -> Result<Self, SoalError> {
        let token = token.trim();
        let bytes = if token.starts_with('{') {
            token.as_bytes().to_vec()
        } else {
            base64_url_decode(token)?
        };
        serde_json::from_slice(&bytes).map_err(|e| SoalError::Other(format!("invite decode: {e}")))
    }
}

fn invite_sign_preimage(inv: &Invite) -> Result<Vec<u8>, SoalError> {
    // Canonical JSON of fields excluding signature.
    let mut body = serde_json::json!({
        "protocol_version": inv.protocol_version,
        "vault_id_hex": inv.vault_id_hex,
        "vault_name": inv.vault_name,
        "encryption_enabled": inv.encryption_enabled,
        "min_replicas": inv.min_replicas,
        "config_seq": inv.config_seq,
        "members": inv.members,
        "role": inv.role,
        "issuer": inv.issuer,
        "created_at": inv.created_at,
        "expires_at": inv.expires_at,
        "invite_secret_hex": inv.invite_secret_hex,
        "sealed_key_hex": inv.sealed_key_hex,
    });
    // Stable key order via serde_json Map is insertion order; rebuild sorted.
    let map = body.as_object_mut().unwrap();
    let mut keys: Vec<_> = map.keys().cloned().collect();
    keys.sort();
    let mut ordered = serde_json::Map::new();
    for k in keys {
        ordered.insert(k.clone(), map.remove(&k).unwrap());
    }
    let json = serde_json::to_vec(&serde_json::Value::Object(ordered))?;
    Ok(codec::frame(&DOMAIN_INVITE, &json))
}

/// Create a signed invite for an open vault.
pub fn generate_invite(
    vault: &Vault,
    sk: &SecretKey,
    role: InviteRole,
    ttl_secs: Option<u64>,
) -> Result<Invite, SoalError> {
    let now = now_secs();
    let ttl = ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);

    let sealed_key_hex = if vault.config.encryption_enabled {
        let key = vault
            .vault_key()
            .ok_or_else(|| SoalError::Other("encrypted vault has no key loaded".into()))?;
        let sealed = wrap_key(key, &secret, INVITE_AAD)?;
        hex::encode(sealed)
    } else {
        String::new()
    };

    let mut members = vault.config.members.clone();
    let issuer = sk.public().to_string();
    if !members.iter().any(|m| m.eq_ignore_ascii_case(&issuer)) {
        members.push(issuer.clone());
    }

    let mut inv = Invite {
        protocol_version: codec::PROTOCOL_VERSION,
        vault_id_hex: vault.config.vault_id.clone(),
        vault_name: vault.name.clone(),
        encryption_enabled: vault.config.encryption_enabled,
        min_replicas: vault.config.min_replicas,
        config_seq: vault.config.config_seq,
        members,
        role,
        issuer,
        created_at: now,
        expires_at: now.saturating_add(ttl),
        invite_secret_hex: hex::encode(secret),
        sealed_key_hex,
        signature_hex: String::new(),
    };
    let msg = invite_sign_preimage(&inv)?;
    let sig = sk.sign(&msg);
    inv.signature_hex = hex::encode(sig.to_bytes());
    Ok(inv)
}

/// Verify invite signature + expiry.
pub fn verify_invite(inv: &Invite, now: Option<u64>) -> Result<(), SoalError> {
    if inv.protocol_version != codec::PROTOCOL_VERSION {
        return Err(SoalError::Verify(format!(
            "unsupported invite protocol_version {}",
            inv.protocol_version
        )));
    }
    let now = now.unwrap_or_else(now_secs);
    if inv.is_expired(now) {
        return Err(SoalError::Verify("invite expired".into()));
    }
    if inv.signature_hex.is_empty() {
        return Err(SoalError::Verify("invite unsigned".into()));
    }
    let sig_bytes = hex::decode(inv.signature_hex.trim())
        .map_err(|_| SoalError::Verify("bad invite signature hex".into()))?;
    if sig_bytes.len() != 64 {
        return Err(SoalError::Verify(
            "invite signature must be 64 bytes".into(),
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    // Issuer is an iroh public key string (z32 or hex depending on Display).
    let pk = inv
        .issuer
        .parse::<iroh::PublicKey>()
        .map_err(|e| SoalError::Verify(format!("bad invite issuer: {e}")))?;
    let msg = invite_sign_preimage(inv)?;
    let sig = iroh::Signature::from_bytes(&sig_arr);
    pk.verify(&msg, &sig)
        .map_err(|_| SoalError::Verify("invite signature invalid".into()))?;
    Ok(())
}

/// Join a vault from an invite into `base_dir` (creates local vault).
pub fn join_invite(
    base_dir: &Path,
    soal_home: &Path,
    token: &str,
    local_name: Option<&str>,
) -> Result<Vault, SoalError> {
    let inv = Invite::from_token(token)?;
    verify_invite(&inv, None)?;

    let name = local_name.unwrap_or(&inv.vault_name);
    let vault_id = inv.vault_id_bytes()?;

    let key: Option<Key> = if inv.encryption_enabled {
        let secret_bytes = hex::decode(inv.invite_secret_hex.trim())
            .map_err(|_| SoalError::Other("bad invite secret".into()))?;
        if secret_bytes.len() != 32 {
            return Err(SoalError::Other("invite secret must be 32 bytes".into()));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);
        let sealed = hex::decode(inv.sealed_key_hex.trim())
            .map_err(|_| SoalError::Other("bad sealed key".into()))?;
        Some(unwrap_key(&sealed, &secret, INVITE_AAD)?)
    } else {
        None
    };

    // Ensure local node is in members list.
    let mut members = inv.members.clone();
    if let Ok(me) = identity::local_author_sync(soal_home) {
        if !members.iter().any(|m| m.eq_ignore_ascii_case(&me)) {
            members.push(me);
        }
    }
    // Always keep issuer.
    if !members.iter().any(|m| m.eq_ignore_ascii_case(&inv.issuer)) {
        members.push(inv.issuer.clone());
    }

    let mut v = Vault::create_for_test(
        base_dir,
        name,
        inv.encryption_enabled,
        vault_id,
        key,
        members,
    )?;
    // Align policy fields from invite.
    v.config.min_replicas = inv.min_replicas.max(1);
    v.config.config_seq = inv.config_seq;
    v.config.vault_id = inv.vault_id_hex.clone();
    v.persist_config()?;
    // Re-open so soal_home is bound for signing going forward.
    let opened = Vault::open(base_dir, name)?.with_soal_home(soal_home.to_path_buf());
    Ok(opened)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>, SoalError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s.trim()))
        .map_err(|e| SoalError::Other(format!("base64: {e}")))
}

/// Generate a random invite secret (test helper / token building).
pub fn random_invite_secret() -> Key {
    generate_key()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Network;
    use tempfile::tempdir;

    #[tokio::test]
    async fn invite_generate_verify_join_roundtrip() {
        let home_a = tempdir().unwrap();
        let home_b = tempdir().unwrap();
        let base_a = home_a.path().join("vaults");
        let base_b = home_b.path().join("vaults");
        std::fs::create_dir_all(&base_a).unwrap();
        std::fs::create_dir_all(&base_b).unwrap();

        // Init node A identity
        let _net_a = Network::open(home_a.path()).await.unwrap();
        let sk = identity::load_secret_key(home_a.path()).unwrap();

        let mut va = Vault::create(&base_a, "photos", true).unwrap();
        va = va.with_soal_home(home_a.path().to_path_buf());
        // Ensure members include issuer
        let inv = generate_invite(&va, &sk, InviteRole::Write, Some(3600)).unwrap();
        verify_invite(&inv, None).unwrap();
        let token = inv.to_token().unwrap();

        // Init node B and join
        let _net_b = Network::open(home_b.path()).await.unwrap();
        let vb = join_invite(&base_b, home_b.path(), &token, None).unwrap();
        assert_eq!(vb.config.vault_id, va.config.vault_id);
        assert!(vb.config.encryption_enabled);
        assert_eq!(
            vb.vault_key().unwrap(),
            va.vault_key().unwrap(),
            "joined vault must share encryption key"
        );
    }

    #[tokio::test]
    async fn invite_rejects_tamper_and_expiry() {
        let home = tempdir().unwrap();
        let base = home.path().join("vaults");
        std::fs::create_dir_all(&base).unwrap();
        let _ = Network::open(home.path()).await.unwrap();
        let sk = identity::load_secret_key(home.path()).unwrap();
        let v = Vault::create(&base, "v", true).unwrap();
        let mut inv = generate_invite(&v, &sk, InviteRole::Read, Some(1)).unwrap();
        inv.vault_name = "hacked".into();
        assert!(verify_invite(&inv, None).is_err());

        let mut inv2 = generate_invite(&v, &sk, InviteRole::Read, Some(1)).unwrap();
        inv2.expires_at = 1;
        assert!(verify_invite(&inv2, Some(100)).is_err());
    }
}
