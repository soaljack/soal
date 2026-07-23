//! Encryption at rest (default on).
//!
//! XChaCha20-Poly1305 AEAD with a per-vault 32-byte key.
//!
//! For content-addressed storage we use **deterministic** encryption:
//! nonce = first 24 bytes of BLAKE3(plaintext). Identical plaintext + vault key
//! → identical ciphertext → same storage hash → intra-vault deduplication
//! (see spec §5.2.1).

use crate::SoalError;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use rand::RngCore;

/// 32-byte symmetric key.
pub type Key = [u8; 32];

/// Nonce size for XChaCha20-Poly1305.
pub const NONCE_LEN: usize = 24;

/// Generate a new random key.
pub fn generate_key() -> Key {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Encrypt plaintext with a random nonce. Returns nonce (24 bytes) + ciphertext.
/// Prefer [`encrypt_deterministic`] for stored content-addressed chunks.
pub fn encrypt(plain: &[u8], key: &Key) -> Result<Vec<u8>, SoalError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ct = cipher
        .encrypt(nonce.as_ref().into(), plain)
        .map_err(|e| SoalError::Crypto(e.to_string()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt: input = nonce(24) + ciphertext.
pub fn decrypt(ciphertext: &[u8], key: &Key) -> Result<Vec<u8>, SoalError> {
    if ciphertext.len() < NONCE_LEN {
        return Err(SoalError::Crypto("ciphertext too short".into()));
    }
    let (nonce, ct) = ciphertext.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), ct)
        .map_err(|e| SoalError::Crypto(e.to_string()))
}

/// Encrypt a plaintext chunk deterministically for the ciphertext-hash storage model.
///
/// Nonce is derived from BLAKE3(plain) so identical plaintext + vault key
/// always produces identical (nonce + ct).
pub fn encrypt_deterministic(plain: &[u8], key: &Key) -> Result<Vec<u8>, SoalError> {
    let p_hash = blake3::hash(plain);
    let nonce = &p_hash.as_bytes()[..NONCE_LEN];
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(nonce.into(), plain)
        .map_err(|e| SoalError::Crypto(e.to_string()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a stored chunk blob (nonce + ciphertext).
pub fn decrypt_chunk(stored: &[u8], key: &Key) -> Result<Vec<u8>, SoalError> {
    decrypt(stored, key)
}

/// Parse a 32-byte key from hex.
pub fn key_from_hex(s: &str) -> Result<Key, SoalError> {
    let bytes = hex::decode(s.trim()).map_err(|_| SoalError::InvalidHash)?;
    if bytes.len() != 32 {
        return Err(SoalError::Other("invalid key length".into()));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Ok(k)
}

/// Seal a vault key with a wrap key (PR-05 building block).
///
/// Wire: nonce(24) || ciphertext. AAD binds to vault context when provided.
/// Passphrase KDF (Argon2) is layered by higher-level vault config; this is
/// the AEAD seal only.
pub fn wrap_key(vault_key: &Key, wrap_key: &Key, aad: &[u8]) -> Result<Vec<u8>, SoalError> {
    let cipher = XChaCha20Poly1305::new(wrap_key.into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let payload = chacha20poly1305::aead::Payload {
        msg: vault_key.as_slice(),
        aad,
    };
    let ct = cipher
        .encrypt(nonce.as_ref().into(), payload)
        .map_err(|e| SoalError::Crypto(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed vault key (inverse of [`wrap_key`]).
pub fn unwrap_key(sealed: &[u8], wrap_key: &Key, aad: &[u8]) -> Result<Key, SoalError> {
    if sealed.len() < NONCE_LEN + 16 {
        return Err(SoalError::Crypto("wrapped key too short".into()));
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(wrap_key.into());
    let payload = chacha20poly1305::aead::Payload { msg: ct, aad };
    let plain = cipher
        .decrypt(nonce.into(), payload)
        .map_err(|e| SoalError::Crypto(e.to_string()))?;
    if plain.len() != 32 {
        return Err(SoalError::Crypto("unwrapped key wrong length".into()));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&plain);
    Ok(k)
}

/// Build AAD for vault key wrap: `vault_id || "wrap/v1"`.
pub fn wrap_aad(vault_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 7);
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(b"wrap/v1");
    aad
}

// ---------------------------------------------------------------------------
// Passphrase-wrapped vault keys (PR-05)
// ---------------------------------------------------------------------------

/// Default Argon2id memory cost (KiB). ~19 MiB keeps tests fast enough on CI.
pub const ARGON2_M_KIB: u32 = 19_456;
/// Default Argon2id time cost (iterations).
pub const ARGON2_T_COST: u32 = 2;
/// Default Argon2id parallelism.
pub const ARGON2_P_COST: u32 = 1;

/// On-disk passphrase-wrapped vault key (JSON under `vault.wrapped.json`).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct WrappedKey {
    /// KDF algorithm tag.
    pub kdf: String,
    /// 16-byte salt (hex).
    pub salt_hex: String,
    /// Argon2 memory cost in KiB.
    pub m_kib: u32,
    /// Argon2 time cost.
    pub t_cost: u32,
    /// Argon2 parallelism.
    pub p_cost: u32,
    /// Sealed vault key: nonce(24) || ciphertext (hex).
    pub sealed_hex: String,
}

impl WrappedKey {
    pub fn salt_bytes(&self) -> Result<[u8; 16], SoalError> {
        let b = hex::decode(self.salt_hex.trim()).map_err(|_| SoalError::InvalidHash)?;
        if b.len() != 16 {
            return Err(SoalError::Crypto(
                "wrapped key salt must be 16 bytes".into(),
            ));
        }
        let mut a = [0u8; 16];
        a.copy_from_slice(&b);
        Ok(a)
    }

    pub fn sealed_bytes(&self) -> Result<Vec<u8>, SoalError> {
        hex::decode(self.sealed_hex.trim()).map_err(|_| SoalError::InvalidHash)
    }
}

/// Derive a 32-byte wrap key from a passphrase via Argon2id.
pub fn derive_key_from_passphrase(
    passphrase: &str,
    salt: &[u8; 16],
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Key, SoalError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m_kib, t_cost, p_cost, Some(32))
        .map_err(|e| SoalError::Crypto(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| SoalError::Crypto(format!("argon2: {e}")))?;
    Ok(out)
}

/// Seal a vault key under a passphrase (PR-05).
pub fn wrap_vault_key_passphrase(
    vault_key: &Key,
    passphrase: &str,
    vault_id: &[u8; 16],
) -> Result<WrappedKey, SoalError> {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let wrap = derive_key_from_passphrase(
        passphrase,
        &salt,
        ARGON2_M_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
    )?;
    let aad = wrap_aad(vault_id);
    let sealed = wrap_key(vault_key, &wrap, &aad)?;
    Ok(WrappedKey {
        kdf: "argon2id".into(),
        salt_hex: hex::encode(salt),
        m_kib: ARGON2_M_KIB,
        t_cost: ARGON2_T_COST,
        p_cost: ARGON2_P_COST,
        sealed_hex: hex::encode(sealed),
    })
}

/// Open a passphrase-wrapped vault key.
pub fn unwrap_vault_key_passphrase(
    wrapped: &WrappedKey,
    passphrase: &str,
    vault_id: &[u8; 16],
) -> Result<Key, SoalError> {
    if wrapped.kdf != "argon2id" {
        return Err(SoalError::Crypto(format!(
            "unsupported wrap kdf: {}",
            wrapped.kdf
        )));
    }
    let salt = wrapped.salt_bytes()?;
    let wrap = derive_key_from_passphrase(
        passphrase,
        &salt,
        wrapped.m_kib,
        wrapped.t_cost,
        wrapped.p_cost,
    )?;
    let sealed = wrapped.sealed_bytes()?;
    let aad = wrap_aad(vault_id);
    unwrap_key(&sealed, &wrap, &aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let data = b"hello soal encryption test 12345";
        let enc = encrypt(data, &key).unwrap();
        let dec = decrypt(&enc, &key).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let data = b"secret";
        let enc = encrypt(data, &key1).unwrap();
        assert!(decrypt(&enc, &key2).is_err());
    }

    #[test]
    fn deterministic_encrypt_produces_same_ct_for_same_plain() {
        let key = generate_key();
        let data = b"identical chunk for dedup test 98765";
        let ct1 = encrypt_deterministic(data, &key).unwrap();
        let ct2 = encrypt_deterministic(data, &key).unwrap();
        assert_eq!(ct1, ct2, "deterministic encrypt must be stable");

        let data2 = b"different chunk";
        let ct3 = encrypt_deterministic(data2, &key).unwrap();
        assert_ne!(ct1, ct3);
    }

    #[test]
    fn deterministic_roundtrip() {
        let key = generate_key();
        let data = b"roundtrip deterministic soal 123";
        let enc = encrypt_deterministic(data, &key).unwrap();
        let dec = decrypt(&enc, &key).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn nondet_encrypt_differs_from_det_and_is_randomized() {
        let key = generate_key();
        let data = b"same data";
        let d1 = encrypt_deterministic(data, &key).unwrap();
        let d2 = encrypt_deterministic(data, &key).unwrap();
        assert_eq!(d1, d2);

        let n1 = encrypt(data, &key).unwrap();
        let n2 = encrypt(data, &key).unwrap();
        assert_ne!(n1, n2);
        assert_ne!(n1, d1);
    }

    #[test]
    fn short_ciphertext_errors() {
        let key = generate_key();
        assert!(decrypt(b"short", &key).is_err());
    }

    #[test]
    fn wrap_unwrap_roundtrip_with_aad() {
        let vault_key = generate_key();
        let wrap = generate_key();
        let vault_id = [0x42u8; 16];
        let aad = wrap_aad(&vault_id);
        let sealed = wrap_key(&vault_key, &wrap, &aad).unwrap();
        let opened = unwrap_key(&sealed, &wrap, &aad).unwrap();
        assert_eq!(opened, vault_key);
        // Wrong AAD fails
        assert!(unwrap_key(&sealed, &wrap, b"wrong").is_err());
        // Wrong wrap key fails
        let other = generate_key();
        assert!(unwrap_key(&sealed, &other, &aad).is_err());
    }

    #[test]
    fn passphrase_wrap_roundtrip() {
        let vault_key = generate_key();
        let vault_id = [0x11u8; 16];
        let wrapped =
            wrap_vault_key_passphrase(&vault_key, "correct horse battery", &vault_id).unwrap();
        let opened =
            unwrap_vault_key_passphrase(&wrapped, "correct horse battery", &vault_id).unwrap();
        assert_eq!(opened, vault_key);
        assert!(unwrap_vault_key_passphrase(&wrapped, "wrong password", &vault_id).is_err());
        // Wrong vault_id AAD fails
        assert!(
            unwrap_vault_key_passphrase(&wrapped, "correct horse battery", &[0x22u8; 16]).is_err()
        );
    }
}
