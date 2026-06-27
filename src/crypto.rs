//! Encryption at rest (default on)
//!
//! Phase 0: Simple AEAD using ChaCha20-Poly1305.
//! Key per vault. Nonce stored with ciphertext.

use crate::SoalError;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use rand::RngCore;

/// 32-byte symmetric key
pub type Key = [u8; 32];

/// Generate a new random key
pub fn generate_key() -> Key {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Encrypt plaintext. Returns nonce (24 bytes) + ciphertext.
pub fn encrypt(plain: &[u8], key: &Key) -> Result<Vec<u8>, SoalError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ct = cipher
        .encrypt(nonce.as_ref().into(), plain)
        .map_err(|e| SoalError::Crypto(e.to_string()))?;

    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt: input = nonce(24) + ciphertext
pub fn decrypt(ciphertext: &[u8], key: &Key) -> Result<Vec<u8>, SoalError> {
    if ciphertext.len() < 24 {
        return Err(SoalError::Crypto("ciphertext too short".into()));
    }
    let (nonce, ct) = ciphertext.split_at(24);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), ct)
        .map_err(|e| SoalError::Crypto(e.to_string()))
}

/// Helper: encrypt a chunk's data. Returns the blob to store on disk.
pub fn encrypt_chunk(plain: &[u8], key: &Key) -> Result<Vec<u8>, SoalError> {
    encrypt(plain, key)
}

/// Decrypt a stored chunk blob.
pub fn decrypt_chunk(stored: &[u8], key: &Key) -> Result<Vec<u8>, SoalError> {
    decrypt(stored, key)
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
}
