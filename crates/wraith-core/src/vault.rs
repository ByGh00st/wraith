//! Wraith ChaCha20-Poly1305 Encrypted RamFS Vault & Memory Protection Engine
//! Audited ChaCha20-Poly1305 AEAD (RFC 8439) with hardware acceleration,
//! kernel `mlock` page locking, and zeroize-on-drop memory sanitization.

use rand::RngCore;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use tracing::{debug, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use crate::error::{Result, WraithError};

pub const VAULT_DIR: &str = "/dev/shm/.wraith_vault";

// ==============================================================================
// 1. VAULT KEY & ZEROIZATION PRIMITIVES
// ==============================================================================

/// 256-bit Cryptographic Symmetric Key with automated zeroization on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey(pub [u8; 32]);

impl VaultKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ==============================================================================
// 2. AUDITED CHACHA20-POLY1305 AEAD ENCRYPT / DECRYPT (RFC 8439)
// ==============================================================================

/// Encrypts plaintext using RFC 8439 ChaCha20-Poly1305 AEAD
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let cipher_nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let encrypted_with_tag = cipher
        .encrypt(cipher_nonce, payload)
        .map_err(|e| WraithError::Custom(format!("ChaCha20Poly1305 encryption failed: {e}")))?;

    if encrypted_with_tag.len() < 16 {
        return Err(WraithError::Custom("Encrypted payload length is invalid".into()));
    }

    let split_idx = encrypted_with_tag.len() - 16;
    let ciphertext = encrypted_with_tag[..split_idx].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&encrypted_with_tag[split_idx..]);

    Ok((ciphertext, tag))
}

/// Decrypts and authenticates ciphertext using RFC 8439 ChaCha20-Poly1305 AEAD
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>> {
    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let cipher_nonce = Nonce::from_slice(nonce);

    let mut combined = Vec::with_capacity(ciphertext.len() + 16);
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);

    let payload = Payload {
        msg: &combined,
        aad,
    };

    let plaintext = cipher
        .decrypt(cipher_nonce, payload)
        .map_err(|_| WraithError::Custom("AEAD Poly1305 authentication tag mismatch (tampering detected)".into()))?;

    Ok(plaintext)
}

// ==============================================================================
// 3. ZEROIZE PROTECTED MEMORY SECRET
// ==============================================================================

/// Protected in-memory secret with zeroize-on-drop guarantees
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ProtectedMemorySecret {
    data: Vec<u8>,
}

impl ProtectedMemorySecret {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            data: secret.to_vec(),
        }
    }

    /// Access the secret in an isolated closure scope
    pub fn with_unmasked<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.data)
    }
}

// Alias for backward compatibility
pub type ScrambledSecret = ProtectedMemorySecret;

// ==============================================================================
// 4. EPHEMERAL ENCRYPTED RAMFS VAULT
// ==============================================================================

pub struct EncryptedRamVault {
    vault_path: PathBuf,
    master_key: VaultKey,
    key_ring: HashMap<String, ProtectedMemorySecret>,
}

impl EncryptedRamVault {
    pub fn init() -> Result<Self> {
        let path = PathBuf::from(VAULT_DIR);

        // Mount or create secure directory
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }

        #[cfg(unix)]
        {
            // SAFETY: Calling libc::mlockall with valid flags to lock RAM pages and prevent swap-to-disk leaks.
            unsafe {
                let res = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
                if res != 0 {
                    warn!(
                        "mlockall failed (non-fatal, check RLIMIT_MEMLOCK): {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
        }

        let master_key = VaultKey::generate();
        info!("Initialized ChaCha20-Poly1305 Encrypted RAMFS Vault in {VAULT_DIR}");

        Ok(Self {
            vault_path: path,
            master_key,
            key_ring: HashMap::new(),
        })
    }

    pub fn write_secret(&mut self, secret_name: &str, data: &[u8]) -> Result<()> {
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);

        let (ciphertext, tag) = chacha20_poly1305_encrypt(
            self.master_key.as_bytes(),
            &nonce,
            secret_name.as_bytes(),
            data,
        )?;

        let target_file = self.vault_path.join(format!("{secret_name}.enc"));
        let mut file = OpenOptions::new().write(true).create(true).truncate(true).open(&target_file)?;

        file.write_all(&nonce)?;
        file.write_all(&tag)?;
        file.write_all(&ciphertext)?;
        file.sync_all()?;

        self.key_ring.insert(secret_name.to_string(), ProtectedMemorySecret::new(data));
        debug!("Vault: Encrypted secret '{secret_name}' stored with AEAD authentication");
        Ok(())
    }

    pub fn read_secret(&self, secret_name: &str) -> Result<Vec<u8>> {
        // Fast path: In-memory protected key ring
        if let Some(protected) = self.key_ring.get(secret_name) {
            return Ok(protected.with_unmasked(|bytes| bytes.to_vec()));
        }

        let target_file = self.vault_path.join(format!("{secret_name}.enc"));
        if !target_file.exists() {
            return Err(WraithError::Custom(format!("Secret '{secret_name}' not found in vault")));
        }

        let mut file = File::open(&target_file)?;
        let mut nonce = [0u8; 12];
        let mut tag = [0u8; 16];

        file.read_exact(&mut nonce)?;
        file.read_exact(&mut tag)?;

        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext)?;

        let plaintext = chacha20_poly1305_decrypt(
            self.master_key.as_bytes(),
            &nonce,
            secret_name.as_bytes(),
            &ciphertext,
            &tag,
        )?;

        Ok(plaintext)
    }

    pub fn destroy(mut self) -> Result<()> {
        self.master_key.zeroize();
        self.key_ring.clear();

        if self.vault_path.exists() {
            if let Err(e) = fs::remove_dir_all(&self.vault_path) {
                warn!("Failed removing RAMFS vault directory {}: {e}", self.vault_path.display());
            }
        }

        info!("RAMFS Vault destroyed and memory zeroized");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x19u8; 12];
        let aad = b"test_metadata_header";
        let plaintext = b"Wraith Operating Protocol Payload 0xDEADBEEF";

        let (ciphertext, tag) = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext)
            .expect("Encryption must succeed");

        assert_ne!(ciphertext, plaintext);
        assert_eq!(tag.len(), 16);

        let decrypted = chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag)
            .expect("Decryption must succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_poly1305_tamper_detection() {
        let key = [0x42u8; 32];
        let nonce = [0x19u8; 12];
        let aad = b"test_metadata_header";
        let plaintext = b"Original Payload";

        let (mut ciphertext, tag) = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext)
            .expect("Encryption must succeed");

        // Tamper with ciphertext
        if let Some(byte) = ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        let result = chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag);
        assert!(result.is_err(), "Decryption must fail when ciphertext is tampered");
    }
}
