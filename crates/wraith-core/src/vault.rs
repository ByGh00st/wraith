//! Wraith ChaCha20-Poly1305 Encrypted RamFS Vault & Memory Protection Engine
//! Audited ChaCha20-Poly1305 AEAD (RFC 8439) with hardware acceleration,
//! kernel `mlock` page locking, and zeroize-on-drop memory sanitization.

#![allow(unused_imports, unused_variables, dead_code)]

use rand::RngCore;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce, Tag,
};
use crate::crypto::constant_time_eq;
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
) -> (Vec<u8>, [u8; 16]) {
    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let cipher_nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let encrypted_with_tag = cipher
        .encrypt(cipher_nonce, payload)
        .expect("ChaCha20Poly1305 encryption must not fail with valid key/nonce");

    let split_idx = encrypted_with_tag.len() - 16;
    let ciphertext = encrypted_with_tag[..split_idx].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&encrypted_with_tag[split_idx..]);

    (ciphertext, tag)
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
            // Lock memory pages to prevent swapping to physical drive
            unsafe {
                libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
            }
        }

        let master_key = VaultKey::generate();
        info!("Initialized Sovereign ChaCha20-Poly1305 Encrypted RAMFS Vault in {VAULT_DIR}");

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
        );

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
            let _ = fs::remove_dir_all(&self.vault_path);
        }

        info!("Sovereign RAMFS Vault destroyed and memory zeroized");
        Ok(())
    }
}
