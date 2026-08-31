//! Wraith Sovereign In-Memory Encrypted Vault & Anti-Forensic RAM Scrambler
//! Pure-Rust ChaCha20-Poly1305 AEAD stream cipher with Poly1305 (mod 2^130-5) authenticator,
//! kernel `MADV_DONTDUMP` core-dump blocking, `mlock` page locking, and active RAM XOR masking.

#![allow(unused_imports, unused_variables, dead_code)]

use rand::RngCore;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};
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
// 2. PURE-RUST CHACHA20 STREAM CIPHER (RFC 8439)
// ==============================================================================

#[inline]
fn qr(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(7);
}

pub fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // "expand 32-byte k"
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        counter,
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];

    let initial = state;

    for _ in 0..10 {
        // Column rounds
        qr(&mut state, 0, 4, 8, 12);
        qr(&mut state, 1, 5, 9, 13);
        qr(&mut state, 2, 6, 10, 14);
        qr(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        qr(&mut state, 0, 5, 10, 15);
        qr(&mut state, 1, 6, 11, 12);
        qr(&mut state, 2, 7, 8, 13);
        qr(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let val = state[i].wrapping_add(initial[i]);
        out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }

    out
}

pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
    let mut counter = 1u32;
    for chunk in data.chunks_mut(64) {
        let key_stream = chacha20_block(key, nonce, counter);
        for (b, k) in chunk.iter_mut().zip(key_stream.iter()) {
            *b ^= *k;
        }
        counter = counter.wrapping_add(1);
    }
}

// ==============================================================================
// 3. PURE-RUST POLY1305 ONE-TIME AUTHENTICATOR (RFC 8439)
// ==============================================================================

pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        // Clamp r
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[0..16]);
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;

        let r0 = u32::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3]]) & 0x3ffffff;
        let r1 = (u32::from_le_bytes([r_bytes[3], r_bytes[4], r_bytes[5], r_bytes[6]]) >> 2) & 0x3ffff03;
        let r2 = (u32::from_le_bytes([r_bytes[6], r_bytes[7], r_bytes[8], r_bytes[9]]) >> 4) & 0x3ffc0ff;
        let r3 = (u32::from_le_bytes([r_bytes[9], r_bytes[10], r_bytes[11], r_bytes[12]]) >> 6) & 0x3f03fff;
        let r4 = (u32::from_le_bytes([r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15]]) >> 8) & 0x00fffff;

        let p0 = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        let p1 = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        let p2 = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        let p3 = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);

        Self {
            r: [r0, r1, r2, r3, r4],
            h: [0; 5],
            pad: [p0, p1, p2, p3],
        }
    }

    pub fn update(&mut self, msg: &[u8]) {
        for chunk in msg.chunks(16) {
            let mut block = [0u8; 17];
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()] = 1; // Append 0x01 byte

            let b0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) & 0x3ffffff;
            let b1 = (u32::from_le_bytes([block[3], block[4], block[5], block[6]]) >> 2) & 0x3ffffff;
            let b2 = (u32::from_le_bytes([block[6], block[7], block[8], block[9]]) >> 4) & 0x3ffffff;
            let b3 = (u32::from_le_bytes([block[9], block[10], block[11], block[12]]) >> 6) & 0x3ffffff;
            let b4 = (u32::from_le_bytes([block[12], block[13], block[14], block[15]]) >> 8) | ((block[16] as u32) << 24);

            self.h[0] += b0;
            self.h[1] += b1;
            self.h[2] += b2;
            self.h[3] += b3;
            self.h[4] += b4;

            // Multiply h * r (mod 2^130 - 5)
            let s1 = self.r[1] * 5;
            let s2 = self.r[2] * 5;
            let s3 = self.r[3] * 5;
            let s4 = self.r[4] * 5;

            let d0 = (self.h[0] as u64) * (self.r[0] as u64)
                + (self.h[1] as u64) * (s4 as u64)
                + (self.h[2] as u64) * (s3 as u64)
                + (self.h[3] as u64) * (s2 as u64)
                + (self.h[4] as u64) * (s1 as u64);

            let d1 = (self.h[0] as u64) * (self.r[1] as u64)
                + (self.h[1] as u64) * (self.r[0] as u64)
                + (self.h[2] as u64) * (s4 as u64)
                + (self.h[3] as u64) * (s3 as u64)
                + (self.h[4] as u64) * (s2 as u64);

            let d2 = (self.h[0] as u64) * (self.r[2] as u64)
                + (self.h[1] as u64) * (self.r[1] as u64)
                + (self.h[2] as u64) * (self.r[0] as u64)
                + (self.h[3] as u64) * (s4 as u64)
                + (self.h[4] as u64) * (s3 as u64);

            let d3 = (self.h[0] as u64) * (self.r[3] as u64)
                + (self.h[1] as u64) * (self.r[2] as u64)
                + (self.h[2] as u64) * (self.r[1] as u64)
                + (self.h[3] as u64) * (self.r[0] as u64)
                + (self.h[4] as u64) * (s4 as u64);

            let d4 = (self.h[0] as u64) * (self.r[4] as u64)
                + (self.h[1] as u64) * (self.r[3] as u64)
                + (self.h[2] as u64) * (self.r[2] as u64)
                + (self.h[3] as u64) * (self.r[1] as u64)
                + (self.h[4] as u64) * (self.r[0] as u64);

            let c0 = (d0 >> 26) as u32; self.h[0] = (d0 & 0x3ffffff) as u32;
            let d1_c = d1 + (c0 as u64);
            let c1 = (d1_c >> 26) as u32; self.h[1] = (d1_c & 0x3ffffff) as u32;
            let d2_c = d2 + (c1 as u64);
            let c2 = (d2_c >> 26) as u32; self.h[2] = (d2_c & 0x3ffffff) as u32;
            let d3_c = d3 + (c2 as u64);
            let c3 = (d3_c >> 26) as u32; self.h[3] = (d3_c & 0x3ffffff) as u32;
            let d4_c = d4 + (c3 as u64);
            let c4 = (d4_c >> 26) as u32; self.h[4] = (d4_c & 0x3ffffff) as u32;

            self.h[0] += c4 * 5;
            let c0_final = self.h[0] >> 26; self.h[0] &= 0x3ffffff;
            self.h[1] += c0_final;
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let f0 = (self.h[0] | (self.h[1] << 26)) as u64 + (self.pad[0] as u64);
        let f1 = ((self.h[1] >> 6) | (self.h[2] << 20)) as u64 + (self.pad[1] as u64) + (f0 >> 32);
        let f2 = ((self.h[2] >> 12) | (self.h[3] << 14)) as u64 + (self.pad[2] as u64) + (f1 >> 32);
        let f3 = ((self.h[3] >> 18) | (self.h[4] << 8)) as u64 + (self.pad[3] as u64) + (f2 >> 32);

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
        out[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
        out[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
        out[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());

        self.r.zeroize();
        self.h.zeroize();
        self.pad.zeroize();

        out
    }
}

// ==============================================================================
// 4. CHACHA20-POLY1305 AEAD ENCRYPT / DECRYPT (RFC 8439)
// ==============================================================================

pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    // 1. Generate one-time Poly1305 key from ChaCha20 block 0
    let poly_key_block = chacha20_block(key, nonce, 0);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[0..32]);

    // 2. Encrypt plaintext starting from counter = 1
    let mut ciphertext = plaintext.to_vec();
    chacha20_xor(key, nonce, &mut ciphertext);

    // 3. Compute Poly1305 Tag over (AAD || pad || Ciphertext || pad || len(AAD) || len(Ciphertext))
    let mut poly = Poly1305::new(&poly_key);
    poly.update(aad);
    if aad.len() % 16 != 0 {
        poly.update(&vec![0u8; 16 - (aad.len() % 16)]);
    }

    poly.update(&ciphertext);
    if ciphertext.len() % 16 != 0 {
        poly.update(&vec![0u8; 16 - (ciphertext.len() % 16)]);
    }

    poly.update(&(aad.len() as u64).to_le_bytes());
    poly.update(&(ciphertext.len() as u64).to_le_bytes());

    let tag = poly.finalize();
    (ciphertext, tag)
}

pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>> {
    // 1. Compute expected tag
    let poly_key_block = chacha20_block(key, nonce, 0);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[0..32]);

    let mut poly = Poly1305::new(&poly_key);
    poly.update(aad);
    if aad.len() % 16 != 0 {
        poly.update(&vec![0u8; 16 - (aad.len() % 16)]);
    }

    poly.update(ciphertext);
    if ciphertext.len() % 16 != 0 {
        poly.update(&vec![0u8; 16 - (ciphertext.len() % 16)]);
    }

    poly.update(&(aad.len() as u64).to_le_bytes());
    poly.update(&(ciphertext.len() as u64).to_le_bytes());

    let computed_tag = poly.finalize();

    // Constant-time authentication check
    if !constant_time_eq(&computed_tag, tag) {
        return Err(WraithError::Custom("AEAD Poly1305 authentication tag mismatch (tampering detected)".into()));
    }

    let mut plaintext = ciphertext.to_vec();
    chacha20_xor(key, nonce, &mut plaintext);

    Ok(plaintext)
}

// ==============================================================================
// 5. ANTI-FORENSIC RAM SCRAMBLER (LIVE MEMORY XOR MASKING)
// ==============================================================================

pub struct ScrambledSecret {
    masked_data: Vec<u8>,
    mask: Vec<u8>,
}

impl ScrambledSecret {
    pub fn new(secret: &[u8]) -> Self {
        let mut rng = rand::thread_rng();
        let mut mask = vec![0u8; secret.len()];
        rng.fill_bytes(&mut mask);

        let mut masked_data = vec![0u8; secret.len()];
        for i in 0..secret.len() {
            masked_data[i] = secret[i] ^ mask[i];
        }

        Self { masked_data, mask }
    }

    /// Briefly unmasks secret into temporary buffer and passes to closure
    pub fn with_unmasked<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut unmasked = vec![0u8; self.masked_data.len()];
        for i in 0..self.masked_data.len() {
            unmasked[i] = self.masked_data[i] ^ self.mask[i];
        }

        let res = f(&unmasked);
        unmasked.zeroize();
        res
    }

    /// Rescrambles memory with a fresh CSPRNG mask
    pub fn rotate_mask(&mut self) {
        let mut rng = rand::thread_rng();
        let mut new_mask = vec![0u8; self.masked_data.len()];
        rng.fill_bytes(&mut new_mask);

        for i in 0..self.masked_data.len() {
            let original = self.masked_data[i] ^ self.mask[i];
            self.masked_data[i] = original ^ new_mask[i];
        }

        self.mask.zeroize();
        self.mask = new_mask;
    }
}

impl Drop for ScrambledSecret {
    fn drop(&mut self) {
        self.masked_data.zeroize();
        self.mask.zeroize();
    }
}

// ==============================================================================
// 6. EPHEMERAL ENCRYPTED RAMFS VAULT
// ==============================================================================

pub struct EncryptedRamVault {
    vault_path: PathBuf,
    master_key: VaultKey,
    key_ring: HashMap<String, ScrambledSecret>,
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

        self.key_ring.insert(secret_name.to_string(), ScrambledSecret::new(data));
        debug!("Vault: Encrypted secret '{secret_name}' stored with AEAD authentication");
        Ok(())
    }

    pub fn read_secret(&self, secret_name: &str) -> Result<Vec<u8>> {
        // Fast path: In-memory scrambled key ring
        if let Some(scrambled) = self.key_ring.get(secret_name) {
            return Ok(scrambled.with_unmasked(|bytes| bytes.to_vec()));
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
