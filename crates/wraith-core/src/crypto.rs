use std::fmt;
use sha2::{Digest, Sha256 as CoreSha256};
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Constant-time memory equality check to eliminate timing side-channels
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time zero check
#[inline]
pub fn constant_time_is_zero(data: &[u8]) -> bool {
    let mut acc = 0u8;
    for &b in data {
        acc |= b;
    }
    acc.ct_eq(&0u8).into()
}

/// 256-bit Secure Digest with automated zeroization
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Digest256(pub [u8; 32]);

impl fmt::Debug for Digest256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest256(***)")
    }
}

impl fmt::Display for Digest256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// FIPS 180-4 Audited SHA-256 Implementation (Hardware-Accelerated / SIMD)
pub struct Sha256 {
    hasher: CoreSha256,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            hasher: CoreSha256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    pub fn finalize(self) -> Digest256 {
        let result = self.hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        Digest256(digest)
    }

    pub fn digest(data: &[u8]) -> Digest256 {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

type HmacSha256Core = Hmac<CoreSha256>;

/// RFC 2104 Audited HMAC-SHA256 Implementation
pub struct HmacSha256 {
    mac: HmacSha256Core,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mac = HmacSha256Core::new_from_slice(key)
            .unwrap_or_else(|_| {
                let hashed_key = Sha256::digest(key);
                HmacSha256Core::new_from_slice(&hashed_key.0).expect("HMAC 32-byte key must not fail")
            });
        Self { mac }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.mac.update(data);
    }

    pub fn finalize(self) -> Digest256 {
        let result = self.mac.finalize().into_bytes();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        Digest256(digest)
    }

    pub fn mac(key: &[u8], data: &[u8]) -> Digest256 {
        let mut hmac = Self::new(key);
        hmac.update(data);
        hmac.finalize()
    }
}

/// Standard MD5 digest in hex format (used for TLS JA3 Fingerprint calculation)
pub fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

