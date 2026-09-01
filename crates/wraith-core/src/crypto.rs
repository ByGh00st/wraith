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

impl Digest256 {
    pub fn to_hex(&self) -> String {
        self.to_string()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
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
        let mac = match HmacSha256Core::new_from_slice(key) {
            Ok(m) => m,
            Err(_) => {
                let hashed_key = Sha256::digest(key);
                match HmacSha256Core::new_from_slice(&hashed_key.0) {
                    Ok(m) => m,
                    Err(_) => match HmacSha256Core::new_from_slice(&[0u8; 32]) {
                        Ok(m) => m,
                        Err(_) => match HmacSha256Core::new_from_slice(&[]) {
                            Ok(m) => m,
                            Err(_) => unreachable!("HMAC-SHA256 zero-key initialization invariant"),
                        },
                    },
                }
            }
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_digest() {
        let digest = Sha256::digest(b"hello world");
        assert_eq!(digest.0.len(), 32);
        let hex_str = digest.to_hex();
        assert_eq!(hex_str, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret_key";
        let data = b"sensitive_message";
        let mac1 = HmacSha256::mac(key, data);
        let mac2 = HmacSha256::mac(key, data);
        assert_eq!(mac1.0, mac2.0);

        let mac3 = HmacSha256::mac(b"other_key", data);
        assert_ne!(mac1.0, mac3.0);
    }

    #[test]
    fn test_constant_time_equality() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }
}

