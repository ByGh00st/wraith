//! Wraith Sovereign Tor Moat Circumvention Engine
//! Implements Tor Project BridgeDB Moat Protocol (JSON-API specification)
//! Automated discovery and challenge-response negotiation for Pluggable Transports
//! (obfs4, snowflake, webtunnel, meek-azure) under hostile network censorship.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info};
use wraith_core::error::{Result, WraithError};

pub const MOAT_DEFAULT_ENDPOINT: &str = "https://bridges.torproject.org/moat";
pub const MOAT_CONTENT_TYPE: &str = "application/vnd.api+json";
pub const MOAT_VERSION: &str = "0.1.0";

/// Moat JSON-API Challenge Response Object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoatChallenge {
    pub id: String,
    pub transport: String,
    pub challenge: String,
    pub image_base64: String,
}

/// Generic Moat JSON-API Resource Data Structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MoatData {
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub data_type: String,
    pub version: Option<String>,
    pub transport: Option<String>,
    pub image: Option<String>,
    pub challenge: Option<String>,
    pub bridges: Option<Vec<String>>,
    pub qrcode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoatEnvelope {
    pub data: Vec<MoatData>,
    #[serde(default)]
    pub errors: Option<Vec<MoatErrorItem>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoatErrorItem {
    pub id: Option<String>,
    pub status: Option<String>,
    pub title: Option<String>,
    pub detail: Option<String>,
}

/// Sovereign Moat Client Engine
pub struct MoatClient {
    endpoint: String,
    timeout_secs: u64,
}

impl Default for MoatClient {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl MoatClient {
    pub fn new(endpoint: Option<&str>, timeout_secs: Option<u64>) -> Self {
        Self {
            endpoint: endpoint.unwrap_or(MOAT_DEFAULT_ENDPOINT).trim_end_matches('/').to_string(),
            timeout_secs: timeout_secs.unwrap_or(10),
        }
    }

    /// Step 1: Request a challenge / CAPTCHA from Moat for the specified transport
    pub async fn fetch_challenge(&self, transport: &str) -> Result<MoatChallenge> {
        let url = format!("{}/fetch", self.endpoint);
        let req_payload = serde_json::json!({
            "data": [
                {
                    "version": MOAT_VERSION,
                    "type": "moat-challenge",
                    "transport": transport
                }
            ]
        });

        info!("🛡️ TOR MOAT: Fetching bridge challenge from {} for transport '{}'", url, transport);
        let resp_bytes = self.post_json_api(&url, &req_payload.to_string()).await?;
        let envelope: MoatEnvelope = serde_json::from_slice(&resp_bytes).map_err(|e| {
            WraithError::Tor(format!("Failed to parse Moat challenge response: {e}"))
        })?;

        if let Some(errs) = envelope.errors {
            if !errs.is_empty() {
                let msg = errs[0].title.clone().unwrap_or_else(|| "Moat challenge error".into());
                return Err(WraithError::Tor(format!("Moat API error: {msg}")));
            }
        }

        let item = envelope.data.into_iter().find(|d| d.data_type == "moat-challenge").ok_or_else(|| {
            WraithError::Tor("Moat response missing 'moat-challenge' payload".into())
        })?;

        let challenge = item.challenge.ok_or_else(|| {
            WraithError::Tor("Moat response missing challenge token".into())
        })?;
        let image_base64 = item.image.unwrap_or_default();
        let id = item.id.unwrap_or_else(|| "1".into());

        Ok(MoatChallenge {
            id,
            transport: transport.to_string(),
            challenge,
            image_base64,
        })
    }

    /// Step 2: Submit challenge solution and obtain fresh bridge descriptors
    pub async fn check_solution(
        &self,
        transport: &str,
        challenge: &str,
        solution: &str,
    ) -> Result<Vec<String>> {
        let url = format!("{}/check", self.endpoint);
        let req_payload = serde_json::json!({
            "data": [
                {
                    "id": "2",
                    "type": "moat-solution",
                    "version": MOAT_VERSION,
                    "transport": transport,
                    "challenge": challenge,
                    "solution": solution.trim(),
                    "qrcode": "false"
                }
            ]
        });

        info!("🛡️ TOR MOAT: Submitting challenge solution to {}...", url);
        let resp_bytes = self.post_json_api(&url, &req_payload.to_string()).await?;
        let envelope: MoatEnvelope = serde_json::from_slice(&resp_bytes).map_err(|e| {
            WraithError::Tor(format!("Failed to parse Moat check response: {e}"))
        })?;

        if let Some(errs) = envelope.errors {
            if !errs.is_empty() {
                let msg = errs[0].title.clone().unwrap_or_else(|| "Invalid challenge solution".into());
                return Err(WraithError::Tor(format!("Moat solution rejected: {msg}")));
            }
        }

        let item = envelope.data.into_iter().find(|d| d.data_type == "moat-bridges").ok_or_else(|| {
            WraithError::Tor("Moat response did not contain 'moat-bridges'".into())
        })?;

        let bridges = item.bridges.ok_or_else(|| {
            WraithError::Tor("Moat bridges list was empty".into())
        })?;

        info!("🛡️ TOR MOAT: Received {} active bridges from BridgeDB", bridges.len());
        Ok(bridges)
    }

    /// Automated bridge discovery with fallback:
    /// Queries Moat, and if unavailable or blocked, falls back to hardened built-in pools.
    pub async fn auto_discover_or_fallback(&self, transport: &str) -> Vec<String> {
        // Attempt circumvention default fetch if available
        match self.fetch_circumvention_defaults(transport).await {
            Ok(bridges) if !bridges.is_empty() => {
                info!("TOR MOAT: Successfully retrieved {} circumvention bridges", bridges.len());
                return bridges;
            }
            Err(e) => {
                debug!("Moat circumvention defaults query bypassed ({e}), utilizing resilient fallback pools");
            }
            _ => {}
        }

        // Return hardened built-in pools based on requested transport
        crate::bridge_discovery::resolve_bridges(
            crate::bridge_discovery::PluggableTransportType::from_str(transport)
                .unwrap_or(crate::bridge_discovery::PluggableTransportType::Obfs4),
            None,
        )
    }

    /// Query Moat circumvention settings / defaults endpoint if supported
    pub async fn fetch_circumvention_defaults(&self, transport: &str) -> Result<Vec<String>> {
        let url = format!("{}/circumvention/builtin", self.endpoint);
        let req_payload = serde_json::json!({
            "transport": transport
        });

        let resp_bytes = self.post_json_api(&url, &req_payload.to_string()).await?;
        if let Ok(envelope) = serde_json::from_slice::<MoatEnvelope>(&resp_bytes) {
            if let Some(item) = envelope.data.into_iter().find(|d| d.bridges.is_some()) {
                if let Some(bridges) = item.bridges {
                    if !bridges.is_empty() {
                        return Ok(bridges);
                    }
                }
            }
        }

        Err(WraithError::Tor("No circumvention defaults returned".into()))
    }

    /// Low-level HTTP POST using `curl` wire-transport with JSON-API headers
    async fn post_json_api(&self, url: &str, body: &str) -> Result<Vec<u8>> {
        if !url.starts_with("https://") {
            return Err(WraithError::Custom(
                "Invalid Moat endpoint URL: must be HTTPS".into(),
            ));
        }

        let timeout_str = self.timeout_secs.to_string();
        let mut child = tokio::process::Command::new("curl")
            .args([
                "-s",
                "-X", "POST",
                "--connect-timeout", "4",
                "-m", &timeout_str,
                "-H", &format!("Content-Type: {MOAT_CONTENT_TYPE}"),
                "-H", &format!("Accept: {MOAT_CONTENT_TYPE}"),
                "--data-binary", "@-",
                "--",
                url,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| WraithError::Network(format!("Failed to spawn Moat request child: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(body.as_bytes()).await;
        }

        let output = child.wait_with_output().await
            .map_err(|e| WraithError::Network(format!("Moat HTTP communication failed: {e}")))?;

        if output.status.success() && !output.stdout.is_empty() {
            Ok(output.stdout)
        } else {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            Err(WraithError::Tor(format!(
                "Moat request failed (HTTP error / connection timeout): {err_msg}"
            )))
        }
    }

    /// Save base64-encoded CAPTCHA challenge PNG to disk
    pub fn save_captcha_image(base64_str: &str, output_path: &Path) -> Result<()> {
        let clean_b64 = base64_str.trim().trim_start_matches("data:image/png;base64,");
        let decoded = decode_base64(clean_b64).map_err(|e| {
            WraithError::Tor(format!("Failed to decode Moat base64 captcha: {e}"))
        })?;

        if let Some(parent) = output_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        std::fs::write(output_path, decoded)?;
        info!("Saved Moat CAPTCHA challenge image to {:?}", output_path);
        Ok(())
    }
}

/// Pure-Rust RFC 4648 Base64 Decoder (Zero external crate dependencies)
pub fn decode_base64(input: &str) -> std::result::Result<Vec<u8>, String> {
    const TABLE: [i8; 256] = {
        let mut t = [-1i8; 256];
        let mut i = 0usize;
        while i < 26 {
            t[b'A' as usize + i] = i as i8;
            t[b'a' as usize + i] = (i + 26) as i8;
            i += 1;
        }
        let mut d = 0usize;
        while d < 10 {
            t[b'0' as usize + d] = (d + 52) as i8;
            d += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &b in bytes {
        if b == b'=' || b == b'\r' || b == b'\n' || b == b' ' {
            continue;
        }
        let val = TABLE[b as usize];
        if val < 0 {
            return Err(format!("Invalid base64 character: {b:#x}"));
        }
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decoder() {
        let text = "Hello Tor Moat Protocol";
        // Base64 of text is SGVsbG8gVG9yIE1vYXQgUHJvdG9jb2w=
        let encoded = "SGVsbG8gVG9yIE1vYXQgUHJvdG9jb2w=";
        let decoded = decode_base64(encoded).expect("Decode failed");
        assert_eq!(String::from_utf8(decoded).unwrap(), text);
    }

    #[test]
    fn test_moat_client_init() {
        let client = MoatClient::new(Some("https://bridges.torproject.org/moat/"), Some(15));
        assert_eq!(client.endpoint, "https://bridges.torproject.org/moat");
        assert_eq!(client.timeout_secs, 15);
    }

    #[test]
    fn test_moat_challenge_parsing() {
        let sample_json = r#"{
            "data": [
                {
                    "id": "1",
                    "type": "moat-challenge",
                    "version": "0.1.0",
                    "transport": "obfs4",
                    "image": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
                    "challenge": "test_token_12345"
                }
            ]
        }"#;

        let envelope: MoatEnvelope = serde_json::from_str(sample_json).expect("Parse failed");
        assert_eq!(envelope.data.len(), 1);
        let challenge = &envelope.data[0];
        assert_eq!(challenge.data_type, "moat-challenge");
        assert_eq!(challenge.challenge.as_deref(), Some("test_token_12345"));
    }
}
