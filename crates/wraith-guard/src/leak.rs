//! Wraith Multi-Vector Leak Verification Engine
//! Verifies IP routing, Tor identity status, IPv6 blocking, and DNS proxying.

use serde::{Deserialize, Serialize};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;
use tracing::warn;
use wraith_core::config::{IP_CHECK_APIS, REQUEST_TIMEOUT_SECS, TOR_CHECK_API};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LeakReport {
    pub ip_address: Option<String>,
    pub is_tor: bool,
    pub dns_leak: bool,
    pub ipv6_leak: bool,
    pub webrtc_leak: bool,
    pub secure: bool,
    pub errors: Vec<String>,
}

pub async fn get_current_ip() -> Option<String> {
    for api in IP_CHECK_APIS {
        let timeout_str = REQUEST_TIMEOUT_SECS.to_string();
        if let Ok(output) = Command::new("curl")
            .args(["-s", "--connect-timeout", &timeout_str, "-m", &timeout_str, api])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    for key in &["ip", "origin", "query"] {
                        if let Some(val) = json.get(key).and_then(|v| v.as_str()) {
                            return Some(val.trim().to_string());
                        }
                    }
                } else {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() && !trimmed.contains('<') {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
    }
    None
}

pub async fn verify_tor_connection() -> (bool, Option<String>) {
    let timeout_str = REQUEST_TIMEOUT_SECS.to_string();
    if let Ok(output) = Command::new("curl")
        .args(["-s", "--connect-timeout", &timeout_str, "-m", &timeout_str, TOR_CHECK_API])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                let is_tor = json.get("IsTor").and_then(|v| v.as_bool()).unwrap_or(false);
                let ip = json.get("IP").and_then(|v| v.as_str()).map(|s| s.to_string());
                return (is_tor, ip);
            }
        }
    }
    (false, None)
}

pub fn check_ipv6_leak() -> bool {
    // Attempt connecting to public IPv6 DNS resolvers (Google / Cloudflare)
    let test_targets = [
        "[2001:4860:4860::8888]:53",
        "[2606:4700:4700::1111]:53",
    ];

    for target in test_targets {
        if let Ok(addr) = target.parse() {
            if TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok() {
                warn!("IPv6 connection succeeded to {target} — LEAK DETECTED!");
                return true;
            }
        }
    }
    false
}

pub fn check_dns_leak() -> bool {
    // Check if we can query directly through system fallback DNS instead of localhost Tor
    if let Ok(output) = Command::new("dig")
        .args(["+short", "myip.opendns.com", "@resolver1.opendns.com"])
        .output()
    {
        if output.status.success() {
            let res = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !res.is_empty() {
                return true; // Direct UDP 53 DNS query escaped Tor!
            }
        }
    }
    false
}

pub async fn run_full_leak_test() -> LeakReport {
    let mut report = LeakReport::default();

    let (is_tor, tor_ip) = verify_tor_connection().await;
    report.is_tor = is_tor;
    report.ip_address = tor_ip.or(get_current_ip().await);

    report.ipv6_leak = check_ipv6_leak();
    report.dns_leak = check_dns_leak();

    report.secure = report.is_tor && !report.ipv6_leak && !report.dns_leak;
    report
}
