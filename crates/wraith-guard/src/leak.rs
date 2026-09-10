//! Wraith Multi-Vector Leak Verification Engine
//! Verifies IP routing, Tor identity status, IPv6 blocking, and DNS proxying.

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use std::process::Command;
use std::time::Duration;
use tracing::warn;
use wraith_core::config::{IP_CHECK_APIS, REQUEST_TIMEOUT_SECS, TOR_CHECK_API};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LeakReport {
    pub ip_address: Option<String>,
    pub is_tor: bool,
    #[serde(default)]
    pub dns_checked: bool,
    pub dns_leak: bool,
    pub ipv6_leak: bool,
    pub webrtc_leak: bool,
    pub secure: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpGeoInfo {
    pub ip: String,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub is_tor: bool,
}

impl std::fmt::Display for IpGeoInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cc = self.country_code.as_deref().unwrap_or("??");
        let country = self.country_name.as_deref().unwrap_or("Unknown");
        if let Some(city) = &self.city {
            write!(f, "{} [📍 {}] {}, {}", self.ip, cc, country, city)
        } else {
            write!(f, "{} [📍 {}] {}", self.ip, cc, country)
        }
    }
}

pub async fn get_current_ip_geo() -> IpGeoInfo {
    let mut info = IpGeoInfo::default();

    // 1. Authoritative Tor verification via check.torproject.org
    let (is_tor, tor_ip) = verify_tor_connection().await;
    info.is_tor = is_tor;
    if let Some(ref ip) = tor_ip {
        info.ip = ip.clone();
    }

    // 2. Query ipwho.is for full country & city geolocation
    let geo_url = if !info.ip.is_empty() {
        format!("https://ipwho.is/{}", info.ip)
    } else {
        "https://ipwho.is/".to_string()
    };

    if let Ok(output) = query_endpoint(&geo_url, 3).await
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(ip) = json.get("ip").and_then(|v| v.as_str()).and_then(valid_ip) {
                    if info.ip.is_empty() {
                        info.ip = ip.to_string();
                    }
                    info.country_code = json.get("country_code").and_then(|v| v.as_str()).map(|s| s.to_string());
                    info.country_name = json.get("country").and_then(|v| v.as_str()).map(|s| s.to_string());
                    info.city = json.get("city").and_then(|v| v.as_str()).map(|s| s.to_string());
                    return info;
                }
            }
        }
    }

    // 3. Fallback geolocation via api.myip.com
    if let Ok(output) = query_endpoint("https://api.myip.com", 3).await
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(ip) = json.get("ip").and_then(|v| v.as_str()).and_then(valid_ip) {
                    if info.ip.is_empty() {
                        info.ip = ip.to_string();
                    }
                    info.country_code = json.get("cc").and_then(|v| v.as_str()).map(|s| s.to_string());
                    info.country_name = json.get("country").and_then(|v| v.as_str()).map(|s| s.to_string());
                    return info;
                }
            }
        }
    }

    if info.ip.is_empty() {
        info.ip = get_current_ip().await.unwrap_or_else(|| "Hidden".to_string());
    }
    info
}

pub async fn get_current_ip() -> Option<String> {
    for api in IP_CHECK_APIS {
        if let Ok(output) = query_endpoint(api, REQUEST_TIMEOUT_SECS).await
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    for key in &["ip", "origin", "query"] {
                        if let Some(val) = json.get(key).and_then(|v| v.as_str()) {
                            if let Some(ip) = valid_ip(val) { return Some(ip); }
                        }
                    }
                } else {
                    let trimmed = text.trim();
                    if let Some(ip) = valid_ip(trimmed) { return Some(ip); }
                }
            }
        }
    }
    None
}

pub async fn verify_tor_connection() -> (bool, Option<String>) {
    if let Ok(output) = query_endpoint(TOR_CHECK_API, REQUEST_TIMEOUT_SECS).await
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                let is_tor = json.get("IsTor").and_then(|v| v.as_bool()).unwrap_or(false);
                let ip = json.get("IP").and_then(|v| v.as_str()).and_then(valid_ip);
                return (is_tor && ip.is_some(), ip);
            }
        }
    }
    (false, None)
}

pub async fn check_ipv6_leak() -> bool {
    // Attempt connecting to public IPv6 DNS resolvers (Google / Cloudflare)
    let test_targets = [
        "[2001:4860:4860::8888]:53",
        "[2606:4700:4700::1111]:53",
    ];

    for target in test_targets {
        if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(target)).await {
                warn!("IPv6 connection succeeded to {target} — LEAK DETECTED!");
                return true;
        }
    }
    false
}

pub fn check_dns_leak() -> bool {
    // Check if we can query directly through system fallback DNS instead of localhost Tor
    if let Ok(output) = Command::new("dig")
        .args(["+time=2", "+tries=1", "+short", "myip.opendns.com", "@resolver1.opendns.com"])
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
    report.ip_address = match tor_ip { Some(ip) => Some(ip), None => get_current_ip().await };

    report.ipv6_leak = check_ipv6_leak().await;
    // Redirected DNS responses cannot establish whether egress was direct.
    report.dns_checked = false;
    report.errors.push("DNS egress path is inconclusive; resolver responses alone do not establish the route.".into());
    report.errors.push("WebRTC was not tested. Failed IPv6 probes do not prove firewall enforcement.".into());
    if !report.is_tor { report.errors.push("Tor exit could not be verified.".into()); }
    report.secure = report.is_tor && report.dns_checked && !report.ipv6_leak && !report.dns_leak;
    report
}

fn valid_ip(value: &str) -> Option<String> {
    value.trim().parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())
}

async fn query_endpoint(url: &str, seconds: u64) -> std::io::Result<std::process::Output> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(Duration::from_secs(seconds + 1), async {
        let mut child = tokio::process::Command::new("curl")
            .args(["-q", "-s", "--fail", "--proto", "=https", "--proxy", "", "--noproxy", "*", "--connect-timeout", "2", "--max-time"])
            .arg(seconds.to_string()).arg("--").arg(url)
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
            .kill_on_drop(true).spawn()?;
        let mut bytes = Vec::new();
        child.stdout.take().ok_or_else(|| std::io::Error::other("Missing curl output"))?
            .take(65537).read_to_end(&mut bytes).await?;
        if bytes.len() > 65536 { return Err(std::io::Error::other("Diagnostic response exceeds 64 KiB")); }
        let status = child.wait().await?;
        Ok(std::process::Output { status, stdout: bytes, stderr: Vec::new() })
    }).await.map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Diagnostic request timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_error_pages_and_malformed_ip_results() {
        assert_eq!(valid_ip(" 203.0.113.1 ").as_deref(), Some("203.0.113.1"));
        for value in ["error", "<html>", "1.2.3.4/path", "1.2.3.4, 2.3.4.5", "999.1.1.1"] { assert!(valid_ip(value).is_none()); }
    }
}
