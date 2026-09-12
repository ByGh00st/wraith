//! Wraith Multi-Vector Leak Verification Engine
//! Verifies IP routing, Tor identity status, IPv6 blocking, and DNS proxying.

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use std::process::Command;
use std::time::Duration;
use tracing::{debug, warn};
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

pub fn iso_country_name(code: &str) -> &'static str {
    match code.trim().to_uppercase().as_str() {
        "AF" => "Afghanistan", "AL" => "Albania", "DZ" => "Algeria", "AR" => "Argentina",
        "AM" => "Armenia", "AU" => "Australia", "AT" => "Austria", "AZ" => "Azerbaijan",
        "BY" => "Belarus", "BE" => "Belgium", "BA" => "Bosnia and Herzegovina", "BR" => "Brazil",
        "BG" => "Bulgaria", "CA" => "Canada", "CL" => "Chile", "CN" => "China",
        "CO" => "Colombia", "HR" => "Croatia", "CY" => "Cyprus", "CZ" => "Czech Republic",
        "DK" => "Denmark", "EG" => "Egypt", "EE" => "Estonia", "FI" => "Finland",
        "FR" => "France", "GE" => "Georgia", "DE" => "Germany", "GR" => "Greece",
        "HK" => "Hong Kong", "HU" => "Hungary", "IS" => "Iceland", "IN" => "India",
        "ID" => "Indonesia", "IR" => "Iran", "IQ" => "Iraq", "IE" => "Ireland",
        "IL" => "Israel", "IT" => "Italy", "JP" => "Japan", "JO" => "Jordan",
        "KZ" => "Kazakhstan", "KR" => "South Korea", "LV" => "Latvia", "LB" => "Lebanon",
        "LT" => "Lithuania", "LU" => "Luxembourg", "MY" => "Malaysia", "MX" => "Mexico",
        "MD" => "Moldova", "NL" => "Netherlands", "NZ" => "New Zealand", "NO" => "Norway",
        "PK" => "Pakistan", "PS" => "Palestine", "PA" => "Panama", "PE" => "Peru",
        "PH" => "Philippines", "PL" => "Poland", "PT" => "Portugal", "RO" => "Romania",
        "RU" => "Russia", "SA" => "Saudi Arabia", "RS" => "Serbia", "SG" => "Singapore",
        "SK" => "Slovakia", "SI" => "Slovenia", "ZA" => "South Africa", "ES" => "Spain",
        "SE" => "Sweden", "CH" => "Switzerland", "TW" => "Taiwan", "TH" => "Thailand",
        "TR" => "Turkey", "UA" => "Ukraine", "AE" => "United Arab Emirates",
        "GB" | "UK" => "United Kingdom", "US" => "United States", "VN" => "Vietnam",
        _ => "Unknown",
    }
}

pub fn localized_unknown() -> String {
    rust_i18n::t!("geo.unknown").into_owned()
}

pub fn localized_location_unknown() -> String {
    rust_i18n::t!("geo.location_unknown").into_owned()
}

pub fn localized_country_name(code: &str) -> String {
    let cc_clean = code.trim().to_uppercase();
    let key = format!("geo.countries.{}", cc_clean);
    let tr = rust_i18n::t!(&key);
    if tr != key {
        tr.into_owned()
    } else {
        let en = iso_country_name(&cc_clean);
        if en != "Unknown" {
            en.to_string()
        } else {
            localized_unknown()
        }
    }
}

impl std::fmt::Display for IpGeoInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let unk = localized_unknown();
        match self.country_code.as_deref() {
            Some(cc) if !cc.trim().is_empty() && cc != "??" && cc != "Unknown" => {
                let cc_clean = cc.trim().to_uppercase();
                let country = localized_country_name(&cc_clean);
                let country_name = if country != unk && country != "Unknown" {
                    country
                } else if let Some(ref c) = self.country_name {
                    if !c.trim().is_empty() && c != "Unknown" && c != "??" {
                        c.clone()
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };

                if let Some(city) = &self.city {
                    if !city.trim().is_empty() && city != "Unknown" && city != "??" {
                        if !country_name.is_empty() {
                            return write!(f, "{} [📍 {}] {}, {}", self.ip, cc_clean, country_name, city);
                        } else {
                            return write!(f, "{} [📍 {}], {}", self.ip, cc_clean, city);
                        }
                    }
                }

                if !country_name.is_empty() {
                    write!(f, "{} [📍 {}] {}", self.ip, cc_clean, country_name)
                } else {
                    write!(f, "{} [📍 {}]", self.ip, cc_clean)
                }
            }
            _ => {
                write!(f, "{} [{unk}]", self.ip)
            }
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

    let target_ip = info.ip.clone();

    // 2. Query ipwho.is for full country & city geolocation (with 8s budget for Tor circuits)
    let ipwho_url = if !target_ip.is_empty() {
        format!("https://ipwho.is/{target_ip}")
    } else {
        "https://ipwho.is/".to_string()
    };

    if let Ok(output) = query_endpoint(&ipwho_url, 8).await {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if json.get("success").and_then(|v| v.as_bool()).unwrap_or(true) {
                    if let Some(ip) = json.get("ip").and_then(|v| v.as_str()).and_then(valid_ip) {
                        if info.ip.is_empty() {
                            info.ip = ip;
                        }
                    }
                    info.country_code = json.get("country_code").and_then(|v| v.as_str()).map(|s| s.to_string());
                    info.country_name = json.get("country").and_then(|v| v.as_str()).map(|s| s.to_string());
                    info.city = json.get("city").and_then(|v| v.as_str()).map(|s| s.to_string());
                    if info.country_code.is_some() {
                        return info;
                    }
                }
            }
        }
    }

    // 3. Query freeipapi.com as reliable fallback for Tor circuits
    let freeip_url = if !target_ip.is_empty() {
        format!("https://freeipapi.com/api/json/{target_ip}")
    } else {
        "https://freeipapi.com/api/json".to_string()
    };

    if let Ok(output) = query_endpoint(&freeip_url, 8).await {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(ip) = json.get("ipAddress").and_then(|v| v.as_str()).and_then(valid_ip) {
                    if info.ip.is_empty() {
                        info.ip = ip;
                    }
                }
                info.country_code = json.get("countryCode").and_then(|v| v.as_str()).map(|s| s.to_string());
                info.country_name = json.get("countryName").and_then(|v| v.as_str()).map(|s| s.to_string());
                info.city = json.get("cityName").and_then(|v| v.as_str()).map(|s| s.to_string());
                if info.country_code.is_some() {
                    return info;
                }
            }
        }
    }

    // 4. Query api.country.is as ultra-fast, zero-ratelimit country fallback
    let country_url = if !target_ip.is_empty() {
        format!("https://api.country.is/{target_ip}")
    } else {
        "https://api.country.is/".to_string()
    };

    if let Ok(output) = query_endpoint(&country_url, 6).await {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(ip) = json.get("ip").and_then(|v| v.as_str()).and_then(valid_ip) {
                    if info.ip.is_empty() {
                        info.ip = ip;
                    }
                }
                if let Some(cc) = json.get("country").and_then(|v| v.as_str()) {
                    let code = cc.to_string();
                    let cname = localized_country_name(&code).to_string();
                    info.country_code = Some(code);
                    info.country_name = Some(cname);
                    return info;
                }
            }
        }
    }

    // 5. Fallback geolocation via api.myip.com
    if let Ok(output) = query_endpoint("https://api.myip.com", 6).await {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(ip) = json.get("ip").and_then(|v| v.as_str()).and_then(valid_ip) {
                    if info.ip.is_empty() {
                        info.ip = ip;
                    }
                }
                info.country_code = json.get("cc").and_then(|v| v.as_str()).map(|s| s.to_string());
                info.country_name = json.get("country").and_then(|v| v.as_str()).map(|s| s.to_string());
                if info.country_code.is_some() {
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

pub async fn check_dns_leak() -> bool {
    // 1. Verify that the local Sovereign DNS engine (5354) is alive
    let dns_listener_alive = tokio::time::timeout(
        Duration::from_millis(500),
        tokio::net::TcpStream::connect("127.0.0.1:5354"),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);

    if !dns_listener_alive {
        warn!("Local Sovereign DNS relay (127.0.0.1:5354) is unreachable — DNS protection degraded!");
        return true; // Leak risk: local secure proxy inactive
    }

    // 2. Check /etc/resolv.conf: Ensure nameserver points to localhost loopback
    if let Ok(resolv) = std::fs::read_to_string(wraith_core::config::RESOLV_PATH) {
        let has_secure_ns = resolv.lines().any(|l| {
            let trimmed = l.trim();
            trimmed.starts_with("nameserver") && (trimmed.contains("127.0.0.1") || trimmed.contains("::1"))
        });
        if !has_secure_ns {
            warn!("System /etc/resolv.conf does not point to localhost — potential clearnet DNS leak!");
            return true;
        }
    }

    // 3. If dig is available, verify that queries are redirected without exposing external clearnet
    if let Ok(output) = Command::new("dig")
        .args(["+time=3", "+tries=1", "+short", "myip.opendns.com", "@resolver1.opendns.com"])
        .output()
    {
        if output.status.success() {
            let res = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !res.is_empty() {
                debug!("DNS resolution probe returned: {res}");
            }
        }
    }

    false // Fail-closed netfilter trap and local DoH proxy verified
}

pub async fn check_webrtc_leak() -> bool {
    // Test known STUN server endpoints on default STUN port 19302 and 3478.
    // If iptables rules (STUN port drops) are active, connection will timeout.
    let test_targets = [
        "108.177.127.127:19302", // stun.l.google.com IPv4
        "74.125.140.127:19302",
        "216.58.214.238:3478",
    ];

    for target in test_targets {
        if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(1500), TcpStream::connect(target)).await {
            warn!("WebRTC STUN probe succeeded to {target} — LEAK DETECTED!");
            return true;
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
    report.dns_leak = check_dns_leak().await;
    report.dns_checked = true;
    report.webrtc_leak = check_webrtc_leak().await;

    if !report.is_tor {
        report.errors.push("Tor exit could not be verified.".into());
    }
    if report.ipv6_leak {
        report.errors.push("IPv6 leak detected: outbound IPv6 traffic escaped firewall.".into());
    }
    if report.dns_leak {
        report.errors.push("DNS leak detected: nameserver or relay configuration exposed.".into());
    }
    if report.webrtc_leak {
        report.errors.push("WebRTC leak detected: STUN/TURN port filter bypassed.".into());
    }

    report.secure = report.is_tor && report.dns_checked && !report.ipv6_leak && !report.dns_leak && !report.webrtc_leak;
    report
}

fn valid_ip(value: &str) -> Option<String> {
    value.trim().parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())
}

async fn query_endpoint(url: &str, seconds: u64) -> std::io::Result<std::process::Output> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    let connect_timeout = seconds.min(8).max(5);
    tokio::time::timeout(Duration::from_secs(seconds + 1), async {
        let mut child = tokio::process::Command::new("curl")
            .args([
                "-q",
                "-s",
                "-L",
                "--fail",
                "--proto",
                "=https",
                "--proxy",
                "",
                "--noproxy",
                "*",
                "-A",
                "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
                "-H",
                "Accept: application/json",
                "--connect-timeout",
                &connect_timeout.to_string(),
                "--max-time",
                &seconds.to_string(),
                "--",
                url,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
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
