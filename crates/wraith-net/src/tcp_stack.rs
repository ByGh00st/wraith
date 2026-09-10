//! Wraith TCP/IP Stack Normalizer & p0f Evasion Engine
//! Manipulates kernel L4 network parameters to mask the Linux OS signature against DPI and p0f probes.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::info;
use wraith_core::error::{Result, WraithError};

pub const TARGET_SYSCTL_SETTINGS: &[(&str, &str)] = &[
    // 1. Windows default TTL = 128 (Linux default = 64)
    ("net.ipv4.ip_default_ttl", "128"),
    // 2. Disable TCP timestamps to defeat remote uptime calculation & clock-skew fingerprinting
    ("net.ipv4.tcp_timestamps", "0"),
    // 3. Standardize TCP Window Scaling
    ("net.ipv4.tcp_window_scaling", "1"),
    // 4. Selective Acknowledgements (SACK)
    ("net.ipv4.tcp_sack", "1"),
    // 5. TCP SYN Retries (shortened to prevent SYN-flood & timing profiling)
    ("net.ipv4.tcp_syn_retries", "2"),
    // 6. TCP FIN Timeout
    ("net.ipv4.tcp_fin_timeout", "30"),
    // 7. IANA Standard Ephemeral Port Range (49152 - 65535)
    ("net.ipv4.ip_local_port_range", "49152 65535"),
    // 8. Explicit Congestion Notification (disable to avoid ECN fingerprinting)
    ("net.ipv4.tcp_ecn", "0"),
    // 9. RFC 1337 TIME-WAIT Assassination & RST Fingerprint Protection
    ("net.ipv4.tcp_rfc1337", "1"),
    // 10. Ignore ICMP Echo Broadcasts (anti-smurf / network sweep)
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
    // 11. Ignore Bogus ICMP Error Responses
    ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
    // 12. Strict Challenge ACK rate limit (anti-off-path injection)
    ("net.ipv4.tcp_challenge_ack_limit", "999999999"),
];

pub const DEFAULT_LINUX_SYSCTL_SETTINGS: &[(&str, &str)] = &[
    ("net.ipv4.ip_default_ttl", "64"),
    ("net.ipv4.tcp_timestamps", "1"),
    ("net.ipv4.tcp_window_scaling", "1"),
    ("net.ipv4.tcp_sack", "1"),
    ("net.ipv4.tcp_syn_retries", "6"),
    ("net.ipv4.tcp_fin_timeout", "60"),
    ("net.ipv4.ip_local_port_range", "32768 60999"),
    ("net.ipv4.tcp_ecn", "2"),
    ("net.ipv4.tcp_rfc1337", "0"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
    ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
    ("net.ipv4.tcp_challenge_ack_limit", "1000"),
];

fn sysctl_key_to_proc_path(key: &str) -> String {
    format!("/proc/sys/{}", key.replace('.', "/"))
}

pub fn read_sysctl(key: &str) -> Result<String> {
    let proc_path = sysctl_key_to_proc_path(key);
    let path = Path::new(&proc_path);
    if path.exists() {
        let val = fs::read_to_string(path).map_err(|e| {
            WraithError::Firewall(format!("Failed reading sysctl {key}: {e}"))
        })?;
        Ok(val.trim().to_string())
    } else {
        Ok(String::new())
    }
}

pub fn write_sysctl(key: &str, val: &str) -> Result<()> {
    let proc_path = sysctl_key_to_proc_path(key);
    let path = Path::new(&proc_path);
    if path.exists() {
        fs::write(path, val).map_err(|e| {
            WraithError::Firewall(format!("Failed writing {val} to sysctl {key}: {e}"))
        })?;
    }
    Ok(())
}

pub fn backup_and_apply_tcp_mask() -> Result<HashMap<String, String>> {
    let mut backup = HashMap::new();

    info!("Applying TCP/IP Stack Normalizer (p0f/Nmap OS fingerprint mask & clock-skew evasion)");

    for (key, target_val) in TARGET_SYSCTL_SETTINGS {
        if let Ok(original) = read_sysctl(key) {
            if !original.is_empty() {
                backup.insert(key.to_string(), original);
            }
        }
        let _ = write_sysctl(key, target_val);
    }

    info!("TCP/IP Stack parameters normalized to generic Windows/Standard L4 profile (TS=0, TTL=128)");
    Ok(backup)
}

pub fn restore_default_tcp_stack() -> Result<()> {
    info!("Restoring canonical Linux TCP/IP stack parameters");
    for (key, val) in DEFAULT_LINUX_SYSCTL_SETTINGS {
        let _ = write_sysctl(key, val);
    }
    Ok(())
}

pub fn restore_tcp_stack(backup: &HashMap<String, String>) -> Result<()> {
    info!("Restoring original Linux TCP/IP stack parameters");
    if backup.is_empty() {
        return restore_default_tcp_stack();
    }
    for (key, val) in backup {
        let _ = write_sysctl(key, val);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysctl_key_to_proc_path() {
        assert_eq!(
            sysctl_key_to_proc_path("net.ipv4.tcp_timestamps"),
            "/proc/sys/net/ipv4/tcp_timestamps"
        );
        assert_eq!(
            sysctl_key_to_proc_path("net.ipv4.ip_default_ttl"),
            "/proc/sys/net/ipv4/ip_default_ttl"
        );
    }

    #[test]
    fn test_target_settings_contain_timestamp_and_ttl() {
        let ts_setting = TARGET_SYSCTL_SETTINGS.iter().find(|(k, _)| *k == "net.ipv4.tcp_timestamps");
        assert!(ts_setting.is_some());
        assert_eq!(ts_setting.unwrap().1, "0");

        let ttl_setting = TARGET_SYSCTL_SETTINGS.iter().find(|(k, _)| *k == "net.ipv4.ip_default_ttl");
        assert!(ttl_setting.is_some());
        assert_eq!(ttl_setting.unwrap().1, "128");

        let rfc1337_setting = TARGET_SYSCTL_SETTINGS.iter().find(|(k, _)| *k == "net.ipv4.tcp_rfc1337");
        assert!(rfc1337_setting.is_some());
        assert_eq!(rfc1337_setting.unwrap().1, "1");
    }

    #[test]
    fn test_default_settings_keys_match_target() {
        for (target_key, _) in TARGET_SYSCTL_SETTINGS {
            let default_match = DEFAULT_LINUX_SYSCTL_SETTINGS.iter().find(|(k, _)| k == target_key);
            assert!(default_match.is_some(), "Key {target_key} missing from default settings");
        }
    }
}
