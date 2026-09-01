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
    // 5. TCP SYN Retries
    ("net.ipv4.tcp_syn_retries", "2"),
    // 6. TCP FIN Timeout
    ("net.ipv4.tcp_fin_timeout", "30"),
    // 7. IANA Standard Ephemeral Port Range (49152 - 65535)
    ("net.ipv4.ip_local_port_range", "49152 65535"),
    // 8. Explicit Congestion Notification
    ("net.ipv4.tcp_ecn", "0"),
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

    info!("Applying TCP/IP Stack Normalizer (p0f/Nmap OS fingerprint mask)");

    for (key, target_val) in TARGET_SYSCTL_SETTINGS {
        if let Ok(original) = read_sysctl(key) {
            if !original.is_empty() {
                backup.insert(key.to_string(), original);
            }
        }
        let _ = write_sysctl(key, target_val);
    }

    info!("TCP/IP Stack parameters normalized to generic Windows/Standard L4 profile");
    Ok(backup)
}

pub fn restore_tcp_stack(backup: &HashMap<String, String>) -> Result<()> {
    info!("Restoring original Linux TCP/IP stack parameters");
    for (key, val) in backup {
        let _ = write_sysctl(key, val);
    }
    Ok(())
}
