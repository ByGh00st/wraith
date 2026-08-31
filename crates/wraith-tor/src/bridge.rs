//! Wraith Tor Bridge & Obfs4 Censorship Evasion
//! Bypasses Deep Packet Inspection (DPI) via pluggable transports.

use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::info;
use wraith_core::config::{TORRC_PATH, TOR_CONTROL_PORT, TOR_DNS_PORT, TOR_TRANS_PORT};
use wraith_core::error::{Result, WraithError};

pub const BUILTIN_BRIDGES: &[&str] = &[
    "obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgTAKQxQ3AX2Fwn2ccJq6SnvnmSAlp77e4Efg iat-mode=0",
    "obfs4 38.229.1.78:80 C8CBDB2464FC9804A69531437BCF2BE31FDD2EE4 cert=Hmyfd2ev46gGY7NoVxA9ngrPF2zCZtzskRTzoWXbxNkzeVnGFPWmrTtILRyqCTjHR+s9dg iat-mode=0",
    "obfs4 85.31.186.98:443 011F2599C0E9B27EE74B353155E244813763C3E5 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOl/SRKVoxho2T5YRl2Nh5hpdcTBbug iat-mode=0",
];

pub fn find_obfs4proxy() -> Option<String> {
    let candidates = [
        "/usr/bin/obfs4proxy",
        "/usr/local/bin/obfs4proxy",
        "/usr/bin/lyrebird",
    ];

    for c in candidates {
        if Path::new(c).exists() {
            return Some(c.to_string());
        }
    }

    if let Ok(output) = Command::new("which").arg("obfs4proxy").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(path);
            }
        }
    }

    None
}

pub fn write_bridge_torrc(custom_bridges: Option<Vec<String>>) -> Result<usize> {
    let obfs4_path = find_obfs4proxy().ok_or_else(|| {
        WraithError::Tor("obfs4proxy not found! Install with: sudo apt install obfs4proxy".into())
    })?;

    let bridges: Vec<String> = match custom_bridges {
        Some(b) if !b.is_empty() => b,
        _ => {
            tracing::warn!("Built-in obfs4 bridges are public and may degrade/decay over time. Configure custom bridges via BridgeDB (https://bridges.torproject.org) if blocked.");
            BUILTIN_BRIDGES.iter().map(|s| s.to_string()).collect()
        }
    };

    let count = bridges.len();
    let bridge_lines = bridges
        .iter()
        .map(|b| format!("Bridge {b}"))
        .collect::<Vec<_>>()
        .join("\n");

    let content = format!(
        "\
VirtualAddrNetwork 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort {TOR_TRANS_PORT}
DNSPort {TOR_DNS_PORT}
ControlPort {TOR_CONTROL_PORT}
RunAsDaemon 1
CookieAuthentication 1
AvoidDiskWrites 1
UseBridges 1
ClientTransportPlugin obfs4 exec {obfs4_path}
{bridge_lines}
"
    );

    let path = Path::new(TORRC_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(path, content)?;
    info!("Bridge torrc written with {count} obfs4 bridges");
    Ok(count)
}
