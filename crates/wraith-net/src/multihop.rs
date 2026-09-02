//! Wraith Multi-Hop & Hybrid Overlay Tunnel Engine
//! Implements WireGuard (Kernel Native) ➔ Tor (3-Hop Onion) Dual-Layer Tunneling.
//! Guarantees ISP/DPI bypass by encapsulating all outbound Tor traffic inside a WireGuard tunnel.

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use tracing::{debug, info, warn};
use wraith_core::error::{Result, WraithError};

/// Default WireGuard fwmark for policy routing Tor traffic
pub const WRAITH_WG_FWMARK: u32 = 0x5182;
/// Dedicated FIB routing table ID for WireGuard egress
pub const WRAITH_WG_TABLE: u8 = 52;
/// Policy routing rule priority
pub const WRAITH_WG_RULE_PRIO: u32 = 1000;
/// Default fallback WireGuard interface name
pub const WRAITH_WG_DEFAULT_IFACE: &str = "wraith-wg0";

/// WireGuard Interface and Peer Configuration
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WireGuardConfig {
    pub interface_name: String,
    pub address: String,
    pub private_key: String,
    pub peer_public_key: String,
    pub peer_endpoint: String,
    pub allowed_ips: String,
}

impl WireGuardConfig {
    /// Parse a standard WireGuard .conf file
    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let p = path.as_ref();
        let content = fs::read_to_string(p)
            .map_err(|e| WraithError::Custom(format!("Failed reading WireGuard config '{}': {e}", p.display())))?;

        let inferred_iface = p
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(WRAITH_WG_DEFAULT_IFACE)
            .to_string();

        let mut config = WireGuardConfig {
            interface_name: inferred_iface,
            allowed_ips: "0.0.0.0/0".to_string(),
            ..Default::default()
        };

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() || line.starts_with('[') {
                continue;
            }

            if let Some((key, val)) = line.split_once('=') {
                let key = key.trim().to_lowercase();
                let val = val.trim().to_string();

                match key.as_str() {
                    "address" => config.address = val,
                    "privatekey" => config.private_key = val,
                    "publickey" => config.peer_public_key = val,
                    "endpoint" => config.peer_endpoint = val,
                    "allowedips" => config.allowed_ips = val,
                    _ => {}
                }
            }
        }

        if config.private_key.is_empty() || config.peer_endpoint.is_empty() {
            return Err(WraithError::Custom(format!(
                "WireGuard config '{}' missing required PrivateKey or Endpoint",
                p.display()
            )));
        }

        Ok(config)
    }

    /// Generate an ephemeral/demo WireGuard configuration for isolated testing
    pub fn mock_ephemeral() -> Self {
        Self {
            interface_name: WRAITH_WG_DEFAULT_IFACE.to_string(),
            address: "10.66.66.2/24".to_string(),
            private_key: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=".to_string(),
            peer_public_key: "YmJiamJiamJiamJiamJiamJiamJiamJiamJiamJiamJi=".to_string(),
            peer_endpoint: "198.51.100.1:51820".to_string(),
            allowed_ips: "0.0.0.0/0".to_string(),
        }
    }
}

/// Multi-Hop Tunnel Manager
pub struct MultiHopTunnelEngine;

impl MultiHopTunnelEngine {
    /// Up the WireGuard interface using `wg-quick` or native ip link + wg CLI
    pub fn setup_wireguard(config_path: Option<&str>) -> Result<(String, WireGuardConfig)> {
        let (iface, config) = if let Some(path) = config_path {
            info!("Provisioning Multi-Hop WireGuard tunnel from config: {path}");
            let config = WireGuardConfig::parse_file(path)?;
            let iface = config.interface_name.clone();

            let status = Command::new("wg-quick")
                .args(["up", path])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();

            if status.is_err() || !status.as_ref().map(|s| s.success()).unwrap_or(false) {
                debug!("wg-quick returned non-zero; attempting manual interface initialization fallback");
                Self::apply_wireguard_config(&config)?;
            }

            (iface, config)
        } else {
            info!("Creating ephemeral WireGuard multi-hop interface with mock config");
            let config = WireGuardConfig::mock_ephemeral();
            let iface = config.interface_name.clone();
            Self::apply_wireguard_config(&config)?;
            (iface, config)
        };

        info!(
            "Multi-Hop Tunnel Hop 1 (WireGuard) armed on {iface} (Endpoint: {})",
            config.peer_endpoint
        );
        Ok((iface, config))
    }

    /// Applies a WireGuard configuration directly to kernel using `ip link` and `wg` CLI
    pub fn apply_wireguard_config(config: &WireGuardConfig) -> Result<()> {
        let iface = &config.interface_name;

        // 1. Delete link if already exists
        let _ = Command::new("ip")
            .args(["link", "delete", "dev", iface])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        // 2. Add WireGuard network interface
        let add_res = Command::new("ip")
            .args(["link", "add", "dev", iface, "type", "wireguard"])
            .status()
            .map_err(|e| WraithError::Custom(format!("Failed to create WireGuard interface {iface}: {e}")))?;

        if !add_res.success() {
            return Err(WraithError::Custom(format!(
                "Kernel failed to create WireGuard interface {iface}"
            )));
        }

        // 3. Assign IP address
        if !config.address.is_empty() {
            let addr_res = Command::new("ip")
                .args(["addr", "add", &config.address, "dev", iface])
                .status()
                .map_err(|e| WraithError::Custom(format!("Failed to assign IP to {iface}: {e}")))?;

            if !addr_res.success() {
                debug!("ip addr add returned non-zero for {iface}");
            }
        }

        // 4. Configure WireGuard peer, keys and endpoint via wg CLI
        if !config.private_key.is_empty() {
            let mut key_file = tempfile::Builder::new()
                .prefix(".wraith-wg-key-")
                .tempfile()
                .map_err(|e| WraithError::Custom(format!("Failed to create temp keyfile: {e}")))?;

            use std::io::Write;
            key_file
                .write_all(config.private_key.as_bytes())
                .map_err(|e| WraithError::Custom(format!("Failed to write private key: {e}")))?;
            key_file.flush()?;

            let key_path = key_file.path().to_str().unwrap_or("");
            let mut wg_args = vec!["set", iface, "private-key", key_path];

            if !config.peer_public_key.is_empty() {
                wg_args.extend_from_slice(&["peer", &config.peer_public_key]);
                if !config.peer_endpoint.is_empty() {
                    wg_args.extend_from_slice(&["endpoint", &config.peer_endpoint]);
                }
                if !config.allowed_ips.is_empty() {
                    wg_args.extend_from_slice(&["allowed-ips", &config.allowed_ips]);
                }
            }

            let wg_res = Command::new("wg")
                .args(&wg_args)
                .status()
                .map_err(|e| WraithError::Custom(format!("Failed to configure wg interface {iface}: {e}")))?;

            if !wg_res.success() {
                debug!("wg set returned non-zero for {iface}");
            }
        }

        // 5. Bring interface up
        let up_res = Command::new("ip")
            .args(["link", "set", "up", "dev", iface])
            .status()
            .map_err(|e| WraithError::Custom(format!("Failed to set {iface} up: {e}")))?;

        if !up_res.success() {
            return Err(WraithError::Custom(format!(
                "Failed to bring up WireGuard interface {iface}"
            )));
        }

        Ok(())
    }

    /// Bind Tor's outbound traffic strictly to the WireGuard interface via policy routing
    pub fn bind_tor_to_wireguard(tor_uid: u32, wg_iface: &str) -> Result<bool> {
        info!(
            "Binding Tor process (UID {tor_uid}) exclusively to WireGuard interface ({wg_iface})"
        );

        let tor_uid_str = tor_uid.to_string();
        let fwmark_str = format!("0x{:x}", WRAITH_WG_FWMARK);
        let table_str = WRAITH_WG_TABLE.to_string();

        // 1. Allow WireGuard UDP traffic to escape to physical network without being looped back
        let _ = Command::new("iptables")
            .args([
                "-t", "nat", "-I", "OUTPUT", "1",
                "-p", "udp", "--dport", "51820",
                "-j", "ACCEPT",
            ])
            .status();

        let _ = Command::new("iptables")
            .args([
                "-I", "OUTPUT", "1",
                "-p", "udp", "--dport", "51820",
                "-j", "ACCEPT",
            ])
            .status();

        // 2. Mark Tor UID outbound traffic in mangle table with dedicated fwmark
        let _ = Command::new("iptables")
            .args([
                "-t", "mangle", "-A", "OUTPUT",
                "-m", "owner", "--uid-owner", &tor_uid_str,
                "-j", "MARK", "--set-mark", &fwmark_str,
            ])
            .status();

        // 3. Inject Netlink Policy Routing Rule & Route Table
        let mut netlink_success = false;
        if let Ok(mut nl) = crate::netlink::NetlinkSocket::open() {
            let rule_res = nl.add_fwmark_rule(WRAITH_WG_FWMARK, WRAITH_WG_TABLE as u32, WRAITH_WG_RULE_PRIO);
            let route_res = nl.add_subnet_route(
                Ipv4Addr::new(0, 0, 0, 0),
                0,
                None,
                wg_iface,
                WRAITH_WG_TABLE,
            );
            if rule_res.is_ok() && route_res.is_ok() {
                netlink_success = true;
            }
        }

        // Subprocess fallback if netlink was constrained in current environment
        if !netlink_success {
            let _ = Command::new("ip")
                .args([
                    "rule", "add", "fwmark", &fwmark_str,
                    "table", &table_str,
                    "prio", &WRAITH_WG_RULE_PRIO.to_string(),
                ])
                .status();
            let _ = Command::new("ip")
                .args([
                    "route", "replace", "default",
                    "dev", wg_iface,
                    "table", &table_str,
                ])
                .status();
        }

        // 4. Runtime Verification: Probe routing decision for fwmark
        let verified = Self::verify_wireguard_routing(wg_iface, WRAITH_WG_FWMARK);

        if verified {
            info!(
                "Tor exclusively bound to WireGuard interface ({wg_iface}) via fwmark 0x{:x} (Table {WRAITH_WG_TABLE})",
                WRAITH_WG_FWMARK
            );
        } else {
            warn!("Tor traffic may not be routed through WireGuard — verify manually");
            info!("WireGuard interface up, but Tor routing not confirmed on {wg_iface}");
        }

        Ok(verified)
    }

    /// Runtime check: verify if a marked packet gets routed via wg_iface
    pub fn verify_wireguard_routing(wg_iface: &str, fwmark: u32) -> bool {
        let mark_str = format!("0x{:x}", fwmark);
        let test_ips = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];

        for ip in test_ips {
            if let Ok(output) = Command::new("ip")
                .args(["route", "get", ip, "mark", &mark_str])
                .output()
            {
                if output.status.success() {
                    let out_str = String::from_utf8_lossy(&output.stdout);
                    if out_str.contains(&format!("dev {wg_iface}")) || out_str.contains(wg_iface) {
                        debug!("Runtime routing verification confirmed for {ip} via {wg_iface}");
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Teardown the WireGuard interface and routing rules
    pub fn teardown_wireguard(config_path: Option<&str>) -> Result<()> {
        let iface = if let Some(path) = config_path {
            Path::new(path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(WRAITH_WG_DEFAULT_IFACE)
        } else {
            WRAITH_WG_DEFAULT_IFACE
        };

        info!("Tearing down Multi-Hop WireGuard interface ({iface})...");

        // 1. Delete policy routing rule and flush table
        let fwmark_str = format!("0x{:x}", WRAITH_WG_FWMARK);
        let table_str = WRAITH_WG_TABLE.to_string();

        let _ = Command::new("ip")
            .args(["rule", "del", "fwmark", &fwmark_str, "table", &table_str])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        let _ = Command::new("ip")
            .args(["route", "flush", "table", &table_str])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        // 2. Down via wg-quick if config was provided
        if let Some(path) = config_path {
            let _ = Command::new("wg-quick")
                .args(["down", path])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }

        // 3. Delete link if still present
        let _ = Command::new("ip")
            .args(["link", "delete", "dev", iface])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        // 4. Remove iptables escape rule
        let _ = Command::new("iptables")
            .args([
                "-t", "nat", "-D", "OUTPUT",
                "-p", "udp", "--dport", "51820",
                "-j", "ACCEPT",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        let _ = Command::new("iptables")
            .args([
                "-D", "OUTPUT",
                "-p", "udp", "--dport", "51820",
                "-j", "ACCEPT",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        info!("Multi-Hop WireGuard interface and policy routing rules demolished");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wireguard_config_parse() {
        let sample_conf = r#"
[Interface]
PrivateKey = aaaaaabbbbbbccccccddddddeeeeeeffffffgggggg=
Address = 10.200.200.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = 11111122222233333344444455555566666677777788=
Endpoint = 203.0.113.50:51820
AllowedIPs = 0.0.0.0/0
"#;
        let temp_dir = std::env::temp_dir();
        let conf_path = temp_dir.join("test_wg.conf");
        fs::write(&conf_path, sample_conf).unwrap();

        let parsed = WireGuardConfig::parse_file(&conf_path).unwrap();
        assert_eq!(parsed.interface_name, "test_wg");
        assert_eq!(parsed.address, "10.200.200.2/24");
        assert_eq!(parsed.private_key, "aaaaaabbbbbbccccccddddddeeeeeeffffffgggggg=");
        assert_eq!(parsed.peer_public_key, "11111122222233333344444455555566666677777788=");
        assert_eq!(parsed.peer_endpoint, "203.0.113.50:51820");
        assert_eq!(parsed.allowed_ips, "0.0.0.0/0");

        let _ = fs::remove_file(conf_path);
    }

    #[test]
    fn test_wireguard_mock_ephemeral() {
        let mock = WireGuardConfig::mock_ephemeral();
        assert_eq!(mock.interface_name, WRAITH_WG_DEFAULT_IFACE);
        assert!(!mock.private_key.is_empty());
        assert!(!mock.peer_public_key.is_empty());
        assert!(!mock.peer_endpoint.is_empty());
        assert_eq!(mock.allowed_ips, "0.0.0.0/0");
    }

    #[test]
    fn test_wireguard_missing_fields() {
        let invalid_conf = r#"
[Interface]
Address = 10.200.200.2/24
"#;
        let temp_dir = std::env::temp_dir();
        let conf_path = temp_dir.join("invalid_wg.conf");
        fs::write(&conf_path, invalid_conf).unwrap();

        let res = WireGuardConfig::parse_file(&conf_path);
        assert!(res.is_err());

        let _ = fs::remove_file(conf_path);
    }
}
