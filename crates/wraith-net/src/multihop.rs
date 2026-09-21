//! Wraith Multi-Hop & Hybrid Overlay Tunnel Engine
//! Implements WireGuard (Kernel Native) ➔ Tor (3-Hop Onion) Dual-Layer Tunneling.
//! Guarantees ISP/DPI bypass by encapsulating all outbound Tor traffic inside a WireGuard tunnel.

use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::{debug, info};
use wraith_core::error::{Result, WraithError};

fn checked_status(command: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(command).args(args).output()?;
    if !output.status.success() {
        return Err(WraithError::Network(format!("{command} failed: {}", String::from_utf8_lossy(&output.stderr))));
    }
    Ok(())
}

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
    pub preshared_key: Option<String>,
    pub persistent_keepalive: Option<u16>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u16>,
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

        let mut peers = 0;
        for line in content.lines() {
            if line.trim().eq_ignore_ascii_case("[Peer]") {
                peers += 1;
                if peers > 1 { return Err(WraithError::Configuration("Wraith supports one WireGuard peer per tunnel".into())); }
            }
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
                    "presharedkey" => config.preshared_key = Some(val),
                    "persistentkeepalive" => config.persistent_keepalive = Some(val.parse().map_err(|_| WraithError::Configuration("Invalid WireGuard keepalive".into()))?),
                    "listenport" => config.listen_port = Some(val.parse().map_err(|_| WraithError::Configuration("Invalid WireGuard listen port".into()))?),
                    "mtu" => config.mtu = Some(val.parse().map_err(|_| WraithError::Configuration("Invalid WireGuard MTU".into()))?),
                    "dns" => {}, // Wraith's validated DNS relay owns resolver policy.
                    "preup" | "postup" | "predown" | "postdown" | "table" =>
                        return Err(WraithError::Configuration("WireGuard shell hooks and custom tables are not supported".into())),
                    _ => return Err(WraithError::Configuration(format!("Unsupported WireGuard option: {key}"))),
                }
            }
        }

        if config.private_key.is_empty() || config.peer_endpoint.is_empty() {
            return Err(WraithError::Custom(format!(
                "WireGuard config '{}' missing required PrivateKey or Endpoint",
                p.display()
            )));
        }

        validate_config(&config)?;
        Ok(config)
    }

    /// Generate an ephemeral/demo WireGuard configuration for isolated testing
    pub fn mock_ephemeral() -> Self {
        Self {
            interface_name: WRAITH_WG_DEFAULT_IFACE.to_string(),
            address: "10.66.66.2/24".to_string(),
            private_key: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=".to_string(),
            peer_public_key: "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=".to_string(),
            peer_endpoint: "198.51.100.1:51820".to_string(),
            allowed_ips: "0.0.0.0/0".to_string(),
            ..Default::default()
        }
    }
}

/// Multi-Hop Tunnel Manager
pub struct MultiHopTunnelEngine;

impl MultiHopTunnelEngine {
    /// Create a dedicated WireGuard interface without shell hooks or global routes.
    pub fn setup_wireguard(config_path: Option<&str>) -> Result<(String, WireGuardConfig)> {
        let path = config_path.ok_or_else(|| WraithError::Configuration("An explicit WireGuard configuration is required".into()))?;
        let config = WireGuardConfig::parse_file(path)?;
        Self::preflight_wireguard(path)?;
        Self::apply_wireguard_config(&config)?;
        Ok((config.interface_name.clone(), config))
    }

    /// Refuse resource collisions before the CLI records ownership.
    pub fn preflight_wireguard(path: &str) -> Result<()> {
        let config = WireGuardConfig::parse_file(path)?;
        if link_details(&config.interface_name)?.is_some() {
            return Err(WraithError::Network("WireGuard interface already exists; it will not be replaced".into()));
        }
        if !table_routes()?.trim().is_empty() {
            return Err(WraithError::Network("WireGuard routing table 52 is already in use".into()));
        }
        let rules = ip_output(&["rule", "show"])?;
        if rules.lines().any(|line| line.split_whitespace().next() == Some("1000:") || line.contains("fwmark 0x5182") || line.split_whitespace().collect::<Vec<_>>().windows(2).any(|p| p == ["lookup", "52"])) {
            return Err(WraithError::Network("WireGuard routing priority or mark is already in use".into()));
        }
        Ok(())
    }

    /// Applies a WireGuard configuration directly to kernel using `ip link` and `wg` CLI
    pub fn apply_wireguard_config(config: &WireGuardConfig) -> Result<()> {
        let iface = &config.interface_name;

        validate_config(config)?;
        // `add` never replaces a pre-existing interface. The alias identifies
        // exactly the resource cleanup is allowed to remove.
        checked_status("ip", &["link", "add", "name", iface, "alias", "wraith-wireguard", "type", "wireguard"])?;

        // 3. Assign IP address
        if !config.address.is_empty() {
            let addr_res = Command::new("ip")
                .args(["addr", "add", &config.address, "dev", iface])
                .status()
                .map_err(|e| WraithError::Custom(format!("Failed to assign IP to {iface}: {e}")))?;

            if !addr_res.success() {
                return Err(WraithError::Network(format!("ip addr add failed for {iface}")));
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
            let listen_port = config.listen_port.map(|port| port.to_string());
            if let Some(ref port) = listen_port { wg_args.extend_from_slice(&["listen-port", port]); }
            let keepalive = config.persistent_keepalive.map(|seconds| seconds.to_string());
            let mut preshared = if let Some(ref key) = config.preshared_key {
                let mut file = tempfile::NamedTempFile::new()?;
                file.write_all(key.as_bytes())?; file.flush()?;
                Some(file)
            } else { None };
            let preshared_path = preshared.as_mut().map(|file| file.path().to_string_lossy().into_owned());

            if !config.peer_public_key.is_empty() {
                wg_args.extend_from_slice(&["peer", &config.peer_public_key]);
                if let Some(ref path) = preshared_path { wg_args.extend_from_slice(&["preshared-key", path]); }
                if let Some(ref seconds) = keepalive { wg_args.extend_from_slice(&["persistent-keepalive", seconds]); }
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
                return Err(WraithError::Network(format!("wg set failed for {iface}")));
            }
        }

        if let Some(mtu) = config.mtu {
            checked_status("ip", &["link", "set", "dev", iface, "mtu", &mtu.to_string()])?;
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

        if tor_uid == 0 {
            return Err(WraithError::Network("WireGuard binding requires a non-root Tor UID".into()));
        }
        // Only WireGuard's kernel-marked outer UDP packets may bypass Tor.
        // A destination-port-only exemption lets any app leak arbitrary UDP.
        let transport_mark = "0x5183";
        checked_status("wg", &["set", wg_iface, "fwmark", transport_mark])?;
        checked_status("iptables", &["-I", "OUTPUT", "1", "-m", "mark", "--mark", transport_mark, "-p", "udp", "-j", "ACCEPT"])?;
        checked_status("iptables", &["-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", &tor_uid_str, "!", "-o", wg_iface, "-j", "REJECT"])?;
        checked_status("iptables", &["-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"])?;

        // 2. Mark Tor UID outbound traffic in mangle table with dedicated fwmark
        checked_status("iptables", &["-t", "mangle", "-A", "OUTPUT", "-m", "owner", "--uid-owner", &tor_uid_str, "-j", "MARK", "--set-mark", &fwmark_str])?;

        // No unchecked fallback or route replacement of another owner's table.
        checked_status("ip", &["rule", "add", "fwmark", &fwmark_str, "table", &table_str,
            "prio", &WRAITH_WG_RULE_PRIO.to_string()])?;
        checked_status("ip", &["route", "add", "default", "dev", wg_iface, "table", &table_str])?;
        if !Self::verify_wireguard_routing(wg_iface, WRAITH_WG_FWMARK) {
            return Err(WraithError::Network("WireGuard routing verification failed".into()));
        }
        Ok(true)
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
                    if out_str.split_whitespace().collect::<Vec<_>>().windows(2).any(|pair| pair == ["dev", wg_iface]) {
                        debug!("Runtime routing verification confirmed for {ip} via {wg_iface}");
                        continue;
                    }
                }
            }
            return false;
        }
        true
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

        validate_interface_name(iface)?;
        if let Some(link) = link_details(iface)? {
            if link.get("ifalias").and_then(|v| v.as_str()) != Some("wraith-wireguard") {
                return Err(WraithError::Network("Refusing to remove an unowned WireGuard interface".into()));
            }
            checked_status("ip", &["link", "delete", "dev", iface])?;
        }
        // Link deletion removes routes through that link; never flush table 52.
        let rules = ip_output(&["rule", "show"])?;
        for line in rules.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.first() == Some(&"1000:") && fields.windows(2).any(|p| p == ["fwmark", "0x5182"])
                {
                checked_status("ip", &["rule", "del", "fwmark", "0x5182", "table", "52", "prio", "1000"])?;
            }
        }
        let remaining_rules = ip_output(&["rule", "show"])?;
        if link_details(iface)?.is_some() || !table_routes()?.trim().is_empty()
            || remaining_rules.lines().any(|line| line.starts_with("1000:") && line.contains("fwmark 0x5182")) {
            return Err(WraithError::Network("WireGuard cleanup incomplete; recovery record retained".into()));
        }
        Ok(())
    }

}

fn validate_interface_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 15 || name.starts_with('-')
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)) {
        return Err(WraithError::Configuration("Invalid WireGuard interface name".into()));
    }
    Ok(())
}

fn validate_config(config: &WireGuardConfig) -> Result<()> {
    validate_interface_name(&config.interface_name)?;
    let valid_key = |key: &str| key.len() == 44 && key.ends_with('=')
        && key.as_bytes()[..43].iter().all(|b| b.is_ascii_alphanumeric() || b"+/".contains(b));
    if !valid_key(&config.private_key) || !valid_key(&config.peer_public_key)
        || config.preshared_key.as_deref().is_some_and(|key| !valid_key(key)) {
        return Err(WraithError::Configuration("WireGuard keys must encode 32 bytes".into()));
    }
    if config.mtu.is_some_and(|mtu| !(576..=9000).contains(&mtu)) {
        return Err(WraithError::Configuration("WireGuard MTU must be 576..=9000".into()));
    }
    let address = config.address.split_once('/').ok_or_else(|| WraithError::Configuration("WireGuard requires an IPv4 CIDR address".into()))?;
    if address.0.parse::<std::net::Ipv4Addr>().is_err() || !address.1.parse::<u8>().is_ok_and(|n| n <= 32)
        || !config.peer_endpoint.parse::<std::net::SocketAddrV4>().is_ok_and(|a| a.port() > 0)
        || config.allowed_ips != "0.0.0.0/0" {
        return Err(WraithError::Configuration("WireGuard requires IPv4 Address, numeric IPv4 Endpoint and AllowedIPs = 0.0.0.0/0".into()));
    }
    Ok(())
}

fn ip_output(args: &[&str]) -> Result<String> {
    let output = Command::new("ip").env("LC_ALL", "C").args(args).output()?;
    if !output.status.success() { return Err(WraithError::Network(String::from_utf8_lossy(&output.stderr).into_owned())); }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
fn table_routes() -> Result<String> {
    let output = Command::new("ip").env("LC_ALL", "C").args(["route", "show", "table", "52"]).output()?;
    if !output.status.success() && !String::from_utf8_lossy(&output.stderr).contains("FIB table does not exist") {
        return Err(WraithError::Network("Cannot inspect WireGuard route table".into()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
fn link_details(iface: &str) -> Result<Option<serde_json::Value>> {
    let links: Vec<serde_json::Value> = serde_json::from_str(&ip_output(&["-j", "link", "show"])?)?;
    Ok(links.into_iter().find(|link| link.get("ifname").and_then(|v| v.as_str()) == Some(iface)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_tunnel_configuration_is_rejected_before_commands() {
        let mut config = WireGuardConfig::mock_ephemeral();
        config.peer_public_key = "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=".into();
        assert!(validate_config(&config).is_ok());
        for name in ["", "-bad", "name with space", "1234567890123456"] {
            let mut invalid = config.clone(); invalid.interface_name = name.into();
            assert!(validate_config(&invalid).is_err());
        }
        config.allowed_ips = "10.0.0.0/8".into();
        assert!(validate_config(&config).is_err());
    }
    #[test]
    fn shell_hooks_and_multiple_peers_are_not_silently_accepted() {
        let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("wgtest.conf");
        for config in ["[Interface]\nPostUp = arbitrary command", "[Peer]\n[Peer]\n"] {
            fs::write(&path, config).unwrap();
            assert!(WireGuardConfig::parse_file(&path).is_err());
        }
    }
    #[test]
    fn test_wireguard_config_parse() {
        let sample_conf = r#"
[Interface]
PrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
Address = 10.200.200.2/24
DNS = 1.1.1.1
MTU = 1420
ListenPort = 51820

[Peer]
PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=
Endpoint = 203.0.113.50:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
PresharedKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
"#;
        let temp_dir = tempfile::tempdir().unwrap();
        let conf_path = temp_dir.path().join("test_wg.conf");
        fs::write(&conf_path, sample_conf).unwrap();

        let parsed = WireGuardConfig::parse_file(&conf_path).unwrap();
        assert_eq!(parsed.interface_name, "test_wg");
        assert_eq!(parsed.address, "10.200.200.2/24");
        assert_eq!(parsed.private_key, "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=");
        assert_eq!(parsed.peer_public_key, "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=");
        assert_eq!(parsed.peer_endpoint, "203.0.113.50:51820");
        assert_eq!(parsed.allowed_ips, "0.0.0.0/0");
        assert_eq!(parsed.mtu, Some(1420));
        assert_eq!(parsed.listen_port, Some(51820));
        assert_eq!(parsed.persistent_keepalive, Some(25));
        assert!(parsed.preshared_key.is_some());

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
