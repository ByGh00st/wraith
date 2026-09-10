//! Wraith Sovereign Network Interface Discovery & Selector Engine
//! Provides zero-subprocess Linux kernel / sysfs / getifaddrs network interface discovery,
//! classification (physical vs virtual, wireless vs wired), and validation.

use serde::{Deserialize, Serialize};
use std::fmt;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use tracing::{debug, info};
use wraith_core::error::{Result, WraithError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceState {
    Up,
    Down,
    Dormant,
    Unknown,
}

impl fmt::Display for InterfaceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Up => write!(f, "UP"),
            Self::Down => write!(f, "DOWN"),
            Self::Dormant => write!(f, "DORMANT"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub index: u32,
    pub name: String,
    pub mac: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub state: InterfaceState,
    pub is_wireless: bool,
    pub is_loopback: bool,
    pub is_virtual: bool,
    pub mtu: u32,
    pub driver: Option<String>,
    pub speed_mbps: Option<u32>,
}

impl NetworkInterface {
    /// Summary display format for logs and TUI menus
    pub fn summary(&self) -> String {
        let kind = if self.is_loopback {
            "LOOPBACK"
        } else if self.is_wireless {
            "WLAN"
        } else if self.is_virtual {
            "VIRTUAL"
        } else {
            "ETHERNET"
        };

        let ip_display = self.ipv4.as_deref().unwrap_or("-");
        let mac_display = self.mac.as_deref().unwrap_or("--:--:--:--:--:--");

        format!(
            "[{}] {} ({}) | MAC: {} | IP: {} | MTU: {}",
            self.state, self.name, kind, mac_display, ip_display, self.mtu
        )
    }
}

/// Enumerate all network interfaces present in the system
pub fn list_all_interfaces() -> Result<Vec<NetworkInterface>> {
    #[cfg(unix)]
    {
        enumerate_unix_interfaces()
    }
    #[cfg(not(unix))]
    {
        enumerate_fallback_interfaces()
    }
}

/// Enumerate physical network interfaces suitable for L2/L3 anonymization
/// Filters out loopbacks, bridge devices, virtual container veths, wireguard, and tun/tap tunnels
pub fn list_physical_interfaces() -> Result<Vec<NetworkInterface>> {
    let all = list_all_interfaces()?;
    let physical: Vec<NetworkInterface> = all
        .into_iter()
        .filter(|iface| {
            if iface.is_loopback {
                return false;
            }

            // Exclude virtual device signatures
            if iface.is_virtual {
                return false;
            }

            let name = &iface.name;
            if name.starts_with("veth")
                || name.starts_with("docker")
                || name.starts_with("virbr")
                || name.starts_with("br-")
                || name.starts_with("tun")
                || name.starts_with("tap")
                || name.starts_with("wg")
                || name.starts_with("tailscale")
                || name.starts_with("zt")
                || name.starts_with("dummy")
                || name == "lo"
            {
                return false;
            }

            // Must have a valid MAC address that is not empty or all zeroes
            if let Some(ref mac) = iface.mac {
                if mac == "00:00:00:00:00:00" || mac.is_empty() {
                    return false;
                }
            } else {
                return false;
            }

            true
        })
        .collect();

    Ok(physical)
}

/// Auto-select the best candidate network interface for routing
/// Prioritizes:
/// 1. Active default route interface (if available and not loopback)
/// 2. Physical interface in UP state with an IPv4 address
/// 3. Physical interface in UP state
/// 4. Any physical interface
pub fn get_best_active_interface() -> Result<String> {
    // 1. Try kernel default route first
    if let Ok(default_iface) = crate::get_default_interface() {
        if default_iface != "lo" && !default_iface.trim().is_empty() {
            return Ok(default_iface);
        }
    }

    // 2. Query physical candidate interfaces
    let physical = list_physical_interfaces()?;
    if let Some(up_with_ip) = physical.iter().find(|i| i.state == InterfaceState::Up && i.ipv4.is_some()) {
        return Ok(up_with_ip.name.clone());
    }

    if let Some(up_iface) = physical.iter().find(|i| i.state == InterfaceState::Up) {
        return Ok(up_iface.name.clone());
    }

    if let Some(first_physical) = physical.first() {
        return Ok(first_physical.name.clone());
    }

    Err(WraithError::Hardware(
        "No suitable physical network interface detected on system (only loopback or virtual tunnels present)".to_string()
    ))
}

/// Validate that a requested network interface exists, is physical or accessible, and can be managed
pub fn validate_interface(name: &str) -> Result<NetworkInterface> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(WraithError::Hardware(
            "Interface name cannot be empty".to_string(),
        ));
    }

    let interfaces = list_all_interfaces()?;
    for iface in interfaces {
        if iface.name == trimmed {
            if iface.is_loopback {
                return Err(WraithError::Hardware(format!(
                    "Loopback interface '{trimmed}' cannot be used as target anonymization adapter"
                )));
            }
            return Ok(iface);
        }
    }

    Err(WraithError::Hardware(format!(
        "Network interface '{trimmed}' not found on host system"
    )))
}

#[cfg(unix)]
fn enumerate_unix_interfaces() -> Result<Vec<NetworkInterface>> {
    use std::collections::HashMap;
    use std::ffi::CStr;

    let mut addrs_map: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();

    // Query IPv4 and IPv6 addresses via libc::getifaddrs
    // SAFETY: getifaddrs allocates linked list freed properly by freeifaddrs
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) == 0 && !ifap.is_null() {
            let mut cur = ifap;
            while !cur.is_null() {
                let ifa = *cur;
                if !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() {
                    let c_name = CStr::from_ptr(ifa.ifa_name);
                    if let Ok(name) = c_name.to_str() {
                        let entry = addrs_map.entry(name.to_string()).or_insert((None, None));
                        let family = (*ifa.ifa_addr).sa_family as i32;

                        if family == libc::AF_INET {
                            let sin = ifa.ifa_addr as *const libc::sockaddr_in;
                            let ip = std::net::Ipv4Addr::from(u32::from_be((*sin).sin_addr.s_addr));
                            entry.0 = Some(ip.to_string());
                        } else if family == libc::AF_INET6 {
                            let sin6 = ifa.ifa_addr as *const libc::sockaddr_in6;
                            let ip6 = std::net::Ipv6Addr::from((*sin6).sin6_addr.s6_addr);
                            // Store global IPv6 or first non-empty IPv6
                            if entry.1.is_none() || !ip6.is_loopback() {
                                entry.1 = Some(ip6.to_string());
                            }
                        }
                    }
                }
                cur = ifa.ifa_next;
            }
            libc::freeifaddrs(ifap);
        }
    }

    let net_sysfs = Path::new("/sys/class/net");
    if !net_sysfs.exists() || !net_sysfs.is_dir() {
        debug!("/sys/class/net not found, falling back to getifaddrs dictionary");
        let mut fallback_list = Vec::new();
        for (idx, (name, (ipv4, ipv6))) in (1..).zip(addrs_map) {
            let is_loopback = name == "lo";
            fallback_list.push(NetworkInterface {
                index: idx,
                name,
                mac: None,
                ipv4,
                ipv6,
                state: InterfaceState::Unknown,
                is_wireless: false,
                is_loopback,
                is_virtual: !is_loopback,
                mtu: 1500,
                driver: None,
                speed_mbps: None,
            });
        }
        return Ok(fallback_list);
    }

    let mut interfaces = Vec::new();
    let entries = fs::read_dir(net_sysfs)
        .map_err(|e| WraithError::Hardware(format!("Failed to read /sys/class/net: {e}")))?;

    for entry in entries.flatten() {
        let ifname = entry.file_name().to_string_lossy().to_string();
        let ifpath = entry.path();

        // 1. Index
        let index = fs::read_to_string(ifpath.join("ifindex"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0);

        // 2. Operstate
        let state = fs::read_to_string(ifpath.join("operstate"))
            .map(|s| match s.trim().to_lowercase().as_str() {
                "up" => InterfaceState::Up,
                "down" => InterfaceState::Down,
                "dormant" => InterfaceState::Dormant,
                _ => InterfaceState::Unknown,
            })
            .unwrap_or(InterfaceState::Unknown);

        // 3. Flags
        let flags_raw = fs::read_to_string(ifpath.join("flags"))
            .ok()
            .and_then(|s| {
                let clean = s.trim().trim_start_matches("0x");
                u32::from_str_radix(clean, 16).ok()
            })
            .unwrap_or(0);
        let is_loopback = ifname == "lo" || (flags_raw & 0x8) != 0;

        // 4. MAC Address
        let mac = fs::read_to_string(ifpath.join("address"))
            .ok()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty() && s != "00:00:00:00:00:00");

        // 5. MTU
        let mtu = fs::read_to_string(ifpath.join("mtu"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(1500);

        // 6. Wireless detection
        let is_wireless = ifpath.join("wireless").exists() || ifpath.join("phy80211").exists();

        // 7. Virtual detection
        let is_virtual = is_virtual_device(&ifpath, &ifname);

        // 8. Driver
        let driver = fs::read_link(ifpath.join("device/driver"))
            .ok()
            .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()));

        // 9. Speed
        let speed_mbps = fs::read_to_string(ifpath.join("speed"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());

        // 10. IP addresses from map
        let (ipv4, ipv6) = addrs_map.remove(&ifname).unwrap_or((None, None));

        interfaces.push(NetworkInterface {
            index,
            name: ifname,
            mac,
            ipv4,
            ipv6,
            state,
            is_wireless,
            is_loopback,
            is_virtual,
            mtu,
            driver,
            speed_mbps,
        });
    }

    interfaces.sort_by_key(|iface| iface.index);
    info!("Kernel Sysfs: Enumerated {} network interfaces", interfaces.len());
    Ok(interfaces)
}

#[cfg(unix)]
fn is_virtual_device(ifpath: &Path, ifname: &str) -> bool {
    if ifname == "lo" {
        return false;
    }

    if let Ok(device_link) = fs::read_link(ifpath.join("device")) {
        let link_str = device_link.to_string_lossy();
        if link_str.contains("/devices/virtual/") {
            return true;
        }
    } else {
        // No device link usually means virtual interface in Linux sysfs
        let virtual_path = Path::new("/sys/devices/virtual/net").join(ifname);
        if virtual_path.exists() {
            return true;
        }
    }

    false
}

#[cfg(not(unix))]
fn enumerate_fallback_interfaces() -> Result<Vec<NetworkInterface>> {
    Ok(vec![
        NetworkInterface {
            index: 1,
            name: "lo".to_string(),
            mac: None,
            ipv4: Some("127.0.0.1".to_string()),
            ipv6: Some("::1".to_string()),
            state: InterfaceState::Up,
            is_wireless: false,
            is_loopback: true,
            is_virtual: false,
            mtu: 65536,
            driver: None,
            speed_mbps: None,
        },
        NetworkInterface {
            index: 2,
            name: "eth0".to_string(),
            mac: Some("00:0c:29:11:22:33".to_string()),
            ipv4: Some("192.168.1.100".to_string()),
            ipv6: None,
            state: InterfaceState::Up,
            is_wireless: false,
            is_loopback: false,
            is_virtual: false,
            mtu: 1500,
            driver: Some("e1000".to_string()),
            speed_mbps: Some(1000),
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_state_display() {
        assert_eq!(InterfaceState::Up.to_string(), "UP");
        assert_eq!(InterfaceState::Down.to_string(), "DOWN");
        assert_eq!(InterfaceState::Dormant.to_string(), "DORMANT");
        assert_eq!(InterfaceState::Unknown.to_string(), "UNKNOWN");
    }

    #[test]
    fn test_list_all_interfaces_not_empty() {
        let list = list_all_interfaces().expect("Should enumerate interfaces");
        assert!(!list.is_empty(), "Interface list should contain at least 1 interface");
    }

    #[test]
    fn test_validate_interface_rejects_empty() {
        let res = validate_interface("");
        assert!(res.is_err());
    }

    #[test]
    fn test_summary_format() {
        let iface = NetworkInterface {
            index: 1,
            name: "eth0".to_string(),
            mac: Some("00:11:22:33:44:55".to_string()),
            ipv4: Some("10.0.0.2".to_string()),
            ipv6: None,
            state: InterfaceState::Up,
            is_wireless: false,
            is_loopback: false,
            is_virtual: false,
            mtu: 1500,
            driver: Some("e1000".to_string()),
            speed_mbps: Some(1000),
        };
        let summary = iface.summary();
        assert!(summary.contains("eth0"));
        assert!(summary.contains("ETHERNET"));
        assert!(summary.contains("00:11:22:33:44:55"));
    }

    #[test]
    fn test_get_best_active_interface_never_returns_loopback() {
        if let Ok(best) = get_best_active_interface() {
            assert_ne!(best, "lo", "Best active interface must never be loopback 'lo'");
            assert!(!best.is_empty());
        }
    }
}
