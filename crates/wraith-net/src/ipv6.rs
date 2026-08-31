//! Wraith IPv6 Leak Terminator
//! Fully drops all IPv6 ingress and egress traffic at the kernel netfilter layer.

use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};
use wraith_core::error::{Result, WraithError};

const IPV6_SYSCTL_PATHS: &[&str] = &[
    "/proc/sys/net/ipv6/conf/all/disable_ipv6",
    "/proc/sys/net/ipv6/conf/default/disable_ipv6",
    "/proc/sys/net/ipv6/conf/all/accept_ra",
    "/proc/sys/net/ipv6/conf/default/accept_ra",
];

pub fn apply_ipv6_block() -> Result<()> {
    // 1. Kernel sysctl Level: completely deactivate IPv6 protocol and Router Advertisements in kernel
    for path_str in IPV6_SYSCTL_PATHS {
        let p = Path::new(path_str);
        if p.exists() {
            let _ = fs::write(p, "1\n");
        }
    }

    // 2. Netfilter Level: Check if ip6tables is available and apply fail-closed DROP
    if Command::new("which").arg("ip6tables").output().is_err() {
        warn!("ip6tables binary not found, sysctl IPv6 lockdown active");
        return Ok(());
    }

    let commands: Vec<Vec<&str>> = vec![
        vec!["ip6tables", "-F"],
        vec!["ip6tables", "-X"],
        vec!["ip6tables", "-P", "INPUT", "DROP"],
        vec!["ip6tables", "-P", "FORWARD", "DROP"],
        vec!["ip6tables", "-P", "OUTPUT", "DROP"],
        vec!["ip6tables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
        vec!["ip6tables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
    ];

    for cmd in commands {
        let status = Command::new(cmd[0]).args(&cmd[1..]).status();
        if let Err(e) = status {
            return Err(WraithError::Firewall(format!("Failed executing {}: {e}", cmd[0])));
        }
    }

    info!("IPv6 kernel-level lockdown armed (sysctl + ip6tables fail-closed drop)");
    Ok(())
}

pub fn flush_ipv6_block() -> Result<()> {
    // 1. Restore kernel sysctl IPv6
    for path_str in IPV6_SYSCTL_PATHS {
        let p = Path::new(path_str);
        if p.exists() {
            let _ = fs::write(p, "0\n");
        }
    }

    // 2. Restore ip6tables ACCEPT
    let commands: Vec<Vec<&str>> = vec![
        vec!["ip6tables", "-P", "INPUT", "ACCEPT"],
        vec!["ip6tables", "-P", "FORWARD", "ACCEPT"],
        vec!["ip6tables", "-P", "OUTPUT", "ACCEPT"],
        vec!["ip6tables", "-F"],
        vec!["ip6tables", "-X"],
    ];

    for cmd in commands {
        let _ = Command::new(cmd[0]).args(&cmd[1..]).status();
    }

    info!("IPv6 default ACCEPT policy and kernel sysctl restored");
    Ok(())
}
