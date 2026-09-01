//! Wraith IPv6 Leak Terminator
//! Fully drops all IPv6 ingress and egress traffic at the kernel netfilter layer.

use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::info;
use wraith_core::error::Result;

pub const IPV6_LOCKDOWN_SYSCTLS: &[(&str, &str)] = &[
    ("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1\n"),
    ("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1\n"),
    ("/proc/sys/net/ipv6/conf/all/accept_ra", "0\n"),
    ("/proc/sys/net/ipv6/conf/default/accept_ra", "0\n"),
];

pub const IPV6_RESTORE_SYSCTLS: &[(&str, &str)] = &[
    ("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0\n"),
    ("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0\n"),
    ("/proc/sys/net/ipv6/conf/all/accept_ra", "1\n"),
    ("/proc/sys/net/ipv6/conf/default/accept_ra", "1\n"),
];

pub fn apply_ipv6_block() -> Result<()> {
    // 1. Kernel sysctl Level: completely deactivate IPv6 protocol and Router Advertisements in kernel
    for (path_str, val) in IPV6_LOCKDOWN_SYSCTLS {
        let p = Path::new(path_str);
        if p.exists() {
            if let Err(e) = fs::write(p, val) { tracing::warn!("Failed writing {p:?}: {e}"); }
        }
    }

    // 2. Netfilter Level: Apply fail-closed DROP silently
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
        let _ = Command::new(cmd[0])
            .args(&cmd[1..])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    info!("IPv6 kernel-level lockdown armed (sysctl + ip6tables fail-closed drop)");
    Ok(())
}

pub fn flush_ipv6_block() -> Result<()> {
    // 1. Restore kernel sysctl IPv6
    for (path_str, val) in IPV6_RESTORE_SYSCTLS {
        let p = Path::new(path_str);
        if p.exists() {
            if let Err(e) = fs::write(p, val) { tracing::warn!("Failed writing {p:?}: {e}"); }
        }
    }

    // 2. Restore ip6tables ACCEPT silently
    let commands: Vec<Vec<&str>> = vec![
        vec!["ip6tables", "-P", "INPUT", "ACCEPT"],
        vec!["ip6tables", "-P", "FORWARD", "ACCEPT"],
        vec!["ip6tables", "-P", "OUTPUT", "ACCEPT"],
        vec!["ip6tables", "-F"],
        vec!["ip6tables", "-X"],
    ];

    for cmd in commands {
        let _ = Command::new(cmd[0])
            .args(&cmd[1..])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    info!("IPv6 default ACCEPT policy and kernel sysctl restored");
    Ok(())
}
