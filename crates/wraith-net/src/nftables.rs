//! Wraith Firewall Engine — Fail-Closed Architecture
//! TransProxy routing with zero packet leakage guarantee and transactional rollbacks.

use std::io::Write;
use std::process::{Command, Stdio};
use tracing::{debug, error, info};
use wraith_core::config::{LOCAL_NETWORKS, LOOPBACK_NETWORKS, WRAITH_DNS_PORT, TOR_TRANS_PORT, TOR_USER};
use wraith_core::error::{Result, WraithError};

fn execute_command(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| WraithError::Command(format!("Failed to spawn {cmd}: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WraithError::Firewall(format!(
            "{cmd} {:?} failed: {stderr}",
            args
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn get_tor_uid() -> Result<u32> {
    // Match the account actually used by daemon.rs; never exempt all root traffic.
    let uid = execute_command("id", &["-u", TOR_USER])?
        .parse::<u32>().map_err(|_| WraithError::Firewall("Invalid Tor UID".into()))?;
    if uid == 0 {
        return Err(WraithError::Firewall("Tor must use a dedicated non-root account".into()));
    }
    Ok(uid)
}

pub fn save_rules() -> Option<String> {
    let output = Command::new("iptables-save").output().ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

pub fn restore_rules(rules: &str) -> Result<()> {
    restore_rules_with("iptables-restore", rules)
}

pub fn restore_ipv6_rules(rules: &str) -> Result<()> {
    restore_rules_with("ip6tables-restore", rules)
}

fn restore_rules_with(program: &str, rules: &str) -> Result<()> {
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| WraithError::Firewall(format!("Failed to spawn iptables-restore: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(rules.as_bytes())?;
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Failed to restore iptables rules: {stderr}");
        return Err(WraithError::Firewall(format!("Restore failed: {stderr}")));
    }

    info!("Firewall rules restored successfully");
    Ok(())
}

pub fn apply_tor_rules() -> Result<String> {
    apply_tor_rules_for_mode(false)
}

pub fn apply_tor_rules_for_mode(strict: bool) -> Result<String> {
    let saved = save_rules().ok_or_else(|| WraithError::Firewall(
        "Cannot back up firewall; refusing to replace its rules".into()
    ))?;
    let result = install_tor_rules(strict);
    if let Err(error) = result {
        if let Err(rollback) = restore_rules(&saved) {
            return Err(WraithError::Firewall(format!("{error}; rollback failed: {rollback}")));
        }
        return Err(error);
    }
    Ok(saved)
}

fn install_tor_rules(strict: bool) -> Result<()> {
    install_tor_rules_with(strict, get_tor_uid()?, execute_command)
}

fn install_tor_rules_with(
    strict: bool,
    tor_uid: u32,
    mut execute_command: impl FnMut(&str, &[&str]) -> Result<String>,
) -> Result<()> {
    if tor_uid == 0 {
        return Err(WraithError::Firewall("Refusing root Tor exemption".into()));
    }
    let tor_uid_str = tor_uid.to_string();

    info!("Configuring Fail-Closed Tor transparent proxy for UID {}", tor_uid);

    let dns_port_str = WRAITH_DNS_PORT.to_string();
    let trans_port_str = TOR_TRANS_PORT.to_string();

    // Hold fail-closed policies throughout incremental replacement.
    execute_command("iptables", &["-P", "OUTPUT", "DROP"])?;
    execute_command("iptables", &["-P", "INPUT", "DROP"])?;
    execute_command("iptables", &["-P", "FORWARD", "DROP"])?;

    // 1. Flush active filter, nat, and mangle tables
    let flush_cmds = [
        vec!["iptables", "-F"],
        vec!["iptables", "-t", "nat", "-F"],
        vec!["iptables", "-t", "mangle", "-F"],
    ];
    for cmd in flush_cmds {
        execute_command(cmd[0], &cmd[1..])?;
    }

    // ─── NAT Table: Redirect DNS and TCP to Tor ───────────────────────────────
    // 1. Exclude Tor's own process traffic to prevent infinite loops
    execute_command("iptables", &["-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner", &tor_uid_str, "-j", "RETURN"])?;

    // 2. CRITICAL: Redirect ALL DNS queries (port 53 UDP/TCP) to Tor DNSPort (5353) BEFORE loopback exemptions!
    execute_command("iptables", &["-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", &dns_port_str])?;
    execute_command("iptables", &["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", &dns_port_str])?;

    // 3. Bypass NAT for local subnets and loopback networks (AFTER DNS is caught)
    for net in LOOPBACK_NETWORKS.iter().chain(LOCAL_NETWORKS.iter().filter(|_| !strict)) {
        execute_command("iptables", &["-t", "nat", "-A", "OUTPUT", "-d", net, "-j", "RETURN"])?;
    }

    // 4. Redirect cleartext HTTP (port 80) to In-Flight DPI Sanitizer Proxy (9055)
    execute_command("iptables", &[
        "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "--syn", "-j", "REDIRECT", "--to-ports", "9055"
    ])?;

    // 5. Redirect all remaining SYN TCP traffic to Tor TransPort (9040)
    execute_command("iptables", &[
        "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", &trans_port_str
    ])?;

    // ─── FILTER Table: Anti-Nmap & Stealth Inbound Protection (Ghost Mode) ───
    // 1. Set default drop policies for inbound and forward traffic
    execute_command("iptables", &["-P", "INPUT", "DROP"])?;
    execute_command("iptables", &["-P", "FORWARD", "DROP"])?;

    // 2. Allow established and related connections (legitimate return traffic)
    execute_command("iptables", &["-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;

    execute_command("iptables", &["-A", "INPUT", "-p", "udp", "--sport", "67", "--dport", "68", "-j", "ACCEPT"])?;

    // 3. Allow loopback interface traffic explicitly (for local honeypot & proxy)
    execute_command("iptables", &["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])?;

    // 4. Drop all invalid packets (Nmap Stealth NULL, XMAS, FIN scan probes)
    execute_command("iptables", &["-A", "INPUT", "-m", "state", "--state", "INVALID", "-j", "DROP"])?;

    // 5. Drop ICMP Echo Requests (Ping blackout - defeats Nmap ping sweeps)
    execute_command("iptables", &["-A", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "DROP"])?;

    // 6. Drop all inbound TCP SYN port scans on external interfaces
    execute_command("iptables", &["-A", "INPUT", "-p", "tcp", "--syn", "-j", "DROP"])?;

    // 7. Drop all inbound UDP probes on external interfaces
    execute_command("iptables", &["-A", "INPUT", "-p", "udp", "-j", "DROP"])?;

    // ─── FILTER Table: Outbound Fail-Closed Enforcement ───────────────────────
    // Do not grandfather pre-session clearnet sockets through ESTABLISHED.
    // Local proxy traffic and Tor-owned relay sockets are allowed below.

    // Allow loopback interface explicitly
    execute_command("iptables", &["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;

    // Allow Tor's outgoing connection to relays
    execute_command("iptables", &["-A", "OUTPUT", "-m", "owner", "--uid-owner", &tor_uid_str, "-j", "ACCEPT"])?;

    execute_command("iptables", &["-A", "OUTPUT", "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"])?;

    // Allow local LAN subnets
    for net in LOOPBACK_NETWORKS.iter().chain(LOCAL_NETWORKS.iter().filter(|_| !strict)) {
        execute_command("iptables", &["-A", "OUTPUT", "-d", net, "-j", "ACCEPT"])?;
    }

    // Strictly REJECT unrouted TCP/UDP and DROP everything else (Fail-Closed)
    execute_command("iptables", &["-A", "OUTPUT", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"])?;
    execute_command("iptables", &["-A", "OUTPUT", "-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"])?;
    execute_command("iptables", &["-A", "OUTPUT", "-j", "DROP"])?;

    info!("IPv4 Fail-Closed Tor & Anti-Nmap Stealth firewall rules successfully armed");
    Ok(())
}

/// Allows inbound traffic to honeypot decoy ports on external LAN interfaces (for LAN Deception Sensor Mode)
pub fn allow_honey_lan_ports(ports: &[u16]) -> Result<()> {
    if ports.is_empty() {
        return Ok(());
    }
    let ports_str = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
    execute_command(
        "iptables",
        &["-I", "INPUT", "1", "-p", "tcp", "-m", "multiport", "--dports", &ports_str, "-j", "ACCEPT"],
    )?;
    info!("Exempted LAN Honeypot ports ({ports_str}) in INPUT filter table (LAN Deception Sensor Active)");
    Ok(())
}

pub fn flush_rules() -> Result<()> {
    let commands = [
        vec!["iptables", "-P", "INPUT", "ACCEPT"],
        vec!["iptables", "-P", "FORWARD", "ACCEPT"],
        vec!["iptables", "-P", "OUTPUT", "ACCEPT"],
        vec!["iptables", "-t", "nat", "-F"],
        vec!["iptables", "-t", "mangle", "-F"],
        vec!["iptables", "-F"],
        vec!["iptables", "-X"],
    ];

    for cmd in commands {
        if let Err(e) = execute_command(cmd[0], &cmd[1..]) {
            debug!("Firewall flush step '{:?}' notice: {e}", cmd);
        }
    }

    info!("Firewall rules flushed, default ACCEPT restored");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_policy_does_not_allow_existing_clearnet_or_lan() {
        let mut calls = Vec::new();
        install_tor_rules_with(true, 109, |_, args| {
            calls.push(args.join(" "));
            Ok(String::new())
        }).unwrap();
        assert_eq!(calls[0], "-P OUTPUT DROP");
        assert!(!calls.iter().any(|s| s.contains("-A OUTPUT -m state")));
        assert!(!calls.iter().any(|s| s.contains("192.168.") || s.contains("10.0.0.0/8")));
        assert!(calls.iter().any(|s| s == "-A OUTPUT -m owner --uid-owner 109 -j ACCEPT"));
        assert_eq!(calls.last().unwrap(), "-A OUTPUT -j DROP");
    }

    #[test]
    fn refuses_root_and_propagates_failed_rules() {
        assert!(install_tor_rules_with(true, 0, |_, _| panic!("must not mutate")).is_err());
        let mut calls = 0;
        assert!(install_tor_rules_with(true, 109, |_, _| {
            calls += 1;
            Err(WraithError::Firewall("injected failure".into()))
        }).is_err());
        assert_eq!(calls, 1);
    }
}
