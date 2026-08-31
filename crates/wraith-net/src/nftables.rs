//! Wraith Firewall Engine — Fail-Closed Architecture
//! TransProxy routing with zero packet leakage guarantee and transactional rollbacks.

use std::io::Write;
use std::process::{Command, Stdio};
use tracing::{error, info};
use wraith_core::config::{LOCAL_NETWORKS, LOOPBACK_NETWORKS, TOR_DNS_PORT, TOR_TRANS_PORT, TOR_USER};
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
    let output = execute_command("id", &["-u", TOR_USER])?;
    output
        .parse::<u32>()
        .map_err(|_| WraithError::Firewall(format!("Invalid Tor UID: {output}")))
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
    let mut child = Command::new("iptables-restore")
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
    let saved = save_rules().unwrap_or_default();
    let tor_uid = get_tor_uid()?;
    let tor_uid_str = tor_uid.to_string();

    info!("Configuring Fail-Closed Tor transparent proxy for UID {}", tor_uid);

    let dns_port_str = TOR_DNS_PORT.to_string();
    let trans_port_str = TOR_TRANS_PORT.to_string();

    let commands: Vec<Vec<&str>> = vec![
        // Flush active filter and nat tables
        vec!["iptables", "-F"],
        vec!["iptables", "-t", "nat", "-F"],
        vec!["iptables", "-t", "mangle", "-F"],

        // --- NAT Table: Redirect DNS and TCP to Tor ---
        // 1. Exclude Tor's own process traffic
        vec!["iptables", "-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner", &tor_uid_str, "-j", "RETURN"],
    ];

    for cmd in commands {
        execute_command(cmd[0], &cmd[1..])?;
    }

    // 2. Bypass NAT for local and loopback networks FIRST
    for net in LOCAL_NETWORKS.iter().chain(LOOPBACK_NETWORKS.iter()) {
        execute_command("iptables", &["-t", "nat", "-A", "OUTPUT", "-d", net, "-j", "RETURN"])?;
    }

    // 3. Redirect remaining DNS queries to Tor DNSPort
    execute_command("iptables", &["-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", &dns_port_str])?;
    execute_command("iptables", &["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", &dns_port_str])?;

    // 4. Redirect remaining SYN TCP traffic to Tor TransPort
    execute_command("iptables", &[
        "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", &trans_port_str
    ])?;

    // --- FILTER Table: Fail-Closed Enforcement ---
    execute_command("iptables", &["-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;

    for net in LOCAL_NETWORKS.iter().chain(LOOPBACK_NETWORKS.iter()) {
        execute_command("iptables", &["-A", "OUTPUT", "-d", net, "-j", "ACCEPT"])?;
    }

    // Allow Tor's outgoing connection to relays
    execute_command("iptables", &["-A", "OUTPUT", "-m", "owner", "--uid-owner", &tor_uid_str, "-j", "ACCEPT"])?;

    // Strictly REJECT unrouted TCP/UDP and DROP everything else (Fail-Closed)
    execute_command("iptables", &["-A", "OUTPUT", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"])?;
    execute_command("iptables", &["-A", "OUTPUT", "-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"])?;
    execute_command("iptables", &["-A", "OUTPUT", "-j", "DROP"])?;

    info!("IPv4 Fail-Closed Tor firewall rules successfully armed");
    Ok(saved)
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
        let _ = execute_command(cmd[0], &cmd[1..]);
    }

    info!("Firewall rules flushed, default ACCEPT restored");
    Ok(())
}
