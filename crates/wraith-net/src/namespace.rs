//! Wraith Linux Network Namespace Isolation
//! Hardens processes into a virtual network jail where traffic can only exit via Tor.

use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use tracing::info;
use wraith_core::error::{Result, WraithError};

pub const NAMESPACE_NAME: &str = "wraith_ns";
pub const VETH_HOST: &str = "veth-wr-host";
pub const VETH_NS: &str = "veth-wr-ns";
pub const NS_SUBNET: &str = "10.200.1";

fn run_cmd(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| WraithError::Namespace(format!("Failed to execute {cmd}: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WraithError::Namespace(format!("{cmd} {:?} failed: {stderr}", args)));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn is_namespace_active() -> bool {
    Command::new("ip")
        .args(["netns", "list"])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).contains(NAMESPACE_NAME))
        .unwrap_or(false)
}

pub fn create_namespace() -> Result<()> {
    if is_namespace_active() {
        info!("Network namespace {} already exists", NAMESPACE_NAME);
        return Ok(());
    }

    info!("Constructing isolated Linux Network Namespace: {}", NAMESPACE_NAME);

    // 1. Create NetNS
    run_cmd("ip", &["netns", "add", NAMESPACE_NAME])?;

    // 2. Create veth interface pair
    run_cmd("ip", &["link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_NS])?;

    // 3. Move one end into the namespace
    run_cmd("ip", &["link", "set", VETH_NS, "netns", NAMESPACE_NAME])?;

    // 4. Configure host side
    run_cmd("ip", &["addr", "add", &format!("{NS_SUBNET}.1/24"), "dev", VETH_HOST])?;
    run_cmd("ip", &["link", "set", VETH_HOST, "up"])?;

    // 5. Configure namespace side
    run_cmd("ip", &["netns", "exec", NAMESPACE_NAME, "ip", "addr", "add", &format!("{NS_SUBNET}.2/24"), "dev", VETH_NS])?;
    run_cmd("ip", &["netns", "exec", NAMESPACE_NAME, "ip", "link", "set", VETH_NS, "up"])?;
    run_cmd("ip", &["netns", "exec", NAMESPACE_NAME, "ip", "link", "set", "lo", "up"])?;

    // 6. Default route inside namespace -> host veth
    run_cmd("ip", &["netns", "exec", NAMESPACE_NAME, "ip", "route", "add", "default", "via", &format!("{NS_SUBNET}.1")])?;

    // 7. Configure /etc/netns/wraith_ns/resolv.conf for dedicated Tor DNS
    let netns_etc = format!("/etc/netns/{NAMESPACE_NAME}");
    fs::create_dir_all(&netns_etc)?;
    fs::write(format!("{netns_etc}/resolv.conf"), format!("nameserver {NS_SUBNET}.1\n"))?;

    // 8. Host NAT & Forwarding rules
    let _ = run_cmd("iptables", &["-t", "nat", "-A", "POSTROUTING", "-s", &format!("{NS_SUBNET}.0/24"), "-o", "lo", "-j", "MASQUERADE"]);
    let _ = run_cmd("iptables", &["-t", "nat", "-A", "PREROUTING", "-s", &format!("{NS_SUBNET}.0/24"), "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"]);
    let _ = run_cmd("iptables", &["-t", "nat", "-A", "PREROUTING", "-s", &format!("{NS_SUBNET}.0/24"), "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"]);
    let _ = run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]);

    info!("Network namespace {} successfully isolated and linked to Tor", NAMESPACE_NAME);
    Ok(())
}

pub fn destroy_namespace() -> Result<()> {
    if !is_namespace_active() {
        return Ok(());
    }

    info!("Demolishing network namespace: {}", NAMESPACE_NAME);

    let _ = run_cmd("ip", &["netns", "delete", NAMESPACE_NAME]);
    let _ = run_cmd("ip", &["link", "delete", VETH_HOST]);
    let _ = run_cmd("iptables", &["-t", "nat", "-D", "POSTROUTING", "-s", &format!("{NS_SUBNET}.0/24"), "-o", "lo", "-j", "MASQUERADE"]);
    let _ = run_cmd("iptables", &["-t", "nat", "-D", "PREROUTING", "-s", &format!("{NS_SUBNET}.0/24"), "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"]);
    let _ = run_cmd("iptables", &["-t", "nat", "-D", "PREROUTING", "-s", &format!("{NS_SUBNET}.0/24"), "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"]);

    let netns_dir = format!("/etc/netns/{NAMESPACE_NAME}");
    if Path::new(&netns_dir).exists() {
        let _ = fs::remove_dir_all(&netns_dir);
    }

    info!("Namespace purged");
    Ok(())
}

pub fn spawn_in_namespace(command: &str, args: &[&str]) -> Result<Child> {
    if !is_namespace_active() {
        create_namespace()?;
    }

    let mut full_args = vec!["netns", "exec", NAMESPACE_NAME, command];
    full_args.extend_from_slice(args);

    Command::new("ip")
        .args(full_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| WraithError::Namespace(format!("Failed to spawn process in namespace: {e}")))
}
