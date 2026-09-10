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

    // REDIRECT targets the veth address, but Tor listens on loopback only.
    // DNAT explicitly to loopback, scoped to this veth; never permit forwarding
    // namespace UDP directly to the physical network.
    run_cmd("sysctl", &["-w", &format!("net.ipv4.conf.{VETH_HOST}.route_localnet=1")])?;
    for rule in namespace_rules() {
        let args: Vec<&str> = rule.iter().map(String::as_str).collect();
        if let Err(error) = run_cmd("iptables", &args) {
            let _ = destroy_namespace();
            return Err(error);
        }
    }

    // 9. Normalize TCP/IP stack inside network namespace (Eradicate TCP timestamps & align TTL)
    for (key, val) in crate::tcp_stack::TARGET_SYSCTL_SETTINGS {
        let _ = run_cmd("ip", &["netns", "exec", NAMESPACE_NAME, "sysctl", "-w", &format!("{key}={val}")]);
    }

    info!("Network namespace {} successfully isolated and linked to Tor", NAMESPACE_NAME);
    Ok(())
}

pub fn destroy_namespace() -> Result<()> {
    info!("Demolishing network namespace: {}", NAMESPACE_NAME);

    let _ = run_cmd("ip", &["netns", "delete", NAMESPACE_NAME]);
    let _ = run_cmd("ip", &["link", "delete", VETH_HOST]);
    for mut rule in namespace_rules() {
        if let Some(index) = rule.iter().position(|s| s == "-I") {
            rule[index] = "-D".into();
            rule.remove(index + 2); // insertion position is not part of deletion
        }
        let args: Vec<&str> = rule.iter().map(String::as_str).collect();
        let _ = run_cmd("iptables", &args);
    }

    let netns_dir = format!("/etc/netns/{NAMESPACE_NAME}");
    if Path::new(&netns_dir).exists() {
        let _ = fs::remove_dir_all(&netns_dir);
    }

    info!("Namespace purged");
    Ok(())
}

fn namespace_rules() -> Vec<Vec<String>> {
    let subnet = format!("{NS_SUBNET}.0/24");
    let dns = wraith_core::config::WRAITH_DNS_PORT.to_string();
    let mut rules = Vec::new();
    let mut add = |args: Vec<&str>| rules.push(args.into_iter().map(String::from).collect());
    // General TCP first; the DNS rules inserted later take priority.
    add(vec!["-t", "nat", "-I", "PREROUTING", "1", "-i", VETH_HOST, "-s", &subnet, "-p", "tcp", "--syn", "-j", "DNAT", "--to-destination", "127.0.0.1:9040"]);
    let dns_target = format!("127.0.0.1:{dns}");
    for protocol in ["tcp", "udp"] {
        add(vec!["-t", "nat", "-I", "PREROUTING", "1", "-i", VETH_HOST, "-s", &subnet, "-p", protocol, "--dport", "53", "-j", "DNAT", "--to-destination", &dns_target]);
        add(vec!["-I", "INPUT", "1", "-i", VETH_HOST, "-s", &subnet, "-d", "127.0.0.1", "-p", protocol, "--dport", &dns, "-j", "ACCEPT"]);
    }
    add(vec!["-I", "INPUT", "1", "-i", VETH_HOST, "-s", &subnet, "-d", "127.0.0.1", "-p", "tcp", "--dport", "9040", "-j", "ACCEPT"]);
    add(vec!["-I", "OUTPUT", "1", "-o", VETH_HOST, "-s", "127.0.0.1", "-d", &subnet, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]);
    add(vec!["-I", "FORWARD", "1", "-i", VETH_HOST, "-j", "REJECT"]);
    rules
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn namespace_has_no_direct_forwarding_allow_rule() {
        let rules: Vec<String> = namespace_rules().iter().map(|r| r.join(" ")).collect();
        assert!(rules.iter().any(|r| r == "-I FORWARD 1 -i veth-wr-host -j REJECT"));
        assert!(!rules.iter().any(|r| r.contains("FORWARD") && r.contains("ACCEPT")));
        assert!(rules.iter().any(|r| r.contains("127.0.0.1:5354")));
        assert!(rules.iter().any(|r| r.contains("127.0.0.1:9040")));
        assert!(rules.iter().filter(|r| r.contains("PREROUTING")).all(|r| r.contains("-i veth-wr-host -s 10.200.1.0/24")));
    }
}
