//! Wraith Linux Network Namespace Isolation
//! Hardens processes into a virtual network jail where traffic can only exit via Tor.

use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use tracing::info;
use wraith_core::error::{Result, WraithError};
use wraith_core::tcp_fingerprint::TcpFingerprintProfile;
use crate::tcp_stack::NetnsTcpSnapshot;

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
        .map(|out| String::from_utf8_lossy(&out.stdout).lines().any(|line| line.split_whitespace().next() == Some(NAMESPACE_NAME)))
        .unwrap_or(false)
}

/// Check ownership collisions before any namespace resource is journaled.
pub fn preflight_namespace() -> Result<()> {
    let namespaces = run_cmd("ip", &["netns", "list"])?;
    let links = run_cmd("ip", &["-o", "link", "show"])?;
    if namespaces.lines().any(|line| line.split_whitespace().next() == Some(NAMESPACE_NAME))
        || links.lines().any(|line| line.split_whitespace().nth(1).is_some_and(|name|
            [VETH_HOST, VETH_NS].contains(&name.trim_end_matches(':').split('@').next().unwrap_or(""))))
        || fs::symlink_metadata(format!("/etc/netns/{NAMESPACE_NAME}")).is_ok() {
        return Err(WraithError::Namespace("Namespace resources already exist; recover the previous session first".into()));
    }
    Ok(())
}

/// Constructs an isolated Network Namespace and arms 3-tier L4 TCP stack morphing
/// with the specified `TcpFingerprintProfile`.
pub fn create_namespace_with_l4_profile(profile: &TcpFingerprintProfile) -> Result<NetnsTcpSnapshot> {
    create_namespace_with_optional_l4_profile(Some(profile))?
        .ok_or_else(|| WraithError::Namespace("Missing L4 snapshot".into()))
}

/// Build isolation even when morphing is explicitly off. Any setup failure tears
/// down resources owned by this attempt; the caller journals teardown for crash recovery.
pub fn create_namespace_with_optional_l4_profile(profile: Option<&TcpFingerprintProfile>) -> Result<Option<NetnsTcpSnapshot>> {
    if let Some(profile) = profile { profile.validate().map_err(crate::tcp_stack::TcpMorphError::from)?; }
    preflight_namespace()?;
    let namespace_mac = crate::mac::generate_namespace_mac()?;
    info!("Constructing isolated Linux Network Namespace: {}", NAMESPACE_NAME);
    // Do not tear down anything if acquiring the namespace name itself fails.
    run_cmd("ip", &["netns", "add", NAMESPACE_NAME])?;
    let namespace = crate::tcp_namespace::Namespace::open(NAMESPACE_NAME)?;
    let lease = match crate::recovery::begin_namespace(namespace.identity, namespace_mac) {
        Ok(lease) => lease,
        Err(error) => {
            if crate::tcp_namespace::Namespace::open(NAMESPACE_NAME)?.identity == namespace.identity {
                run_cmd("ip", &["netns", "delete", NAMESPACE_NAME])?;
            }
            return Err(error);
        },
    };
    let result = (|| -> Result<Option<NetnsTcpSnapshot>> {
        // 2. Create veth interface pair
        run_cmd("ip", &["link", "add", VETH_HOST, "alias", &lease.tag,
            "type", "veth", "peer", "name", VETH_NS, "alias", &lease.tag])?;

        // 3. Move one end into the namespace
        run_cmd("ip", &["link", "set", VETH_NS, "netns", NAMESPACE_NAME])?;

        // Set and read back the local-unicast address before either veth is UP.
        configure_namespace_mac(&lease.mac, |args| run_cmd("ip", args))?;

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
        fs::write(format!("{netns_etc}/resolv.conf"), format!("nameserver {NS_SUBNET}.1\n"))?;

        // REDIRECT targets the veth address, but Tor listens on loopback only.
        // DNAT explicitly to loopback, scoped to this veth; never permit forwarding
        // namespace UDP directly to the physical network.
        run_cmd("sysctl", &["-w", &format!("net.ipv4.conf.{VETH_HOST}.route_localnet=1")])?;
        for rule in tagged_namespace_rules(Some(&lease.tag)) {
            let args: Vec<&str> = rule.iter().map(String::as_str).collect();
            run_cmd("iptables", &args)?;
        }

        // Apply all three tiers before the namespace is exposed as ready.
        let snapshot = profile.map(|profile|
            crate::tcp_stack::apply_profile_to_netns(NAMESPACE_NAME, profile, true)
        ).transpose()?;
        Ok(snapshot)
    })();
    let snapshot = match result {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return match destroy_namespace() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(WraithError::Namespace(format!("{error}; cleanup incomplete: {cleanup}"))),
            };
        }
    };
    info!("Network namespace {} successfully isolated and linked to Tor", NAMESPACE_NAME);
    Ok(snapshot)
}

/// Backward-compatible namespace creation applying default Windows 11 L4 TCP profile
pub fn create_namespace() -> Result<()> {
    let default_profile = TcpFingerprintProfile::windows11();
    create_namespace_with_l4_profile(&default_profile).map(|_| ())
}

pub fn destroy_namespace() -> Result<()> {
    destroy_namespace_with_identity(None)
}

pub fn destroy_namespace_with_identity(expected: Option<crate::tcp_stack::NamespaceIdentity>) -> Result<()> {
    if crate::recovery::cleanup_owned_namespace()? { return Ok(()); }
    // Legacy teardown is used only by a recorded pre-existing session. Refuse
    // host aliases and busy namespaces even when no newer lease exists.
    let namespaces = run_cmd("ip", &["netns", "list"])?;
    let exists = namespaces.lines().any(|line| line.split_whitespace().next() == Some(NAMESPACE_NAME));
    let links: serde_json::Value = serde_json::from_str(&run_cmd("ip", &["-j", "-d", "link", "show"])?)?;
    let host = links.as_array().and_then(|links| links.iter().find(|link| link["ifname"] == VETH_HOST));
    if exists {
        let namespace = crate::tcp_namespace::Namespace::open(NAMESPACE_NAME)?;
        if expected != Some(namespace.identity) {
            return Err(WraithError::Namespace("Legacy namespace lifetime is unproven; teardown refused".into()));
        }
        if !run_cmd("ip", &["netns", "pids", NAMESPACE_NAME])?.trim().is_empty() {
            return Err(WraithError::Namespace("Close namespace applications before recovery".into()));
        }
        let inside: serde_json::Value = serde_json::from_str(&run_cmd("ip", &["-n", NAMESPACE_NAME, "-j", "-d", "link", "show"])?)?;
        let inside = inside.as_array().ok_or_else(|| WraithError::Namespace("Invalid namespace link inspection".into()))?;
        if inside.iter().any(|link| link["ifname"] != "lo" && link["ifname"] != VETH_NS) {
            return Err(WraithError::Namespace("Legacy namespace contains unowned interfaces".into()));
        }
        let peer = inside.iter().find(|link| link["ifname"] == VETH_NS);
        if !legacy_pair_matches(host, peer) {
            return Err(WraithError::Namespace("Legacy veth peer ownership is unproven".into()));
        }
    } else if host.is_some() {
        return Err(WraithError::Namespace("Unmarked veth has no namespace lifetime proof".into()));
    }
    let netns_dir = format!("/etc/netns/{NAMESPACE_NAME}");
    if fs::symlink_metadata(&netns_dir).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(WraithError::Namespace("Namespace configuration is a symlink".into()));
    }
    if Path::new(&netns_dir).exists() {
        for entry in fs::read_dir(&netns_dir)? {
            let entry = entry?;
            if entry.file_name() != "resolv.conf" || !entry.file_type()?.is_file()
                || fs::read_to_string(entry.path())? != format!("nameserver {NS_SUBNET}.1\n") {
                return Err(WraithError::Namespace("Unowned legacy namespace configuration".into()));
            }
        }
    }
    info!("Demolishing recorded legacy namespace: {}", NAMESPACE_NAME);
    if exists { run_cmd("ip", &["netns", "delete", NAMESPACE_NAME])?; }
    // The peer normally disappears with its namespace; do not delete by name.
    remove_namespace_rules(None)?;
    if Path::new(&netns_dir).exists() {
        let resolver = Path::new(&netns_dir).join("resolv.conf");
        match fs::remove_file(resolver) {
            Ok(()) => {},
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            Err(e) => return Err(e.into()),
        }
        fs::remove_dir(&netns_dir)?;
    }
    preflight_namespace()?;
    info!("Namespace purged");
    Ok(())
}

fn legacy_pair_matches(host: Option<&serde_json::Value>, peer: Option<&serde_json::Value>) -> bool {
    match (host, peer) {
        (None, None) => true,
        (Some(host), Some(peer)) => host["linkinfo"]["info_kind"] == "veth"
            && peer["linkinfo"]["info_kind"] == "veth"
            && host["ifindex"].as_u64().is_some_and(|index| index > 0 && peer["link_index"].as_u64() == Some(index))
            && peer["ifindex"].as_u64().is_some_and(|index| index > 0 && host["link_index"].as_u64() == Some(index)),
        _ => false,
    }
}

pub(crate) fn remove_namespace_rules(tag: Option<&str>) -> Result<()> {
    for mut rule in tagged_namespace_rules(tag) {
        if let Some(index) = rule.iter().position(|s| s == "-I") {
            rule[index] = "-D".into();
            rule.remove(index + 2); // insertion position is not part of deletion
        }
        let mut check = rule.clone();
        let operation = check.iter().position(|value| value == "-D").expect("owned deletion rule");
        check[operation] = "-C".into();
        // Bounded retries also clean duplicate owned rules left by old attempts.
        for attempt in 0..=32 {
            let status = Command::new("iptables").args(["-w", "5"]).args(&check).status()?;
            match status.code() {
                Some(1) => break,
                Some(0) if attempt < 32 => {
                    let args: Vec<&str> = rule.iter().map(String::as_str).collect();
                    run_cmd("iptables", &[&["-w", "5"][..], &args].concat())?;
                },
                _ => return Err(WraithError::Namespace("Namespace rule removal/readback failed".into())),
            }
        }
    }
    Ok(())
}

fn tagged_namespace_rules(tag: Option<&str>) -> Vec<Vec<String>> {
    let mut rules = namespace_rules();
    if let Some(tag) = tag {
        for rule in &mut rules {
            let position = rule.iter().position(|arg| arg == "-j").expect("owned rule target");
            rule.splice(position..position, ["-m", "comment", "--comment", tag].map(String::from));
        }
    }
    rules
}

fn configure_namespace_mac(mac: &str, mut execute: impl FnMut(&[&str]) -> Result<String>) -> Result<()> {
    execute(&["-n", NAMESPACE_NAME, "link", "set", "dev", VETH_NS, "address", mac])?;
    let output = execute(&["-n", NAMESPACE_NAME, "-j", "link", "show", "dev", VETH_NS])?;
    let links: serde_json::Value = serde_json::from_str(&output)?;
    if links.as_array().is_none_or(|links| links.len() != 1)
        || links[0]["address"].as_str() != Some(mac) {
        return Err(WraithError::Namespace("Namespace MAC readback mismatch".into()));
    }
    Ok(())
}

fn namespace_rules() -> Vec<Vec<String>> {
    let subnet = format!("{NS_SUBNET}.0/24");
    let dns = wraith_core::config::WRAITH_DNS_PORT.to_string();
    let mut rules = Vec::new();
    let mut add = |args: Vec<&str>| rules.push(args.into_iter().map(String::from).collect());
    // General TCP first; the DNS rules inserted later take priority.
    add(vec!["-t", "nat", "-I", "PREROUTING", "1", "-i", VETH_HOST, "-s", &subnet, "-p", "tcp", "--syn", "-j", "DNAT", "--to-destination", "127.0.0.1:9040"]);
    add(vec!["-t", "nat", "-I", "PREROUTING", "1", "-i", VETH_HOST, "-s", &subnet, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "127.0.0.1:9055"]);
    add(vec!["-I", "INPUT", "1", "-i", VETH_HOST, "-s", &subnet, "-d", "127.0.0.1", "-p", "tcp", "--dport", "9055", "-j", "ACCEPT"]);
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
        return Err(WraithError::Namespace("Start a namespace session before launching applications".into()));
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
    fn legacy_cleanup_requires_veth_kind_and_reciprocal_peer_indices() {
        let host = serde_json::json!({"ifindex":10,"link_index":11,"linkinfo":{"info_kind":"veth"}});
        let peer = serde_json::json!({"ifindex":11,"link_index":10,"linkinfo":{"info_kind":"veth"}});
        assert!(legacy_pair_matches(Some(&host), Some(&peer)));
        assert!(legacy_pair_matches(None, None));
        assert!(!legacy_pair_matches(Some(&host), None));
        assert!(!legacy_pair_matches(Some(&host), Some(&host)));
        let physical = serde_json::json!({"ifindex":11,"link_index":10,"linkinfo":{"info_kind":"ether"}});
        assert!(!legacy_pair_matches(Some(&host), Some(&physical)));
    }
    #[test]
    fn mac_write_is_checked_and_never_brings_a_link_up_on_failure() {
        let mut calls = Vec::new();
        configure_namespace_mac("02:11:22:33:44:55", |args| {
            calls.push(args.join(" "));
            Ok(r#"[{"address":"02:11:22:33:44:55"}]"#.into())
        }).unwrap();
        assert!(calls[0].contains("address 02:11:22:33:44:55"));
        assert!(calls.iter().all(|call| !call.contains(" up")));
        assert!(configure_namespace_mac("02:11:22:33:44:55", |_| Ok("[]".into())).is_err());
        assert!(configure_namespace_mac("02:11:22:33:44:55", |_| Err(WraithError::PermissionDenied)).is_err());
        assert!(tagged_namespace_rules(Some("owner")).iter().all(|r| r.windows(2).any(|p| p == ["--comment", "owner"])));
    }
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
