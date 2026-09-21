//! Block STUN before transparent NAT rewrites the original destination port.
use std::process::Command;
use wraith_core::error::{Result, WraithError};

pub const STUN_PORTS: &[u16] = &[3478, 3479, 5349, 5350, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309];

fn rules(uid: u32) -> Vec<Vec<String>> {
    let ports = STUN_PORTS.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let uid = uid.to_string();
    let mut rules = Vec::new();
    for protocol in ["tcp", "udp"] {
        // OUTPUT sees locally originated packets before REDIRECT in nat/OUTPUT.
        // Tor itself may legitimately connect to a relay using one of these ports.
        rules.push(vec!["OUTPUT", "-p", protocol, "-m", "owner", "!", "--uid-owner", &uid,
            "-m", "mark", "!", "--mark", "0x5183", "-m", "multiport", "--dports", &ports, "-j", "DROP"].into_iter().map(str::to_owned).collect());
        rules.push(vec!["PREROUTING", "-i", crate::namespace::VETH_HOST, "-p", protocol,
            "-m", "multiport", "--dports", &ports, "-j", "DROP"].into_iter().map(str::to_owned).collect());
    }
    rules.push(vec!["OUTPUT", "!", "-o", "lo", "-p", "udp", "--dport", "5353", "-j", "DROP"]
        .into_iter().map(str::to_owned).collect());
    rules
}

fn apply(insert: bool) -> Result<()> {
    for rule in rules(crate::get_tor_uid()?) {
        let mut args = vec!["-w", "5", "-t", "raw", if insert { "-I" } else { "-D" }];
        args.extend(rule.iter().map(String::as_str));
        let output = Command::new("iptables").args(args).output()?;
        if !output.status.success() {
            return Err(WraithError::Firewall(format!("STUN rule failed: {}", String::from_utf8_lossy(&output.stderr))));
        }
    }
    Ok(())
}

pub fn block_stun_ports() -> Result<()> { apply(true) }
pub fn unblock_stun_ports() -> Result<()> { apply(false) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_local_and_namespace_traffic_are_filtered_without_blocking_tor() {
        let rules = rules(123);
        for protocol in ["tcp", "udp"] {
            assert!(rules.iter().any(|r| r[0] == "OUTPUT" && r.windows(2).any(|p| p == ["-p", protocol])
                && r.windows(3).any(|p| p == ["!", "--uid-owner", "123"])));
            assert!(rules.iter().any(|r| r[0] == "PREROUTING" && r.windows(2).any(|p| p == ["-i", crate::namespace::VETH_HOST])
                && r.windows(2).any(|p| p == ["-p", protocol])));
        }
        assert!(rules.last().unwrap().windows(3).any(|p| p == ["!", "-o", "lo"]));
    }
}
