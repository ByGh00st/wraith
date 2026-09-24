//! Tor UID-scoped access-link normalization. TTL covers every outgoing IPv4
//! TCP packet; only initial SYNs enter NFQUEUE. Host TCP sysctls are untouched.
//! An absent/dead/full queue drops new SYNs: there is no queue-bypass or fail-open.

use serde::{Deserialize, Serialize};
use std::process::Command;
use tokio_util::sync::CancellationToken;
use wraith_core::error::{Result, WraithError};
use wraith_core::tcp_fingerprint::TcpFingerprintProfile;

pub const EGRESS_QUEUE: u16 = 41884;
pub const EGRESS_CHAIN: &str = "WRAITH_L4_EGRESS";
const EGRESS_TAG: &str = "wraith-l4-egress";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpEgressSnapshot {
    pub profile: TcpFingerprintProfile,
    pub tor_uid: u32,
    pub queue_num: u16,
    pub peer_portid: u32,
}

impl TcpEgressSnapshot {
    fn validate(&self) -> Result<()> {
        self.profile
            .validate()
            .map_err(|e| WraithError::Configuration(e.to_string()))?;
        if self.tor_uid == 0 || self.queue_num != EGRESS_QUEUE || self.peer_portid == 0 {
            return Err(WraithError::Configuration(
                "Invalid Tor egress queue ownership".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressQueueStats {
    pub peer_portid: u32,
    pub pending: u32,
    pub kernel_dropped: u32,
    pub userspace_dropped: u32,
    /// NFQUEUE sequence counter, not proof of a completed remote handshake.
    pub queued_syns: u32,
}

pub struct TcpEgressTelemetry {
    pub policy_present: bool,
    pub queue: Option<EgressQueueStats>,
}

fn parse_queue_stats(text: &str, queue: u16) -> Result<Option<EgressQueueStats>> {
    let mut found = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.first().and_then(|v| v.parse::<u16>().ok()) != Some(queue) {
            continue;
        }
        if fields.len() != 9 || found.is_some() {
            return Err(WraithError::Network("Ambiguous NFQUEUE telemetry".into()));
        }
        let number = |index: usize| {
            fields[index]
                .parse::<u32>()
                .map_err(|_| WraithError::Network("Invalid NFQUEUE telemetry".into()))
        };
        found = Some(EgressQueueStats {
            peer_portid: number(1)?,
            pending: number(2)?,
            kernel_dropped: number(5)?,
            userspace_dropped: number(6)?,
            queued_syns: number(7)?,
        });
    }
    Ok(found)
}

fn queue_stats(queue: u16) -> Result<Option<EgressQueueStats>> {
    match std::fs::read_to_string("/proc/net/netfilter/nfnetlink_queue") {
        Ok(text) => parse_queue_stats(&text, queue),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn jump_rule(snapshot: &TcpEgressSnapshot) -> Vec<String> {
    [
        "-p",
        "tcp",
        "!",
        "-o",
        "lo",
        "-m",
        "owner",
        "--uid-owner",
        &snapshot.tor_uid.to_string(),
        "-m",
        "comment",
        "--comment",
        EGRESS_TAG,
        "-j",
        EGRESS_CHAIN,
    ]
    .into_iter()
    .map(Into::into)
    .collect()
}

fn chain_rules(snapshot: &TcpEgressSnapshot) -> Vec<Vec<String>> {
    vec![
        vec![
            "-j".into(),
            "TTL".into(),
            "--ttl-set".into(),
            snapshot.profile.default_ttl.to_string(),
        ],
        [
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,ACK,RST,FIN",
            "SYN",
            "-j",
            "NFQUEUE",
            "--queue-num",
            &snapshot.queue_num.to_string(),
        ]
        .into_iter()
        .map(Into::into)
        .collect(),
    ]
}

fn iptables_args(operation: &str, chain: &str, tail: &[String]) -> Vec<String> {
    let mut args: Vec<String> = ["-w", "5", "-t", "mangle", operation, chain]
        .into_iter()
        .map(Into::into)
        .collect();
    if operation == "-I" {
        args.push("1".into());
    }
    args.extend_from_slice(tail);
    args
}

fn run(args: &[String]) -> Result<String> {
    let output = Command::new("iptables").args(args).output()?;
    if !output.status.success() {
        return Err(WraithError::Firewall(format!(
            "Tor L4 egress rule failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn rule_present(chain: &str, rule: &[String]) -> Result<bool> {
    let output = Command::new("iptables")
        .args(iptables_args("-C", chain, rule))
        .output()?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(WraithError::Firewall(format!(
            "Tor L4 rule readback failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))),
    }
}

#[cfg(any(target_os = "linux", test))]
fn install_policy_with(
    snapshot: &TcpEgressSnapshot,
    mut execute: impl FnMut(&[String]) -> Result<String>,
) -> Result<()> {
    snapshot.validate()?;
    // Acquiring the unique chain must succeed before any ownership/cleanup.
    execute(&iptables_args("-N", EGRESS_CHAIN, &[]))?;
    let result = (|| {
        for rule in chain_rules(snapshot) {
            execute(&iptables_args("-A", EGRESS_CHAIN, &rule))?;
        }
        execute(&iptables_args("-I", "OUTPUT", &jump_rule(snapshot)))?;
        for rule in chain_rules(snapshot) {
            execute(&iptables_args("-C", EGRESS_CHAIN, &rule))?;
        }
        execute(&iptables_args("-C", "OUTPUT", &jump_rule(snapshot)))?;
        Ok(())
    })();
    // The pre-session firewall journal is the crash-safe rollback owner. On
    // failure keep the owned chain: removing a live jump could expose raw SYNs.
    result
}

pub fn inspect_tor_egress(snapshot: &TcpEgressSnapshot) -> Result<TcpEgressTelemetry> {
    snapshot.validate()?;
    let mut policy_present = rule_present("OUTPUT", &jump_rule(snapshot))?;
    for rule in chain_rules(snapshot) {
        policy_present &= rule_present(EGRESS_CHAIN, &rule)?;
    }
    let queue =
        queue_stats(snapshot.queue_num)?.filter(|stats| stats.peer_portid == snapshot.peer_portid);
    Ok(TcpEgressTelemetry {
        policy_present,
        queue,
    })
}

/// Run only after the managed Tor process has stopped. Whole-table recovery
/// remains responsible for restoring the pre-session policy if this fails.
pub fn remove_tor_egress(snapshot: &TcpEgressSnapshot) -> Result<()> {
    snapshot.validate()?;
    let all = run(&["-w", "5", "-t", "mangle", "-S"].map(Into::into))?;
    if !all.lines().any(|line| line == format!("-N {EGRESS_CHAIN}")) {
        return Ok(());
    }
    if rule_present("OUTPUT", &jump_rule(snapshot))? {
        run(&iptables_args("-D", "OUTPUT", &jump_rule(snapshot)))?;
    }
    run(&iptables_args("-F", EGRESS_CHAIN, &[]))?;
    run(&iptables_args("-X", EGRESS_CHAIN, &[]))?;
    Ok(())
}

pub struct TcpEgressWorker {
    pub snapshot: TcpEgressSnapshot,
    pub cancel: CancellationToken,
    pub handle: tokio::task::JoinHandle<()>,
}

/// Bind/configure the queue and journal ownership before attaching its rules.
/// Acquiring NFQUEUE or any required rule failure always fails startup.
pub fn start_tor_egress(
    profile: &TcpFingerprintProfile,
    tor_uid: u32,
    journal: impl FnOnce(&TcpEgressSnapshot) -> Result<()>,
) -> Result<TcpEgressWorker> {
    profile
        .validate()
        .map_err(|e| WraithError::Configuration(e.to_string()))?;
    if tor_uid == 0 {
        return Err(WraithError::Configuration(
            "Tor egress must use a non-root UID".into(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        // Refuse collisions before recording resources as ours.
        let all = run(&["-w", "5", "-t", "mangle", "-S"].map(Into::into))?;
        if all.contains(EGRESS_CHAIN) || all.contains(EGRESS_TAG) || queue_number_in_use(&all) {
            return Err(WraithError::Firewall(
                "Tor L4 egress chain already exists; recover the previous session".into(),
            ));
        }
        // Queue numbers are shared across tables and IPv4/IPv6. An unbound
        // queue can still have someone else's rules; do not attach to them.
        for program in ["iptables-save", "ip6tables-save"] {
            let output = Command::new(program).output()?;
            if !output.status.success() {
                return Err(WraithError::Firewall(format!(
                    "Cannot check existing queue ownership with {program}"
                )));
            }
            if queue_number_in_use(&String::from_utf8_lossy(&output.stdout)) {
                return Err(WraithError::Firewall(format!(
                    "NFQUEUE {EGRESS_QUEUE} is referenced by existing firewall rules"
                )));
            }
        }
        let mut queue = crate::nfqueue::Queue::bind(EGRESS_QUEUE)?;
        let stats = queue_stats(EGRESS_QUEUE)?
            .filter(|s| s.peer_portid == queue.peer_portid)
            .ok_or_else(|| WraithError::Network("Cannot verify owned NFQUEUE".into()))?;
        let snapshot = TcpEgressSnapshot {
            profile: profile.clone(),
            tor_uid,
            queue_num: EGRESS_QUEUE,
            peer_portid: stats.peer_portid,
        };
        snapshot.validate()?;
        journal(&snapshot)?;
        install_policy_with(&snapshot, run)?;
        let cancel = CancellationToken::new();
        let cancelled = cancel.clone();
        let profile = profile.clone();
        let handle = tokio::task::spawn_blocking(move || {
            while !cancelled.is_cancelled() {
                let message = match queue.recv() {
                    Ok(message) => message,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        tracing::error!(
                            "Tor L4 queue stopped: {error}; SYN queue remains fail-closed"
                        );
                        break;
                    }
                };
                let valid = valid_metadata(
                    message.queue,
                    message.hook,
                    message.uid,
                    tor_uid,
                    message.original_len,
                    message.payload.len(),
                    message.checksum_ready,
                    message.gso,
                );
                let rewritten = if valid {
                    crate::tcp_wire::morph_ipv4_syn(&message.payload, &profile)
                        .ok()
                        .filter(|packet| packet.len() <= crate::nfqueue::MAX_PAYLOAD)
                } else {
                    None
                };
                if rewritten.is_none() {
                    tracing::warn!(
                        "Tor L4 rejected an unsupported/truncated SYN; no unmodified fallback"
                    );
                }
                if let Err(error) = queue.verdict(message, rewritten) {
                    tracing::error!(
                        "Tor L4 verdict failed: {error}; SYN queue remains fail-closed"
                    );
                    break;
                }
            }
        });
        tracing::info!(tor_uid, queue = EGRESS_QUEUE, profile = %snapshot.profile.name, "Tor access-link TCP morphing armed");
        Ok(TcpEgressWorker {
            snapshot,
            cancel,
            handle,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = journal;
        Err(WraithError::UnsupportedPlatform)
    }
}

#[cfg(any(target_os = "linux", test))]
fn queue_number_in_use(rules: &str) -> bool {
    rules.lines().any(|line| {
        let words: Vec<_> = line.split_whitespace().collect();
        words.windows(2).any(|pair| match pair[0] {
            "--queue-num" => pair[1].parse::<u16>().ok() == Some(EGRESS_QUEUE),
            "--queue-balance" => pair[1].split_once(':').is_some_and(|(lo, hi)| {
                lo.parse::<u16>()
                    .ok()
                    .zip(hi.parse::<u16>().ok())
                    .is_some_and(|(lo, hi)| (lo..=hi).contains(&EGRESS_QUEUE))
            }),
            _ => false,
        })
    })
}

#[cfg(any(target_os = "linux", test))]
#[allow(clippy::too_many_arguments)]
fn valid_metadata(
    queue: u16,
    hook: u8,
    uid: Option<u32>,
    expected_uid: u32,
    original_len: usize,
    copied_len: usize,
    checksum_ready: bool,
    gso: bool,
) -> bool {
    queue == EGRESS_QUEUE
        && hook == 3
        && expected_uid != 0
        && uid == Some(expected_uid)
        && original_len == copied_len
        && checksum_ready
        && !gso
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> TcpEgressSnapshot {
        TcpEgressSnapshot {
            profile: TcpFingerprintProfile::windows11(),
            tor_uid: 109,
            queue_num: EGRESS_QUEUE,
            peer_portid: 42,
        }
    }

    #[test]
    fn rules_scope_ttl_to_tor_and_queue_only_initial_syns_without_bypass() {
        let mut calls = Vec::new();
        install_policy_with(&snapshot(), |args| {
            calls.push(args.join(" "));
            Ok(String::new())
        })
        .unwrap();
        assert!(calls
            .iter()
            .any(|s| s.contains("-I OUTPUT 1 -p tcp ! -o lo -m owner --uid-owner 109")));
        assert!(calls.iter().any(|s| s.contains("-j TTL --ttl-set 128")));
        assert!(calls
            .iter()
            .any(|s| s.contains("--tcp-flags SYN,ACK,RST,FIN SYN -j NFQUEUE --queue-num 41884")));
        assert!(!calls
            .iter()
            .any(|s| s.contains("bypass") || s.contains("sysctl") || s.contains("ACCEPT")));
        assert_eq!(calls.iter().filter(|s| s.contains(" -C ")).count(), 3);
    }

    #[test]
    fn every_rule_failure_stops_setup_without_removing_the_protective_chain() {
        for fail_at in 0..7 {
            let mut calls = 0;
            assert!(install_policy_with(&snapshot(), |_| {
                let index = calls;
                calls += 1;
                if index == fail_at {
                    Err(WraithError::PermissionDenied)
                } else {
                    Ok(String::new())
                }
            })
            .is_err());
            assert_eq!(calls, fail_at + 1);
        }
    }

    #[test]
    fn queue_ownership_and_packet_metadata_must_match() {
        assert!(valid_metadata(
            EGRESS_QUEUE,
            3,
            Some(109),
            109,
            60,
            60,
            true,
            false
        ));
        assert!(!valid_metadata(
            EGRESS_QUEUE,
            3,
            None,
            109,
            60,
            60,
            true,
            false
        ));
        assert!(!valid_metadata(
            EGRESS_QUEUE,
            3,
            Some(0),
            109,
            60,
            60,
            true,
            false
        ));
        assert!(!valid_metadata(
            EGRESS_QUEUE,
            4,
            Some(109),
            109,
            60,
            60,
            true,
            false
        ));
        assert!(!valid_metadata(0, 3, Some(109), 109, 60, 60, true, false));
        assert!(!valid_metadata(
            EGRESS_QUEUE,
            3,
            Some(109),
            109,
            61,
            60,
            true,
            false
        ));
        assert!(!valid_metadata(
            EGRESS_QUEUE,
            3,
            Some(109),
            109,
            60,
            60,
            false,
            false
        ));
        assert!(!valid_metadata(
            EGRESS_QUEUE,
            3,
            Some(109),
            109,
            60,
            60,
            true,
            true
        ));
    }

    #[test]
    fn queue_counters_are_parsed_without_claiming_wire_verification() {
        let row = "41884 42 1 2 65531 3 4 99 1\n";
        let stats = parse_queue_stats(row, EGRESS_QUEUE).unwrap().unwrap();
        assert_eq!(
            stats,
            EgressQueueStats {
                peer_portid: 42,
                pending: 1,
                kernel_dropped: 3,
                userspace_dropped: 4,
                queued_syns: 99
            }
        );
        assert!(parse_queue_stats(row, 1).unwrap().is_none());
        assert!(parse_queue_stats(&(row.to_owned() + row), EGRESS_QUEUE).is_err());
        assert!(parse_queue_stats("41884 42", EGRESS_QUEUE).is_err());
    }

    #[test]
    fn another_queues_number_or_balance_range_cannot_be_hijacked() {
        assert!(queue_number_in_use(
            "-A OUTPUT -j NFQUEUE --queue-num 41884"
        ));
        assert!(queue_number_in_use(
            "-A OUTPUT -j NFQUEUE --queue-balance 41880:41890"
        ));
        assert!(!queue_number_in_use(
            "-A OUTPUT -j NFQUEUE --queue-num 41885"
        ));
    }
}
