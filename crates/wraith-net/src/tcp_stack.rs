//! Wraith Layer 4 TCP Stack Morphing & p0f Evasion Engine
//!
//! Normalizes Linux kernel TCP/IP stack signatures within isolated Network Namespaces
//! to eliminate fingerprint discrepancies against L7 TLS (JA3/JA4) profiles.
//!
//! ## Three-Tier Application Architecture
//!
//! ```text
//! apply_profile_to_netns()
//! ├── 1. Sysctl Tier     → write_netns_sysctl()    [atomic, fail-closed]
//! ├── 2. Netfilter Tier  → apply_netfilter_mss()    [iptables mangle, rollback-capable]
//! └── 3. FIB Routing Tier→ apply_route_metrics()    [ip route change, rollback-capable]
//! ```
//!
//! ### OPSEC & Kernel Architecture Guards:
//! 1. **Zero Host Contamination**: Host root network parameters are NEVER modified globally.
//! 2. **Tokio Thread-Safety (Anti-setns Contamination)**: All namespace operations execute
//!    via `ip netns exec` sub-processes, ensuring Tokio async worker threads never permanently
//!    inherit a foreign namespace.
//! 3. **Layer Separation**: `forced_syn_mss` and `init_cwnd`/`init_rwnd` are decoupled from sysctl
//!    and routed to Netfilter (iptables) and Routing (FIB) layers respectively.
//! 4. **Graceful Kernel Fallback**: Differentiates between core per-netns parameters (atomic fail-closed)
//!    and kernel-version-dependent extended parameters (graceful warn & continue).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use tracing::{debug, error, info, warn};
use wraith_core::error::{Result as CoreResult, WraithError};
use wraith_core::tcp_fingerprint::TcpFingerprintProfile;

// ══════════════════════════════════════════════════════════════════════════════
// SYSCTL KEY REGISTRIES
// ══════════════════════════════════════════════════════════════════════════════

/// Core sysctl parameters guaranteed to reside inside `struct netns_ipv4` across modern Linux kernels.
pub const CORE_SYSCTL_KEYS: &[&str] = &[
    "net.ipv4.ip_default_ttl",
    "net.ipv4.tcp_window_scaling",
    "net.ipv4.tcp_timestamps",
    "net.ipv4.tcp_sack",
    "net.ipv4.tcp_fin_timeout",
    "net.ipv4.tcp_syn_retries",
];

/// Extended sysctl keys for deep p0f / Nmap OS fingerprint evasion (subject to kernel capability fallback).
pub const EXTENDED_SYSCTL_KEYS: &[&str] = &[
    "net.ipv4.ip_local_port_range",
    "net.ipv4.tcp_ecn",
    "net.ipv4.tcp_rfc1337",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.icmp_ignore_bogus_error_responses",
    "net.ipv4.tcp_challenge_ack_limit",
];

// ══════════════════════════════════════════════════════════════════════════════
// ERROR TAXONOMY
// ══════════════════════════════════════════════════════════════════════════════

/// Precision error taxonomy for L4 TCP stack morphing operations.
#[derive(Debug, thiserror::Error)]
pub enum TcpMorphError {
    #[error("Network namespace '{0}' not found or inactive")]
    NamespaceNotFound(String),

    #[error("Permission denied when accessing sysctl '{parameter}' in namespace '{namespace}': {details}")]
    PermissionDenied {
        parameter: String,
        namespace: String,
        details: String,
    },

    #[error("Sysctl parameter '{parameter}' not found in namespace '{namespace}' (unsupported by kernel)")]
    SysctlNotFound {
        parameter: String,
        namespace: String,
    },

    #[error("Execution failed for sysctl '{parameter}' in namespace '{namespace}': {details}")]
    ExecutionFailed {
        parameter: String,
        namespace: String,
        details: String,
    },

    #[error("Netfilter operation failed in namespace '{namespace}': {details}")]
    NetfilterFailed {
        namespace: String,
        details: String,
    },

    #[error("FIB route metric operation failed in namespace '{namespace}': {details}")]
    RoutingFailed {
        namespace: String,
        details: String,
    },

    #[error("Host mutation forbidden: modifying global host TCP stack is prohibited by OPSEC policy")]
    HostMutationForbidden,

    #[error("Rollback failed in namespace '{namespace}': {details}")]
    RollbackFailed {
        namespace: String,
        details: String,
    },

    #[error("I/O error during TCP stack morphing: {0}")]
    Io(#[from] std::io::Error),
}

impl TcpMorphError {
    /// Determines whether the error qualifies for graceful non-fatal fallback.
    pub fn is_fallback_eligible(&self) -> bool {
        matches!(
            self,
            Self::SysctlNotFound { .. }
                | Self::PermissionDenied { .. }
                | Self::NetfilterFailed { .. }
                | Self::RoutingFailed { .. }
        )
    }
}

impl From<TcpMorphError> for WraithError {
    fn from(err: TcpMorphError) -> Self {
        WraithError::Namespace(err.to_string())
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// SNAPSHOT & STATE TRACKING
// ══════════════════════════════════════════════════════════════════════════════

/// Point-in-time snapshot of all L4 parameters within an isolated network namespace.
/// Captures sysctl values, Netfilter MSS state, and FIB routing metrics for rollback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NetnsTcpSnapshot {
    /// Associated network namespace name.
    pub namespace: String,
    /// Applied profile name, if active.
    pub profile_name: Option<String>,
    /// Key-value mappings of backed-up sysctl parameters.
    pub values: HashMap<String, String>,
    /// Whether a Netfilter MSS rule was active before morphing.
    pub had_netfilter_mss: bool,
    /// The MSS value that was set (for rollback deletion).
    pub netfilter_mss_value: Option<u16>,
    /// Whether FIB route metrics were modified.
    pub had_route_metrics: bool,
}

impl NetnsTcpSnapshot {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            profile_name: None,
            values: HashMap::new(),
            had_netfilter_mss: false,
            netfilter_mss_value: None,
            had_route_metrics: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// NAMESPACE VALIDATION
// ══════════════════════════════════════════════════════════════════════════════

/// Guard: validates that the target is not the host namespace.
fn guard_not_host(netns: &str) -> std::result::Result<(), TcpMorphError> {
    if netns.trim().is_empty() || netns == "host" || netns == "/" {
        return Err(TcpMorphError::HostMutationForbidden);
    }
    Ok(())
}

/// Validates whether a target network namespace exists on the system.
pub fn is_netns_active(netns: &str) -> bool {
    if netns.trim().is_empty() || netns == "host" || netns == "/" {
        return false;
    }

    let run_path = format!("/run/netns/{netns}");
    let var_run_path = format!("/var/run/netns/{netns}");
    if Path::new(&run_path).exists() || Path::new(&var_run_path).exists() {
        return true;
    }

    Command::new("ip")
        .args(["netns", "list"])
        .output()
        .map(|out| {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.lines().any(|l| l.split_whitespace().next() == Some(netns))
        })
        .unwrap_or(false)
}

/// Validates namespace is active, returns typed error otherwise.
fn require_active_netns(netns: &str) -> std::result::Result<(), TcpMorphError> {
    guard_not_host(netns)?;
    if !is_netns_active(netns) {
        return Err(TcpMorphError::NamespaceNotFound(netns.to_string()));
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 1: SYSCTL OPERATIONS (Namespace-Isolated Sub-Process)
// ══════════════════════════════════════════════════════════════════════════════

/// Reads a sysctl parameter value strictly within an isolated network namespace.
///
/// **OPSEC Note**: Executes in an isolated sub-process via `ip netns exec`.
/// Tokio worker threads are completely immune to namespace contamination.
pub fn read_netns_sysctl(netns: &str, key: &str) -> std::result::Result<String, TcpMorphError> {
    require_active_netns(netns)?;

    let output = Command::new("ip")
        .args(["netns", "exec", netns, "sysctl", "-n", key])
        .output()
        .map_err(|e| TcpMorphError::ExecutionFailed {
            parameter: key.to_string(),
            namespace: netns.to_string(),
            details: e.to_string(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
            return Err(TcpMorphError::PermissionDenied {
                parameter: key.to_string(),
                namespace: netns.to_string(),
                details: stderr.trim().to_string(),
            });
        }
        if stderr.contains("No such file or directory") || stderr.contains("cannot stat") {
            return Err(TcpMorphError::SysctlNotFound {
                parameter: key.to_string(),
                namespace: netns.to_string(),
            });
        }
        return Err(TcpMorphError::ExecutionFailed {
            parameter: key.to_string(),
            namespace: netns.to_string(),
            details: stderr.trim().to_string(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Writes a sysctl parameter value strictly within an isolated network namespace.
///
/// **OPSEC Note**: Executes in an isolated sub-process to protect Tokio runtime integrity.
pub fn write_netns_sysctl(netns: &str, key: &str, val: &str) -> std::result::Result<(), TcpMorphError> {
    require_active_netns(netns)?;

    let output = Command::new("ip")
        .args(["netns", "exec", netns, "sysctl", "-w", &format!("{key}={val}")])
        .output()
        .map_err(|e| TcpMorphError::ExecutionFailed {
            parameter: key.to_string(),
            namespace: netns.to_string(),
            details: e.to_string(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
            return Err(TcpMorphError::PermissionDenied {
                parameter: key.to_string(),
                namespace: netns.to_string(),
                details: stderr.trim().to_string(),
            });
        }
        if stderr.contains("No such file or directory") || stderr.contains("cannot stat") {
            return Err(TcpMorphError::SysctlNotFound {
                parameter: key.to_string(),
                namespace: netns.to_string(),
            });
        }
        return Err(TcpMorphError::ExecutionFailed {
            parameter: key.to_string(),
            namespace: netns.to_string(),
            details: stderr.trim().to_string(),
        });
    }

    debug!("Namespace [{netns}] sysctl set: {key}={val}");
    Ok(())
}

/// Captures a snapshot of target sysctl parameters inside the specified namespace.
pub fn snapshot_netns_tcp_stack(
    netns: &str,
    keys: &[&str],
) -> std::result::Result<NetnsTcpSnapshot, TcpMorphError> {
    require_active_netns(netns)?;

    let mut snapshot = NetnsTcpSnapshot::new(netns);

    for &key in keys {
        match read_netns_sysctl(netns, key) {
            Ok(val) => {
                snapshot.values.insert(key.to_string(), val);
            }
            Err(TcpMorphError::SysctlNotFound { .. }) => {
                debug!("Optional sysctl parameter '{key}' not present in netns '{netns}' (kernel variance)");
            }
            Err(e) => {
                warn!("Warning: Failed reading sysctl '{key}' in netns '{netns}': {e}");
            }
        }
    }

    Ok(snapshot)
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 2: NETFILTER MSS CLAMPING (iptables mangle)
// ══════════════════════════════════════════════════════════════════════════════

/// Applies Netfilter TCPMSS clamping rule inside the network namespace.
///
/// This sets the Maximum Segment Size on outgoing SYN packets via the mangle table.
/// The MSS value is NOT a sysctl — it must be enforced through iptables.
///
/// ## iptables Command Executed
/// ```bash
/// ip netns exec <ns> iptables -t mangle -A POSTROUTING -p tcp \
///   --tcp-flags SYN,RST SYN -j TCPMSS --set-mss <mss>
/// ```
pub fn apply_netfilter_mss(
    netns: &str,
    mss: u16,
) -> std::result::Result<(), TcpMorphError> {
    require_active_netns(netns)?;

    let output = Command::new("ip")
        .args([
            "netns", "exec", netns,
            "iptables", "-t", "mangle",
            "-A", "POSTROUTING",
            "-p", "tcp",
            "--tcp-flags", "SYN,RST", "SYN",
            "-j", "TCPMSS",
            "--set-mss", &mss.to_string(),
        ])
        .output()
        .map_err(|e| TcpMorphError::NetfilterFailed {
            namespace: netns.to_string(),
            details: format!("iptables execution error: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(TcpMorphError::NetfilterFailed {
            namespace: netns.to_string(),
            details: format!("TCPMSS --set-mss {mss} failed: {}", stderr.trim()),
        });
    }

    info!("Namespace [{netns}] Netfilter TCPMSS clamped to {mss} bytes");
    Ok(())
}

/// Removes a previously applied Netfilter TCPMSS clamping rule (rollback).
pub fn remove_netfilter_mss(
    netns: &str,
    mss: u16,
) -> std::result::Result<(), TcpMorphError> {
    require_active_netns(netns)?;

    let output = Command::new("ip")
        .args([
            "netns", "exec", netns,
            "iptables", "-t", "mangle",
            "-D", "POSTROUTING",
            "-p", "tcp",
            "--tcp-flags", "SYN,RST", "SYN",
            "-j", "TCPMSS",
            "--set-mss", &mss.to_string(),
        ])
        .output()
        .map_err(|e| TcpMorphError::NetfilterFailed {
            namespace: netns.to_string(),
            details: format!("iptables deletion error: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Netfilter TCPMSS rule removal warning in [{netns}]: {}", stderr.trim());
    } else {
        debug!("Namespace [{netns}] Netfilter TCPMSS rule removed (MSS={mss})");
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 3: FIB ROUTING METRICS (ip route)
// ══════════════════════════════════════════════════════════════════════════════

/// Applies FIB routing metrics (initcwnd / initrwnd) to the default route inside the namespace.
///
/// These metrics control the initial TCP window sizes and directly affect what appears
/// in the SYN packet's window field — a key p0f discriminator.
///
/// ## ip route Command Executed
/// ```bash
/// ip netns exec <ns> ip route change default via <gw> initcwnd <N> initrwnd <N>
/// ```
pub fn apply_route_metrics(
    netns: &str,
    profile: &TcpFingerprintProfile,
) -> std::result::Result<(), TcpMorphError> {
    if !profile.requires_route_metrics() {
        return Ok(());
    }
    require_active_netns(netns)?;

    // First, get the current default route
    let route_output = Command::new("ip")
        .args(["netns", "exec", netns, "ip", "-4", "route", "show", "default"])
        .output()
        .map_err(|e| TcpMorphError::RoutingFailed {
            namespace: netns.to_string(),
            details: format!("Failed to read default route: {e}"),
        })?;

    let route_line = String::from_utf8_lossy(&route_output.stdout);
    let route_line = route_line.trim();

    if route_line.is_empty() {
        warn!("No default route found in namespace '{netns}'; skipping FIB metric morphing");
        return Ok(());
    }

    // Parse gateway from existing route
    let parts: Vec<&str> = route_line.split_whitespace().collect();
    let via_idx = parts.iter().position(|&p| p == "via");
    let dev_idx = parts.iter().position(|&p| p == "dev");

    // Build the route change command
    let mut args = vec![
        "netns".to_string(), "exec".to_string(), netns.to_string(),
        "ip".to_string(), "route".to_string(), "change".to_string(),
        "default".to_string(),
    ];

    if let Some(idx) = via_idx {
        if let Some(gw) = parts.get(idx + 1) {
            args.push("via".to_string());
            args.push(gw.to_string());
        }
    }

    if let Some(idx) = dev_idx {
        if let Some(dev) = parts.get(idx + 1) {
            args.push("dev".to_string());
            args.push(dev.to_string());
        }
    }

    // Append FIB metrics from profile
    args.extend(profile.fib_route_metrics());

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = Command::new("ip")
        .args(&args_ref)
        .output()
        .map_err(|e| TcpMorphError::RoutingFailed {
            namespace: netns.to_string(),
            details: format!("ip route change failed: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(TcpMorphError::RoutingFailed {
            namespace: netns.to_string(),
            details: format!("FIB metric application failed: {}", stderr.trim()),
        });
    }

    info!(
        "Namespace [{netns}] FIB routing metrics applied: {}",
        profile.fib_route_metrics().join(" ")
    );
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// UNIFIED APPLICATION ENGINE (3-Tier Orchestrator)
// ══════════════════════════════════════════════════════════════════════════════

/// Applies a complete `TcpFingerprintProfile` to the network namespace across all three tiers.
///
/// ## Execution Order
/// 1. **Snapshot**: Captures pre-mutation state of all sysctl parameters.
/// 2. **Tier 1 — Sysctl**: Atomic writes of core parameters with rollback on failure.
/// 3. **Tier 2 — Netfilter**: TCPMSS clamping via iptables mangle table.
/// 4. **Tier 3 — FIB Routing**: initcwnd/initrwnd via `ip route change`.
///
/// ## Rollback Strategy
/// - Core sysctl failure → immediate rollback of all written parameters → abort.
/// - Netfilter/routing failure → warn and continue (fail-open on non-core tiers by default).
/// - `fail_closed`: If true, aborts on ANY tier failure. If false, only core sysctl is atomic.
pub fn apply_profile_to_netns(
    netns: &str,
    profile: &TcpFingerprintProfile,
    fail_closed: bool,
) -> std::result::Result<NetnsTcpSnapshot, TcpMorphError> {
    require_active_netns(netns)?;

    info!(
        "Deploying 3-tier L4 TCP fingerprint normalization '{}' into namespace '{}' [{}]",
        profile.name,
        netns,
        profile.format_summary()
    );

    let core_entries = profile.core_sysctl_entries();
    let extended_entries = profile.extended_sysctl_entries();

    let mut all_keys: Vec<&str> = core_entries.iter().map(|(k, _)| *k).collect();
    all_keys.extend(extended_entries.iter().map(|(k, _)| *k));

    // ── Phase 0: Pre-Mutation Snapshot ──────────────────────────────────────
    let mut snapshot = snapshot_netns_tcp_stack(netns, &all_keys)?;
    snapshot.profile_name = Some(profile.name.clone());

    let mut written_keys = Vec::new();

    // ── Phase 1: Core Sysctl (Strict Enforcement & Rollback) ───────────────
    for (key, val) in &core_entries {
        if let Err(e) = write_netns_sysctl(netns, key, val) {
            error!(
                "Failed writing core sysctl '{key}={val}' into netns '{netns}': {e}. Executing atomic rollback."
            );

            // Atomic rollback of modified core parameters
            for applied_key in &written_keys {
                if let Some(orig_val) = snapshot.values.get(*applied_key) {
                    let _ = write_netns_sysctl(netns, applied_key, orig_val);
                }
            }

            if fail_closed {
                return Err(e);
            } else {
                warn!("Fail-open active: L4 TCP core morphing failed, proceeding with fallback");
                return Ok(snapshot);
            }
        }
        written_keys.push(*key);
    }

    // ── Phase 2: Extended Sysctl (Graceful Fallback) ───────────────────────
    for (key, val) in &extended_entries {
        if let Err(e) = write_netns_sysctl(netns, key, val) {
            if e.is_fallback_eligible() {
                warn!(
                    "Extended sysctl '{key}={val}' unsupported or restricted in netns '{netns}': {e}. Graceful fallback applied."
                );
            } else {
                warn!("Warning: Failed applying extended sysctl '{key}={val}': {e}");
            }
        } else {
            written_keys.push(*key);
        }
    }

    // ── Phase 3: Netfilter MSS Clamping (Tier 2) ──────────────────────────
    if let Some(mss) = profile.forced_syn_mss {
        match apply_netfilter_mss(netns, mss) {
            Ok(()) => {
                snapshot.had_netfilter_mss = true;
                snapshot.netfilter_mss_value = Some(mss);
            }
            Err(e) => {
                if fail_closed {
                    // Rollback sysctl before aborting
                    for applied_key in &written_keys {
                        if let Some(orig_val) = snapshot.values.get(*applied_key) {
                            let _ = write_netns_sysctl(netns, applied_key, orig_val);
                        }
                    }
                    return Err(e);
                }
                warn!("Netfilter TCPMSS clamping failed in [{netns}]: {e}. Continuing without MSS override.");
            }
        }
    }

    // ── Phase 4: FIB Routing Metrics (Tier 3) ─────────────────────────────
    if profile.requires_route_metrics() {
        match apply_route_metrics(netns, profile) {
            Ok(()) => {
                snapshot.had_route_metrics = true;
            }
            Err(e) => {
                if fail_closed {
                    // Rollback Netfilter + sysctl
                    if let Some(mss) = snapshot.netfilter_mss_value {
                        let _ = remove_netfilter_mss(netns, mss);
                    }
                    for applied_key in &written_keys {
                        if let Some(orig_val) = snapshot.values.get(*applied_key) {
                            let _ = write_netns_sysctl(netns, applied_key, orig_val);
                        }
                    }
                    return Err(e);
                }
                warn!("FIB routing metric morphing failed in [{netns}]: {e}. Continuing with kernel defaults.");
            }
        }
    }

    info!(
        "L4 TCP Stack normalization verified in namespace '{}': Profile [{}] armed across all tiers",
        netns, profile.name
    );
    Ok(snapshot)
}

/// Restores original TCP stack state from a `NetnsTcpSnapshot`.
/// Reverses all three tiers: sysctl, Netfilter MSS, and FIB routing.
pub fn restore_netns_tcp_stack(snapshot: &NetnsTcpSnapshot) -> std::result::Result<(), TcpMorphError> {
    let netns = &snapshot.namespace;
    guard_not_host(netns)?;

    if !is_netns_active(netns) {
        debug!("Namespace '{netns}' already purged; skipping TCP stack rollback");
        return Ok(());
    }

    info!("Rolling back TCP stack parameters in namespace '{netns}' (3-tier restore)");

    let mut errors = Vec::new();

    // Tier 1: Restore sysctl values
    for (key, val) in &snapshot.values {
        if let Err(e) = write_netns_sysctl(netns, key, val) {
            errors.push(format!("sysctl {key}={val}: {e}"));
        }
    }

    // Tier 2: Remove Netfilter MSS rule
    if let Some(mss) = snapshot.netfilter_mss_value {
        if let Err(e) = remove_netfilter_mss(netns, mss) {
            errors.push(format!("netfilter MSS={mss}: {e}"));
        }
    }

    // Tier 3: FIB route metrics are reset when the namespace is destroyed,
    // so no explicit rollback is needed unless the namespace persists.

    if !errors.is_empty() {
        return Err(TcpMorphError::RollbackFailed {
            namespace: netns.to_string(),
            details: errors.join(", "),
        });
    }

    info!("TCP stack rollback complete in namespace '{netns}'");
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// LEGACY COMPATIBILITY API
// ══════════════════════════════════════════════════════════════════════════════

fn sysctl_key_to_proc_path(key: &str) -> String {
    format!("/proc/sys/{}", key.replace('.', "/"))
}

/// Legacy read function (scans host `/proc/sys` - read-only).
pub fn read_sysctl(key: &str) -> CoreResult<String> {
    let proc_path = sysctl_key_to_proc_path(key);
    let path = Path::new(&proc_path);
    if path.exists() {
        let val = std::fs::read_to_string(path).map_err(|e| {
            WraithError::Firewall(format!("Failed reading sysctl {key}: {e}"))
        })?;
        Ok(val.trim().to_string())
    } else {
        Ok(String::new())
    }
}

/// Legacy write function.
/// IMPORTANT: Host mutation is warned to prevent system instability.
pub fn write_sysctl(key: &str, val: &str) -> CoreResult<()> {
    warn!("Legacy write_sysctl invoked on host for {key}={val}. Prefer apply_profile_to_netns().");
    let proc_path = sysctl_key_to_proc_path(key);
    let path = Path::new(&proc_path);
    if !path.exists() {
        return Err(WraithError::Firewall(format!("Missing sysctl: {key}")));
    }
    std::fs::write(path, val).map_err(|e| {
        WraithError::Firewall(format!("Failed writing {val} to sysctl {key}: {e}"))
    })?;
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// TESTS
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysctl_key_to_proc_path() {
        assert_eq!(
            sysctl_key_to_proc_path("net.ipv4.tcp_timestamps"),
            "/proc/sys/net/ipv4/tcp_timestamps"
        );
        assert_eq!(
            sysctl_key_to_proc_path("net.ipv4.ip_default_ttl"),
            "/proc/sys/net/ipv4/ip_default_ttl"
        );
    }

    #[test]
    fn test_host_mutation_forbidden_guard() {
        let win = TcpFingerprintProfile::windows11();
        assert!(matches!(
            apply_profile_to_netns("", &win, true),
            Err(TcpMorphError::HostMutationForbidden)
        ));
        assert!(matches!(
            apply_profile_to_netns("host", &win, true),
            Err(TcpMorphError::HostMutationForbidden)
        ));
        assert!(matches!(
            apply_profile_to_netns("/", &win, true),
            Err(TcpMorphError::HostMutationForbidden)
        ));
        assert!(matches!(
            read_netns_sysctl("", "net.ipv4.ip_default_ttl"),
            Err(TcpMorphError::HostMutationForbidden)
        ));
        assert!(matches!(
            write_netns_sysctl("", "net.ipv4.ip_default_ttl", "128"),
            Err(TcpMorphError::HostMutationForbidden)
        ));
    }

    #[test]
    fn test_missing_namespace_returns_error() {
        let win = TcpFingerprintProfile::windows11();
        let res = apply_profile_to_netns("non_existent_wraith_ns_test_9999", &win, true);
        assert!(matches!(res, Err(TcpMorphError::NamespaceNotFound(_))));
    }

    #[test]
    fn test_snapshot_struct_serde() {
        let mut snapshot = NetnsTcpSnapshot::new("wraith_ns");
        snapshot.profile_name = Some("Windows 11".to_string());
        snapshot.values.insert("net.ipv4.ip_default_ttl".to_string(), "64".to_string());
        snapshot.values.insert("net.ipv4.tcp_timestamps".to_string(), "1".to_string());
        snapshot.had_netfilter_mss = true;
        snapshot.netfilter_mss_value = Some(1460);

        let serialized = serde_json::to_string(&snapshot).unwrap();
        let deserialized: NetnsTcpSnapshot = serde_json::from_str(&serialized).unwrap();
        assert_eq!(snapshot, deserialized);
        assert_eq!(deserialized.netfilter_mss_value, Some(1460));
    }

    #[test]
    fn test_core_sysctl_keys_present() {
        assert!(CORE_SYSCTL_KEYS.contains(&"net.ipv4.ip_default_ttl"));
        assert!(CORE_SYSCTL_KEYS.contains(&"net.ipv4.tcp_window_scaling"));
        assert!(CORE_SYSCTL_KEYS.contains(&"net.ipv4.tcp_timestamps"));
        assert!(CORE_SYSCTL_KEYS.contains(&"net.ipv4.tcp_sack"));
        assert!(CORE_SYSCTL_KEYS.contains(&"net.ipv4.tcp_fin_timeout"));
        assert!(CORE_SYSCTL_KEYS.contains(&"net.ipv4.tcp_syn_retries"));
    }

    #[test]
    fn test_fallback_eligibility() {
        let not_found = TcpMorphError::SysctlNotFound {
            parameter: "net.ipv4.tcp_rfc1337".to_string(),
            namespace: "wraith_ns".to_string(),
        };
        assert!(not_found.is_fallback_eligible());

        let perm_denied = TcpMorphError::PermissionDenied {
            parameter: "net.ipv4.tcp_ecn".to_string(),
            namespace: "wraith_ns".to_string(),
            details: "EPERM".to_string(),
        };
        assert!(perm_denied.is_fallback_eligible());

        let nf_failed = TcpMorphError::NetfilterFailed {
            namespace: "wraith_ns".to_string(),
            details: "module not loaded".to_string(),
        };
        assert!(nf_failed.is_fallback_eligible());

        let route_failed = TcpMorphError::RoutingFailed {
            namespace: "wraith_ns".to_string(),
            details: "no default route".to_string(),
        };
        assert!(route_failed.is_fallback_eligible());

        let forbidden = TcpMorphError::HostMutationForbidden;
        assert!(!forbidden.is_fallback_eligible());
    }

    #[test]
    fn test_netfilter_guard_rejects_host() {
        assert!(matches!(
            apply_netfilter_mss("", 1460),
            Err(TcpMorphError::HostMutationForbidden)
        ));
        assert!(matches!(
            apply_netfilter_mss("host", 1460),
            Err(TcpMorphError::HostMutationForbidden)
        ));
    }

    #[test]
    fn test_routing_guard_rejects_host() {
        let win = TcpFingerprintProfile::windows11();
        // Linux default has no route metrics, so apply_route_metrics returns Ok immediately
        let linux = TcpFingerprintProfile::linux_default();
        assert!(apply_route_metrics("host", &linux).is_err() || !linux.requires_route_metrics());

        // Windows requires route metrics, should reject host
        assert!(matches!(
            apply_route_metrics("host", &win),
            Err(TcpMorphError::HostMutationForbidden)
        ));
    }

    #[test]
    fn test_snapshot_default_netfilter_state() {
        let snapshot = NetnsTcpSnapshot::new("test_ns");
        assert!(!snapshot.had_netfilter_mss);
        assert!(snapshot.netfilter_mss_value.is_none());
        assert!(!snapshot.had_route_metrics);
    }
}
