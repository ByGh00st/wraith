//! Wraith Layer 4 TCP Stack Morphing & p0f Evasion Engine
//!
//! Normalizes Linux kernel TCP/IP stack signatures within isolated Network Namespaces
//! toward reference profiles. Configuration does not prove on-wire L4/L7 equivalence.
//!
//! ## Three-Tier Application Architecture
//!
//! ```text
//! apply_profile_to_netns()
//! ├── 1. Sysctl Tier     → apply_sysctl_profile() [snapshot, readback, rollback]
//! ├── 2. Netfilter Tier  → apply_netfilter_mss()    [iptables mangle, rollback-capable]
//! └── 3. FIB Routing Tier→ apply_route_metrics()    [ip route change, rollback-capable]
//! ```
//!
//! ### OPSEC & Kernel Architecture Guards:
//! 1. **Zero Host Contamination**: Host root network parameters are NEVER modified globally.
//! 2. **Tokio Thread-Safety (Anti-setns Contamination)**: All namespace operations execute
//!    via pinned namespace descriptors and `nsenter` subprocesses, ensuring worker threads never
//!    inherit a foreign namespace.
//! 3. **Layer Separation**: `syn_mss` and `init_cwnd`/`init_rwnd` are decoupled from sysctl
//!    and routed to Netfilter (iptables) and Routing (FIB) layers respectively.
//! 4. **Graceful Kernel Fallback**: Differentiates between core per-netns parameters (atomic fail-closed)
//!    and extended parameters (required in strict mode).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use crate::tcp_namespace::Namespace;
pub use crate::tcp_namespace::NamespaceIdentity;
use tracing::{debug, info, warn};
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

/// Optional profile settings known to be per-network-namespace.
pub const EXTENDED_SYSCTL_KEYS: &[&str] = &[
    "net.ipv4.ip_local_port_range",
    "net.ipv4.tcp_ecn",
    "net.ipv4.tcp_rfc1337",
];

// ══════════════════════════════════════════════════════════════════════════════
// ERROR TAXONOMY
// ══════════════════════════════════════════════════════════════════════════════

/// Precision error taxonomy for L4 TCP stack morphing operations.
#[derive(Debug, thiserror::Error)]
pub enum TcpMorphError {
    #[error("Only the Wraith-owned namespace can be changed, got '{0}'")]
    UnmanagedNamespace(String),

    #[error("Namespace TCP configuration requires Linux")]
    UnsupportedPlatform,

    #[error("Sysctl key '{0}' is not an allowed per-network-namespace TCP setting")]
    InvalidSysctl(String),

    #[error("Invalid value for sysctl '{0}'")]
    InvalidValue(String),

    #[error(transparent)]
    InvalidProfile(#[from] wraith_core::tcp_fingerprint::TcpProfileError),

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
                | Self::ExecutionFailed { .. }
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
    #[serde(default)]
    pub namespace_identity: Option<NamespaceIdentity>,
    /// Applied profile name; absent when safely skipped.
    pub profile_name: Option<String>,
    /// Key-value mappings of backed-up sysctl parameters.
    pub values: HashMap<String, String>,
    /// Profile applied by the complete three-tier transaction (not a wire measurement).
    #[serde(default)]
    pub applied_profile: Option<TcpFingerprintProfile>,
    /// New rules carry a Wraith ownership comment; legacy snapshots remain readable.
    #[serde(default)]
    pub mss_rule_tagged: bool,
    /// Whether this transaction installed a Netfilter MSS rule.
    pub had_netfilter_mss: bool,
    /// The MSS value that was set (for rollback deletion).
    pub netfilter_mss_value: Option<u16>,
    /// Whether FIB route metrics were modified.
    pub had_route_metrics: bool,
    #[serde(default)]
    pub original_route_metrics: Option<RouteMetricSnapshot>,
}

impl NetnsTcpSnapshot {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            namespace_identity: None,
            applied_profile: None,
            mss_rule_tagged: false,
            profile_name: None,
            values: HashMap::new(),
            had_netfilter_mss: false,
            netfilter_mss_value: None,
            had_route_metrics: false,
            original_route_metrics: None,
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// NAMESPACE VALIDATION
// ══════════════════════════════════════════════════════════════════════════════

/// Guard: validates that the target is not the host namespace.
fn guard_not_host(netns: &str) -> std::result::Result<(), TcpMorphError> {
    crate::tcp_namespace::validate_name(netns)
}

pub fn is_netns_active(netns: &str) -> bool {
    Namespace::open(netns).is_ok()
}

fn validate_sysctl_key(key: &str) -> std::result::Result<(), TcpMorphError> {
    if CORE_SYSCTL_KEYS.contains(&key) || ["net.ipv4.ip_local_port_range", "net.ipv4.tcp_ecn", "net.ipv4.tcp_rfc1337"].contains(&key) {
        Ok(())
    } else { Err(TcpMorphError::InvalidSysctl(key.into())) }
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 1: SYSCTL OPERATIONS (Namespace-Isolated Sub-Process)
// ══════════════════════════════════════════════════════════════════════════════

/// Reads a sysctl parameter value strictly within an isolated network namespace.
///
/// Executes through a pinned namespace handle in a separate `nsenter` process.
/// Tokio worker threads are completely immune to namespace contamination.
pub fn read_netns_sysctl(netns: &str, key: &str) -> std::result::Result<String, TcpMorphError> {
    validate_sysctl_key(key)?;
    read_pinned_sysctl(&Namespace::open(netns)?, key)
}

fn checked_sysctl(ns: &Namespace, key: &str, args: &[&str]) -> std::result::Result<String, TcpMorphError> {
    validate_sysctl_key(key)?;
    let output = ns.run("sysctl", args)?;
    if output.status.success() { return Ok(String::from_utf8_lossy(&output.stdout).trim().into()); }
    let details = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if details.contains("Permission denied") || details.contains("Operation not permitted") {
        return Err(TcpMorphError::PermissionDenied { parameter: key.into(), namespace: ns.name.clone(), details });
    }
    if details.contains("No such file or directory") || details.contains("cannot stat") {
        return Err(TcpMorphError::SysctlNotFound { parameter: key.into(), namespace: ns.name.clone() });
    }
    Err(TcpMorphError::ExecutionFailed { parameter: key.into(), namespace: ns.name.clone(), details })
}

fn read_pinned_sysctl(ns: &Namespace, key: &str) -> std::result::Result<String, TcpMorphError> {
    checked_sysctl(ns, key, &["-n", key])
}

fn write_pinned_sysctl(ns: &Namespace, key: &str, val: &str) -> std::result::Result<(), TcpMorphError> {
    validate_sysctl_key(key)?;
    if !val.bytes().any(|b| b.is_ascii_digit()) || !val.bytes().all(|b| b.is_ascii_digit() || b == b' ' || b == b'\t') {
        return Err(TcpMorphError::InvalidValue(key.into()));
    }
    checked_sysctl(ns, key, &["-w", &format!("{key}={val}")])?;
    let observed = read_pinned_sysctl(ns, key)?;
    verify_sysctl_value(&ns.name, key, val, &observed)?;
    debug!("Namespace [{}] sysctl set and read back: {key}={val}", ns.name);
    Ok(())
}

/// Low-level single setting update. Use apply_sysctl_profile for transactional rollback.
pub fn write_netns_sysctl(netns: &str, key: &str, val: &str) -> std::result::Result<(), TcpMorphError> {
    validate_sysctl_key(key)?;
    write_pinned_sysctl(&Namespace::open(netns)?, key, val)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SysctlFailurePolicy {
    #[default]
    FailClosed,
    /// Continue only after no change was made or every attempted write was restored.
    RestoreAndContinue,
}

#[derive(Debug)]
pub enum SysctlApplyOutcome {
    Applied(NetnsTcpSnapshot),
    Skipped { snapshot: NetnsTcpSnapshot, cause: TcpMorphError },
}

/// Snapshot -> write/readback -> reverse rollback in one pinned namespace.
/// This is a recoverable transaction, not a kernel-wide atomic multi-key update.
pub fn apply_sysctl_profile(netns: &str, profile: &TcpFingerprintProfile, policy: SysctlFailurePolicy)
    -> std::result::Result<SysctlApplyOutcome, TcpMorphError> {
    profile.validate()?;
    apply_pinned_sysctl_profile(&Namespace::open(netns)?, profile, policy)
}

fn apply_pinned_sysctl_profile(namespace: &Namespace, profile: &TcpFingerprintProfile, policy: SysctlFailurePolicy)
    -> std::result::Result<SysctlApplyOutcome, TcpMorphError> {
    let netns = namespace.name.as_str();
    let mut snapshot = NetnsTcpSnapshot::new(netns);
    snapshot.namespace_identity = Some(namespace.identity);
    let entries = profile.sysctl_entries();
    match apply_sysctl_transaction(&mut snapshot, &entries,
        |key| read_pinned_sysctl(namespace, key),
        |key, value| write_pinned_sysctl(namespace, key, value)) {
        Ok(()) => {
            snapshot.profile_name = Some(profile.name.clone());
            info!("TCP sysctl profile '{}' applied and read back in {netns}", profile.name);
            Ok(SysctlApplyOutcome::Applied(snapshot))
        }
        Err(cause) if policy == SysctlFailurePolicy::RestoreAndContinue && cause.is_fallback_eligible() => {
            warn!("TCP sysctl profile skipped after safe rollback: {cause}");
            Ok(SysctlApplyOutcome::Skipped { snapshot, cause })
        }
        Err(error) => Err(error),
    }
}

fn apply_sysctl_transaction<R, W>(snapshot: &mut NetnsTcpSnapshot, entries: &[(&str, String)], mut read: R, write: W)
    -> std::result::Result<(), TcpMorphError>
where R: FnMut(&str) -> std::result::Result<String, TcpMorphError>,
      W: FnMut(&str, &str) -> std::result::Result<(), TcpMorphError> {
    for (key, _) in entries { validate_sysctl_key(key)?; }
    for (key, _) in entries { snapshot.values.insert((*key).into(), read(key)?); }
    apply_sysctl_entries(snapshot, entries, true, write).map(|_| ())
}

fn verify_sysctl_value(netns: &str, key: &str, expected: &str, observed: &str) -> std::result::Result<(), TcpMorphError> {
    if expected.split_whitespace().eq(observed.split_whitespace()) { return Ok(()); }
    Err(TcpMorphError::ExecutionFailed {
        parameter: key.into(), namespace: netns.into(),
        details: format!("Readback mismatch: requested {expected:?}, observed {observed:?}"),
    })
}

// Preflight every required backup before the first write. Include the attempted key
// in rollback: a command can change the value and then fail its readback.
fn apply_sysctl_entries<F>(snapshot: &NetnsTcpSnapshot, entries: &[(&str, String)], strict: bool, mut write: F)
    -> std::result::Result<bool, TcpMorphError>
where F: FnMut(&str, &str) -> std::result::Result<(), TcpMorphError> {
    for (key, _) in entries {
        if !snapshot.values.contains_key(*key) && (strict || CORE_SYSCTL_KEYS.contains(key)) {
            return Err(TcpMorphError::ExecutionFailed { parameter: (*key).into(),
                namespace: snapshot.namespace.clone(), details: "Original value unavailable; refusing an untracked mutation".into() });
        }
    }
    let mut complete = true;
    let mut attempted = Vec::new();
    for (key, value) in entries {
        if !snapshot.values.contains_key(*key) { complete = false; continue; }
        attempted.push(*key);
        if let Err(error) = write(key, value) {
            if !strict && !CORE_SYSCTL_KEYS.contains(key) {
                // Even optional writes must be restored when verification fails.
                if write(key, &snapshot.values[*key]).is_ok() {
                    complete = false;
                    warn!("Optional TCP parameter {key} was not applied: {error}");
                    continue;
                }
                // Failed optional restoration is fatal too; roll back core writes below.
            }
            let mut failures = Vec::new();
            for applied in attempted.iter().rev() {
                if let Err(e) = write(applied, &snapshot.values[*applied]) { failures.push(e.to_string()); }
            }
            if !failures.is_empty() {
                return Err(TcpMorphError::RollbackFailed { namespace: snapshot.namespace.clone(),
                    details: format!("{error}; {}", failures.join("; ")) });
            }
            return Err(error);
        }
    }
    Ok(complete)
}

/// Captures a snapshot of target sysctl parameters inside the specified namespace.
pub fn snapshot_netns_tcp_stack(netns: &str, keys: &[&str]) -> std::result::Result<NetnsTcpSnapshot, TcpMorphError> {
    for key in keys { validate_sysctl_key(key)?; }
    let namespace = Namespace::open(netns)?;
    let mut snapshot = NetnsTcpSnapshot::new(netns);
    snapshot.namespace_identity = Some(namespace.identity);
    for key in keys { snapshot.values.insert((*key).into(), read_pinned_sysctl(&namespace, key)?); }
    Ok(snapshot)
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 2: NETFILTER MSS CLAMPING (iptables mangle)
// ══════════════════════════════════════════════════════════════════════════════

/// Install an owned IPv4 SYN MSS cap, verify it, and remove it if readback fails.
pub fn apply_netfilter_mss(netns: &str, mss: u16) -> std::result::Result<(), TcpMorphError> {
    install_pinned_mss(&Namespace::open(netns)?, mss)
}

fn mss_args(operation: &str, mss: u16, tagged: bool) -> Vec<String> {
    let mut args = vec!["-w", "5", "-t", "mangle", operation, "POSTROUTING", "-p", "tcp",
        "--tcp-flags", "SYN,RST", "SYN"];
    if tagged { args.extend(["-m", "comment", "--comment", "wraith-l4"]); }
    args.extend(["-j", "TCPMSS", "--set-mss"]);
    let mut args: Vec<String> = args.into_iter().map(String::from).collect();
    args.push(mss.to_string());
    args
}

fn mss_command(namespace: &Namespace, operation: &str, mss: u16, tagged: bool)
    -> std::result::Result<bool, TcpMorphError> {
    let args = mss_args(operation, mss, tagged);
    let refs: Vec<_> = args.iter().map(String::as_str).collect();
    let output = namespace.run("iptables", &refs)?;
    if output.status.success() { return Ok(true); }
    // iptables -C uses exit 1 for an absent rule. Syntax/module/lock errors stay errors.
    if operation == "-C" && output.status.code() == Some(1) { return Ok(false); }
    Err(TcpMorphError::NetfilterFailed { namespace: namespace.name.clone(),
        details: format!("TCPMSS {operation}: {}", String::from_utf8_lossy(&output.stderr).trim()) })
}

fn install_pinned_mss(namespace: &Namespace, mss: u16) -> std::result::Result<(), TcpMorphError> {
    if mss < 536 { return Err(TcpMorphError::InvalidValue("SYN MSS below 536".into())); }
    install_mss_transaction(&namespace.name, |op| mss_command(namespace, op, mss, true))
}

fn install_mss_transaction<F>(netns: &str, mut command: F) -> std::result::Result<(), TcpMorphError>
where F: FnMut(&str) -> std::result::Result<bool, TcpMorphError> {
    let error = |details: &str| TcpMorphError::NetfilterFailed { namespace: netns.into(), details: details.into() };
    if command("-C")? { return Err(error("MSS rule already exists; refusing duplicate ownership")); }
    let applied = command("-A").and_then(|_| {
        if command("-C")? { Ok(()) } else { Err(error("MSS rule readback mismatch")) }
    });
    if let Err(cause) = applied {
        // A failing command may have mutated state. Query and undo before returning.
        let cleanup = (|| {
            if command("-C")? { command("-D")?; }
            if command("-C")? { return Err(error("MSS rule remains after rollback")); }
            Ok(())
        })();
        if let Err(rollback) = cleanup {
            return Err(TcpMorphError::RollbackFailed { namespace: netns.into(), details: format!("{cause}; {rollback}") });
        }
        return Err(cause);
    }
    info!("Namespace [{netns}] owned TCPMSS rule installed and read back");
    Ok(())
}

/// Remove a new owned rule. Snapshot restoration also supports older untagged rules.
pub fn remove_netfilter_mss(netns: &str, mss: u16) -> std::result::Result<(), TcpMorphError> {
    remove_pinned_mss(&Namespace::open(netns)?, mss, true)
}

fn remove_pinned_mss(namespace: &Namespace, mss: u16, tagged: bool) -> std::result::Result<(), TcpMorphError> {
    if mss_command(namespace, "-C", mss, tagged)? { mss_command(namespace, "-D", mss, tagged)?; }
    if mss_command(namespace, "-C", mss, tagged)? {
        return Err(TcpMorphError::NetfilterFailed { namespace: namespace.name.clone(), details: "MSS rule remains after removal".into() });
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 3: FIB ROUTING METRICS (ip route)
// ══════════════════════════════════════════════════════════════════════════════

/// Applies FIB routing metrics (initcwnd / initrwnd) to the default route inside the namespace.
///
/// initrwnd influences the receive window; initcwnd controls initial send congestion.
/// Neither guarantees an exact SYN window or complete operating-system fingerprint.
///
/// ## ip route Command Executed
/// ```bash
/// ip netns exec <ns> ip route change default via <gw> initcwnd <N> initrwnd <N>
/// ```
pub fn apply_route_metrics(
    netns: &str,
    profile: &TcpFingerprintProfile,
) -> std::result::Result<(), TcpMorphError> {
    if !profile.requires_route_metrics() { return Ok(()); }
    profile.validate()?;
    let namespace = Namespace::open(netns)?;
    let original = read_pinned_route_metrics(&namespace)?;
    apply_pinned_route_metrics(&namespace, profile, &original)
}

fn apply_pinned_route_metrics(namespace: &Namespace, profile: &TcpFingerprintProfile, original: &RouteMetricSnapshot)
    -> std::result::Result<(), TcpMorphError> {
    let netns = namespace.name.as_str();
    let requested = RouteMetricSnapshot {
        identity: original.identity.clone(),
        attributes: original.attributes.clone(),
        init_cwnd: profile.init_cwnd.map(u32::from).unwrap_or(original.init_cwnd),
        init_rwnd: profile.init_rwnd.map(u32::from).unwrap_or(original.init_rwnd),
    };
    if let Err(error) = set_pinned_route_metrics(namespace, &requested) {
        if let Err(rollback) = set_pinned_route_metrics(namespace, original) {
            return Err(TcpMorphError::RollbackFailed { namespace: netns.into(),
                details: format!("{error}; {rollback}") });
        }
        return Err(error);
    }
    Ok(())
}

/// Only the metrics changed by Wraith; zero means use the kernel default.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteMetricSnapshot {
    pub identity: Vec<String>,
    #[serde(default)]
    pub attributes: Vec<String>,
    pub init_cwnd: u32,
    pub init_rwnd: u32,
}

fn parse_route_metrics(netns: &str, route: &str) -> std::result::Result<RouteMetricSnapshot, TcpMorphError> {
    let identity = default_route_identity(netns, route)?;
    let parts: Vec<_> = route.split_whitespace().collect();
    let metric = |key| -> std::result::Result<u32, TcpMorphError> {
        match parts.iter().position(|part| *part == key) {
            None => Ok(0),
            Some(index) => parts.get(index + 1).and_then(|value| value.parse().ok())
                .ok_or_else(|| TcpMorphError::RoutingFailed { namespace: netns.into(),
                    details: format!("Unsupported or locked {key} route metric") }),
        }
    };
    let mut attributes = Vec::new();
    let mut index = 1;
    while index < parts.len() {
        let key = parts[index];
        let value = parts.get(index + 1).ok_or_else(|| TcpMorphError::RoutingFailed {
            namespace: netns.into(), details: "Incomplete route attribute".into() })?;
        if ["proto", "scope", "src"].contains(&key) {
            attributes.extend([key.to_string(), (*value).to_string()]);
        } else if !["via", "dev", "metric", "table", "initcwnd", "initrwnd"].contains(&key) {
            return Err(TcpMorphError::RoutingFailed { namespace: netns.into(),
                details: format!("Unsupported route attribute {key}; refusing a lossy route change") });
        }
        index += 2;
    }
    Ok(RouteMetricSnapshot { identity, attributes, init_cwnd: metric("initcwnd")?, init_rwnd: metric("initrwnd")? })
}

fn read_pinned_route_metrics(namespace: &Namespace) -> std::result::Result<RouteMetricSnapshot, TcpMorphError> {
    let netns = namespace.name.as_str();
    let output = namespace.run("ip", &["-o", "-4", "route", "show", "default"])?;
    if !output.status.success() {
        return Err(TcpMorphError::RoutingFailed { namespace: netns.into(),
            details: format!("Cannot read default route: {}", String::from_utf8_lossy(&output.stderr).trim()) });
    }
    parse_route_metrics(netns, &String::from_utf8_lossy(&output.stdout))
}

fn route_metric_args(saved: &RouteMetricSnapshot) -> Vec<String> {
    let mut args = saved.identity.clone();
    args.extend(saved.attributes.clone());
    args.extend(["initcwnd".into(), saved.init_cwnd.to_string(), "initrwnd".into(), saved.init_rwnd.to_string()]);
    args
}

fn set_pinned_route_metrics(namespace: &Namespace, saved: &RouteMetricSnapshot) -> std::result::Result<(), TcpMorphError> {
    let netns = namespace.name.as_str();
    update_route_metrics(netns, saved, || read_pinned_route_metrics(namespace), |args| {
        let mut command_args = vec!["-4", "route", "change"];
        command_args.extend(args.iter().map(String::as_str));
        let output = namespace.run("ip", &command_args)?;
        if !output.status.success() {
            return Err(TcpMorphError::RoutingFailed { namespace: netns.into(),
                details: format!("Route metric write failed: {}", String::from_utf8_lossy(&output.stderr).trim()) });
        }
        Ok(())
    })
}

fn update_route_metrics<R, W>(netns: &str, saved: &RouteMetricSnapshot, mut read: R, mut write: W)
    -> std::result::Result<(), TcpMorphError>
where R: FnMut() -> std::result::Result<RouteMetricSnapshot, TcpMorphError>,
      W: FnMut(Vec<String>) -> std::result::Result<(), TcpMorphError> {
    let identity = default_route_identity(netns, &saved.identity.join(" "))?;
    // Validate persisted arguments too, before passing them to iproute2.
    let parsed = parse_route_metrics(netns, &route_metric_args(saved).join(" "))?;
    let current = read()?;
    if parsed != *saved || identity != saved.identity || current.identity != identity || current.attributes != saved.attributes {
        return Err(TcpMorphError::RoutingFailed { namespace: netns.into(), details: "Default route identity changed".into() });
    }
    write(route_metric_args(saved))?;
    if read()? != *saved {
        return Err(TcpMorphError::RoutingFailed { namespace: netns.into(), details: "Route metric readback mismatch".into() });
    }
    Ok(())
}

// A single unicast route is required; never guess between multiple defaults or
// collapse multipath next hops into a different route.
fn default_route_identity(netns: &str, routes: &str) -> std::result::Result<Vec<String>, TcpMorphError> {
    let lines: Vec<_> = routes.lines().filter(|line| !line.trim().is_empty()).collect();
    let invalid = || TcpMorphError::RoutingFailed { namespace: netns.into(),
        details: "Expected exactly one unicast default route with a device".into() };
    if lines.len() != 1 { return Err(invalid()); }
    let parts: Vec<_> = lines[0].split_whitespace().collect();
    if parts.first() != Some(&"default") || parts.contains(&"nexthop") { return Err(invalid()); }
    let mut args = vec!["default".to_string()];
    for key in ["via", "dev", "metric", "table"] {
        if let Some(index) = parts.iter().position(|p| *p == key) {
            let value = parts.get(index + 1).ok_or_else(invalid)?;
            args.extend([key.to_string(), (*value).to_string()]);
        } else if key == "dev" { return Err(invalid()); }
    }
    Ok(args)
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
/// - Core sysctl failure → rollback of attempted parameters → abort.
/// - Netfilter/routing failure → restore every tier; abort or explicitly skip after clean rollback.
/// - `fail_closed`: Requires backups and successful writes for extended parameters too.
pub fn apply_profile_to_netns(
    netns: &str,
    profile: &TcpFingerprintProfile,
    fail_closed: bool,
) -> std::result::Result<NetnsTcpSnapshot, TcpMorphError> {
    let namespace = Namespace::open(netns)?;
    profile.validate()?;
    let route_snapshot = if profile.requires_route_metrics() { Some(read_pinned_route_metrics(&namespace)?) } else { None };
    let policy = if fail_closed { SysctlFailurePolicy::FailClosed } else { SysctlFailurePolicy::RestoreAndContinue };
    let mut snapshot = match apply_pinned_sysctl_profile(&namespace, profile, policy)? {
        SysctlApplyOutcome::Applied(snapshot) => snapshot,
        SysctlApplyOutcome::Skipped { snapshot, .. } => return Ok(snapshot),
    };
    snapshot.original_route_metrics = route_snapshot;
    let result = (|| {
        if let Some(mss) = profile.syn_mss {
            install_pinned_mss(&namespace, mss)?;
            snapshot.had_netfilter_mss = true;
            snapshot.mss_rule_tagged = true;
            snapshot.netfilter_mss_value = Some(mss);
        }
        if let Some(original) = &snapshot.original_route_metrics {
            // Journal before attempting the write, including a failed readback.
            snapshot.had_route_metrics = true;
            apply_pinned_route_metrics(&namespace, profile, original)?;
        }
        Ok::<(), TcpMorphError>(())
    })();
    if let Err(error) = result {
        restore_pinned_tcp_stack(&namespace, &snapshot).map_err(|rollback| TcpMorphError::RollbackFailed {
            namespace: netns.into(), details: format!("{error}; {rollback}"),
        })?;
        if fail_closed || !error.is_fallback_eligible() { return Err(error); }
        warn!("L4 configuration skipped after complete rollback: {error}");
        return Ok(NetnsTcpSnapshot { namespace_identity: Some(namespace.identity), ..NetnsTcpSnapshot::new(netns) });
    }
    snapshot.applied_profile = Some(profile.clone());
    info!("L4 profile '{}' applied and read back in {netns}; wire fingerprint not measured", profile.name);
    Ok(snapshot)
}

/// Restores original TCP stack state from a `NetnsTcpSnapshot`.
/// Reverses all three tiers: sysctl, Netfilter MSS, and FIB routing.
pub fn restore_netns_tcp_stack(snapshot: &NetnsTcpSnapshot) -> std::result::Result<(), TcpMorphError> {
    let netns = &snapshot.namespace;
    guard_not_host(netns)?;

    let namespace = match Namespace::open(netns) {
        Ok(namespace) => namespace,
        Err(TcpMorphError::NamespaceNotFound(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    restore_pinned_tcp_stack(&namespace, snapshot)
}

fn restore_pinned_tcp_stack(namespace: &Namespace, snapshot: &NetnsTcpSnapshot) -> std::result::Result<(), TcpMorphError> {
    let netns = namespace.name.as_str();
    if snapshot.namespace_identity.is_some_and(|identity| identity != namespace.identity) {
        return Err(TcpMorphError::RollbackFailed { namespace: netns.into(), details: "Namespace was replaced; refusing to restore into another lifetime".into() });
    }
    // Check all persisted keys before any rollback write, including legacy snapshots.
    for key in snapshot.values.keys() { validate_sysctl_key(key)?; }

    info!("Rolling back TCP stack parameters in namespace '{netns}' (3-tier restore)");

    let mut errors = Vec::new();

    // Tier 1: Restore sysctl values
    for (key, val) in &snapshot.values {
        if let Err(e) = write_pinned_sysctl(namespace, key, val) {
            errors.push(format!("sysctl {key}={val}: {e}"));
        }
    }

    // Tier 2: Remove Netfilter MSS rule
    if let Some(mss) = snapshot.netfilter_mss_value {
        if let Err(e) = remove_pinned_mss(namespace, mss, snapshot.mss_rule_tagged) {
            errors.push(format!("netfilter MSS={mss}: {e}"));
        }
    }

    // Tier 3: restore metrics even when the namespace remains alive.
    if snapshot.had_route_metrics {
        match &snapshot.original_route_metrics {
            Some(original) => {
                if let Err(error) = set_pinned_route_metrics(namespace, original) { errors.push(format!("route metrics: {error}")); }
            }
            None => errors.push("Original route metrics missing from legacy snapshot; namespace teardown is required".into()),
        }
    }

    if !errors.is_empty() {
        return Err(TcpMorphError::RollbackFailed {
            namespace: netns.to_string(),
            details: errors.join(", "),
        });
    }

    info!("TCP stack rollback complete in namespace '{netns}'");
    Ok(())
}

/// Fresh kernel observations. These verify configuration, never JA3/JA4 or p0f equivalence.
#[derive(Debug)]
pub struct TcpStackTelemetry {
    pub values: HashMap<String, String>,
    pub mss_present: Option<bool>,
    pub route: Option<RouteMetricSnapshot>,
    pub matches_profile: bool,
}

pub fn inspect_tcp_stack(snapshot: &NetnsTcpSnapshot) -> std::result::Result<TcpStackTelemetry, TcpMorphError> {
    let namespace = Namespace::open(&snapshot.namespace)?;
    validate_telemetry_identity(snapshot.namespace_identity, namespace.identity)?;
    let profile = snapshot.applied_profile.as_ref().ok_or_else(|| TcpMorphError::InvalidValue("Legacy snapshot lacks applied profile; live comparison unavailable".into()))?;
    profile.validate()?;
    let mut values = HashMap::new();
    for (key, _) in profile.sysctl_entries() { values.insert(key.into(), read_pinned_sysctl(&namespace, key)?); }
    let mss_present = profile.syn_mss.map(|mss| mss_command(&namespace, "-C", mss, snapshot.mss_rule_tagged)).transpose()?;
    let route = if profile.requires_route_metrics() { Some(read_pinned_route_metrics(&namespace)?) } else { None };
    let matches_profile = observations_match(profile, &values, mss_present, route.as_ref())
        && (!profile.requires_route_metrics() || route.as_ref().zip(snapshot.original_route_metrics.as_ref())
            .is_some_and(|(current, original)| current.identity == original.identity && current.attributes == original.attributes));
    Ok(TcpStackTelemetry { values, mss_present, route, matches_profile })
}

fn validate_telemetry_identity(saved: Option<NamespaceIdentity>, current: NamespaceIdentity) -> std::result::Result<(), TcpMorphError> {
    if saved == Some(current) { return Ok(()); }
    Err(TcpMorphError::InvalidValue("Namespace lifetime is different or unrecorded; live comparison unavailable".into()))
}

fn observations_match(profile: &TcpFingerprintProfile, values: &HashMap<String, String>, mss_present: Option<bool>, route: Option<&RouteMetricSnapshot>) -> bool {
    profile.sysctl_entries().iter().all(|(key, expected)| values.get(*key).is_some_and(|actual|
        expected.split_whitespace().eq(actual.split_whitespace())))
        && (profile.syn_mss.is_none() || mss_present == Some(true))
        && (!profile.requires_route_metrics() || route.is_some_and(|route|
            profile.init_cwnd.is_none_or(|n| u32::from(n) == route.init_cwnd)
            && profile.init_rwnd.is_none_or(|n| u32::from(n) == route.init_rwnd)))
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

/// Kept for source compatibility; global TCP mutations are always rejected.
pub fn write_sysctl(_key: &str, _val: &str) -> CoreResult<()> {
    Err(TcpMorphError::HostMutationForbidden.into())
}

// ══════════════════════════════════════════════════════════════════════════════
// TESTS
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mss_install_verifies_and_refuses_existing_rule_ownership() {
        let mut calls = Vec::new();
        let mut present = false;
        install_mss_transaction("test", |op| {
            calls.push(op.to_string());
            if op == "-A" { present = true; }
            Ok(present)
        }).unwrap();
        assert_eq!(calls, ["-C", "-A", "-C"]);
        let mut calls = Vec::new();
        assert!(install_mss_transaction("test", |op| { calls.push(op.to_string()); Ok(true) }).is_err());
        assert_eq!(calls, ["-C"]);
    }

    #[test]
    fn mss_failed_readback_rolls_back_and_failed_rollback_is_fatal() {
        for fail_delete in [false, true] {
            let mut count = 0;
            let mut present = false;
            let result = install_mss_transaction("test", |op| {
                count += 1;
                if count == 3 || (op == "-D" && fail_delete) {
                    return Err(TcpMorphError::NetfilterFailed { namespace: "test".into(), details: "injected failure".into() });
                }
                if op == "-A" { present = true; }
                if op == "-D" { present = false; }
                Ok(present)
            });
            assert!(result.is_err());
            assert_eq!(matches!(result, Err(TcpMorphError::RollbackFailed { .. })), fail_delete);
            assert_eq!(present, fail_delete);
        }
    }

    #[test]
    fn telemetry_detects_sysctl_mss_and_route_drift() {
        let profile = TcpFingerprintProfile::windows11();
        let mut values: HashMap<String, String> = profile.sysctl_entries().into_iter().map(|(k, v)| (k.into(), v)).collect();
        let mut route = parse_route_metrics("test", "default dev eth0 initcwnd 10 initrwnd 44").unwrap();
        assert!(observations_match(&profile, &values, Some(true), Some(&route)));
        assert!(!observations_match(&profile, &values, Some(false), Some(&route)));
        route.init_rwnd = 45;
        assert!(!observations_match(&profile, &values, Some(true), Some(&route)));
        route.init_rwnd = 44;
        values.insert("net.ipv4.ip_default_ttl".into(), "64".into());
        assert!(!observations_match(&profile, &values, Some(true), Some(&route)));
        let current = NamespaceIdentity { device: 4, inode: 42 };
        assert!(validate_telemetry_identity(Some(current), current).is_ok());
        assert!(validate_telemetry_identity(None, current).is_err());
        assert!(validate_telemetry_identity(Some(NamespaceIdentity { inode: 43, ..current }), current).is_err());
    }

    #[test]
    fn route_attributes_survive_roundtrip_and_unknown_metrics_are_rejected() {
        let saved = parse_route_metrics("test", "default via 10.0.0.1 dev eth0 proto static src 10.0.0.2 initrwnd 44").unwrap();
        assert_eq!(parse_route_metrics("test", &route_metric_args(&saved).join(" ")).unwrap(), saved);
        assert!(parse_route_metrics("test", "default dev eth0 mtu 1400").is_err());
        assert!(parse_route_metrics("test", "default dev eth0 initrwnd lock 44").is_err());
    }

    #[test]
    fn legacy_snapshots_do_not_claim_applied_profile_or_tagged_rules() {
        let mut json = serde_json::to_value(NetnsTcpSnapshot::new("wraith_ns")).unwrap();
        for key in ["applied_profile", "mss_rule_tagged", "namespace_identity"] { json.as_object_mut().unwrap().remove(key); }
        let snapshot: NetnsTcpSnapshot = serde_json::from_value(json).unwrap();
        assert!(snapshot.applied_profile.is_none());
        assert!(!snapshot.mss_rule_tagged);
        assert!(snapshot.namespace_identity.is_none());
    }

    #[test]
    fn global_writer_and_unapproved_sysctls_are_always_rejected() {
        assert!(write_sysctl("net.ipv4.ip_default_ttl", "128").is_err());
        for key in ["kernel.hostname", "vm.drop_caches", "net.ipv4.conf.all.forwarding", "-a", "net/ipv4/tcp_sack", "net.ipv4.tcp_sack=0"] {
            assert!(matches!(write_netns_sysctl(crate::namespace::NAMESPACE_NAME, key, "1"), Err(TcpMorphError::InvalidSysctl(_))));
        }
    }

    #[test]
    fn snapshot_failure_never_starts_mutation() {
        let mut snapshot = NetnsTcpSnapshot::new("test");
        let entries = vec![("net.ipv4.ip_default_ttl", "128".into()), ("net.ipv4.tcp_sack", "1".into())];
        let result = apply_sysctl_transaction(&mut snapshot, &entries, |key| {
            if key.ends_with("tcp_sack") {
                Err(TcpMorphError::SysctlNotFound { parameter: key.into(), namespace: "test".into() })
            } else { Ok("64".into()) }
        }, |_, _| panic!("writes must wait for all backups"));
        assert!(matches!(result, Err(TcpMorphError::SysctlNotFound { .. })));
        assert!(snapshot.profile_name.is_none());
    }

    #[test]
    fn transaction_prevalidates_all_keys_before_reading() {
        let mut snapshot = NetnsTcpSnapshot::new("test");
        assert!(apply_sysctl_transaction(&mut snapshot,
            &[("net.ipv4.tcp_sack", "1".into()), ("kernel.hostname", "1".into())],
            |_| panic!("must validate first"), |_, _| panic!("must validate first")).is_err());
    }

    #[test]
    fn namespace_and_rollback_failures_are_not_fallback_eligible() {
        assert!(!TcpMorphError::HostMutationForbidden.is_fallback_eligible());
        assert!(!TcpMorphError::UnmanagedNamespace("other".into()).is_fallback_eligible());
        assert!(!TcpMorphError::RollbackFailed { namespace: "test".into(), details: "failed".into() }.is_fallback_eligible());
    }

    #[test]
    fn route_metrics_capture_explicit_and_default_values() {
        let route = parse_route_metrics("test", "default via 10.0.0.1 dev eth0 initcwnd 20 initrwnd 30").unwrap();
        assert_eq!((route.init_cwnd, route.init_rwnd), (20, 30));
        let defaults = parse_route_metrics("test", "default dev eth0").unwrap();
        assert_eq!((defaults.init_cwnd, defaults.init_rwnd), (0, 0));
        assert!(parse_route_metrics("test", "default dev eth0 initcwnd lock 10").is_err());
        assert!(parse_route_metrics("test", "default dev eth0 initrwnd invalid").is_err());
    }

    #[test]
    fn route_restore_resets_overrides_and_checks_readback() {
        use std::cell::RefCell;
        let saved = parse_route_metrics("test", "default dev eth0 initcwnd 20").unwrap();
        let current = RefCell::new(parse_route_metrics("test", "default dev eth0 initcwnd 10 initrwnd 44").unwrap());
        update_route_metrics("test", &saved, || Ok(current.borrow().clone()), |args| {
            *current.borrow_mut() = parse_route_metrics("test", &args.join(" "))?;
            Ok(())
        }).unwrap();
        assert_eq!(*current.borrow(), saved);
        let defaults = parse_route_metrics("test", "default dev eth0").unwrap();
        assert!(update_route_metrics("test", &defaults, || Ok(current.borrow().clone()), |_| Ok(())).is_err());
    }

    #[test]
    fn route_restore_refuses_a_replaced_route_without_writing() {
        let saved = parse_route_metrics("test", "default dev eth0 initrwnd 12").unwrap();
        let other = parse_route_metrics("test", "default dev eth1 initrwnd 12").unwrap();
        assert!(update_route_metrics("test", &saved, || Ok(other.clone()), |_| panic!("must not mutate replacement route")).is_err());
    }

    #[test]
    fn missing_backup_prevents_all_writes_in_strict_mode() {
        let mut snapshot = NetnsTcpSnapshot::new("test");
        snapshot.values.insert("net.ipv4.ip_default_ttl".into(), "64".into());
        let entries = vec![("net.ipv4.ip_default_ttl", "128".into()), ("net.ipv4.tcp_ecn", "0".into())];
        let mut writes = 0;
        assert!(apply_sysctl_entries(&snapshot, &entries, true, |_, _| { writes += 1; Ok(()) }).is_err());
        assert_eq!(writes, 0);
    }

    #[test]
    fn failed_extended_write_restores_attempted_value_and_core() {
        let mut snapshot = NetnsTcpSnapshot::new("test");
        snapshot.values.insert("net.ipv4.ip_default_ttl".into(), "64".into());
        snapshot.values.insert("net.ipv4.tcp_ecn".into(), "2".into());
        let entries = vec![("net.ipv4.ip_default_ttl", "128".into()), ("net.ipv4.tcp_ecn", "0".into())];
        let mut writes = Vec::new();
        let result = apply_sysctl_entries(&snapshot, &entries, true, |key, value| {
            writes.push((key.to_string(), value.to_string()));
            if key == "net.ipv4.tcp_ecn" && value == "0" { return Err(TcpMorphError::Io(std::io::ErrorKind::PermissionDenied.into())); }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(writes.iter().map(|(_, value)| value.as_str()).collect::<Vec<_>>(), ["128", "0", "2", "64"]);
    }

    #[test]
    fn rollback_failure_is_reported() {
        let mut snapshot = NetnsTcpSnapshot::new("test");
        snapshot.values.insert("net.ipv4.ip_default_ttl".into(), "64".into());
        let result = apply_sysctl_entries(&snapshot, &[("net.ipv4.ip_default_ttl", "128".into())], true,
            |_, _| Err(TcpMorphError::Io(std::io::ErrorKind::PermissionDenied.into())));
        assert!(matches!(result, Err(TcpMorphError::RollbackFailed { .. })));
    }

    #[test]
    fn optional_restore_failure_still_rolls_back_core_writes() {
        let mut snapshot = NetnsTcpSnapshot::new("test");
        snapshot.values.insert("net.ipv4.ip_default_ttl".into(), "64".into());
        snapshot.values.insert("net.ipv4.tcp_ecn".into(), "2".into());
        let entries = vec![("net.ipv4.ip_default_ttl", "128".into()), ("net.ipv4.tcp_ecn", "0".into())];
        let mut ttl = String::from("64");
        let result = apply_sysctl_entries(&snapshot, &entries, false, |key, value| {
            if key == "net.ipv4.tcp_ecn" { return Err(TcpMorphError::Io(std::io::ErrorKind::PermissionDenied.into())); }
            ttl = value.to_string();
            Ok(())
        });
        assert!(matches!(result, Err(TcpMorphError::RollbackFailed { .. })));
        assert_eq!(ttl, "64");
    }

    #[test]
    fn optional_missing_backup_is_skipped_and_marks_incomplete() {
        let snapshot = NetnsTcpSnapshot::new("test");
        let complete = apply_sysctl_entries(&snapshot, &[("net.ipv4.tcp_ecn", "0".into())], false,
            |_, _| panic!("Untracked setting must not be written")).unwrap();
        assert!(!complete);
    }

    #[test]
    fn readback_accepts_kernel_spacing_but_rejects_different_values() {
        assert!(verify_sysctl_value("test", "ports", "49152 65535", "49152\t65535").is_ok());
        assert!(verify_sysctl_value("test", "ttl", "128", "64").is_err());
    }

    #[test]
    fn route_selection_rejects_missing_ambiguous_and_multipath_defaults() {
        for route in ["", "default via 10.0.0.1", "default dev eth0\ndefault dev eth1", "default nexthop via 10.0.0.1 dev eth0"] {
            assert!(default_route_identity("test", route).is_err(), "{route}");
        }
        assert_eq!(default_route_identity("test", "default via 10.0.0.1 dev eth0 proto static metric 100").unwrap(),
            ["default", "via", "10.0.0.1", "dev", "eth0", "metric", "100"]);
    }

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
        assert!(matches!(res, Err(TcpMorphError::UnmanagedNamespace(_))));
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
