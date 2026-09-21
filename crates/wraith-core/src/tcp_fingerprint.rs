//! Wraith L4 TCP Stack Fingerprint Profiles & Cross-Layer Correlation Engine
//!
//! This module defines the complete Layer 4 TCP/IP fingerprint specification and provides
//! the intelligence layer that bridges L4 (TCP SYN parameters) with L7 (TLS JA3/JA4)
//! emulation profiles to eliminate the passive OS fingerprinting paradox.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    L7: TLS ClientHello (JA3/JA4)                   │
//! │  Browser Emulation: Chrome 131 / Firefox 133 / Safari 18 / Edge   │
//! │  → cipher_suites, extensions, supported_groups, ALPN, HTTP/2      │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │              CrossLayerProfile (Correlation Engine)                │
//! │  Maps: BrowserType ──→ TcpProfileKind (OS inference)              │
//! │  Validates: L7.implied_os == L4.kind (paradox detection)          │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                    L4: TCP SYN Parameters                         │
//! │  ┌──────────────┐  ┌──────────────────┐  ┌───────────────────┐   │
//! │  │ Tier 1:      │  │ Tier 2:          │  │ Tier 3:           │   │
//! │  │ Sysctl       │  │ Netfilter        │  │ FIB Routing       │   │
//! │  │ TTL, TS,     │  │ iptables mangle  │  │ ip route metrics  │   │
//! │  │ WS, SACK,    │  │ TCPMSS clamp     │  │ initcwnd,         │   │
//! │  │ FIN, SYN-R   │  │ (forced MSS)     │  │ initrwnd          │   │
//! │  └──────────────┘  └──────────────────┘  └───────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Threat Model
//!
//! Passive observers (ISP, nation-state, CDN) correlate:
//! - **L7 signal**: TLS ClientHello → JA3 hash → "Chrome on Windows 11"
//! - **L4 signal**: TCP SYN → TTL=64, TS=1, MSS=1460, WS=7 → "Linux 6.x"
//!
//! This contradiction (L7 says Windows, L4 says Linux) is a high-confidence
//! deanonymisation vector. This module eliminates it by morphing the L4 stack
//! to match the OS implied by the L7 TLS profile.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

// ══════════════════════════════════════════════════════════════════════════════
// 1. OPERATING SYSTEM TAXONOMY
// ══════════════════════════════════════════════════════════════════════════════

/// Operating system targets for L4 TCP/IP stack normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TcpProfileKind {
    Windows11,
    MacOS,
    LinuxDefault,
}

impl fmt::Display for TcpProfileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows11 => write!(f, "windows11"),
            Self::MacOS => write!(f, "macos"),
            Self::LinuxDefault => write!(f, "linux"),
        }
    }
}

impl FromStr for TcpProfileKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "windows" | "windows11" | "win" | "win11" => Ok(Self::Windows11),
            "macos" | "mac" | "darwin" | "apple" | "osx" => Ok(Self::MacOS),
            "linux" | "linuxdefault" | "default" | "canonical" => Ok(Self::LinuxDefault),
            other => Err(format!(
                "Unknown TCP fingerprint profile: '{other}'. Supported: windows11, macos, linux"
            )),
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. p0f SYN WIRE SIGNATURE MODEL
// ══════════════════════════════════════════════════════════════════════════════

/// Represents the expected p0f SYN signature parameters as they appear on the wire.
///
/// p0f identifies operating systems by analyzing the first SYN packet's IP+TCP header fields.
/// This structure models the exact wire-level values that a passive observer would extract.
///
/// ## p0f Signature Format
/// ```text
/// ver:ittl:olen:mss:wsize,wscale:olayout:quirks:pclass
/// ```
///
/// Example Windows 11 signature:
/// ```text
/// *:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct P0fSynSignature {
    /// IP version (4 or 6, * for wildcard).
    pub ip_version: &'static str,
    /// Initial TTL as observed on wire (before hop decrements).
    pub initial_ttl: u8,
    /// IP options length in bytes (almost always 0 for modern stacks).
    pub ip_options_length: u8,
    /// Maximum Segment Size from TCP options.
    pub mss: u16,
    /// TCP window size from the SYN header.
    pub window_size: u32,
    /// Window scale factor from TCP options (None = absent).
    pub window_scale: Option<u8>,
    /// TCP option layout string in p0f format (e.g., "mss,nop,ws,nop,nop,sok").
    pub tcp_options_layout: &'static str,
    /// p0f quirks field (e.g., "df,id+" for Don't Fragment + non-zero IPID).
    pub quirks: &'static str,
    /// Payload class: 0 = no payload in SYN (standard).
    pub payload_class: u8,
}

impl P0fSynSignature {
    /// Windows 11 (NT 10.0) SYN signature as captured by p0f.
    ///
    /// Key characteristics:
    /// - TTL=128 (Windows default, nearest power-of-2 boundary)
    /// - No TCP timestamps (Windows clients omit on SYN)
    /// - MSS=1460 (standard 1500 MTU Ethernet)
    /// - Window=65535 with WScale=8 → effective 16MB receive window
    /// - TCP options: MSS, NOP, WS, NOP, NOP, SACK-OK
    /// - DF flag set, non-zero IP ID
    pub fn windows11() -> Self {
        Self {
            ip_version: "*",
            initial_ttl: 128,
            ip_options_length: 0,
            mss: 1460,
            window_size: 65535,
            window_scale: Some(8),
            tcp_options_layout: "mss,nop,ws,nop,nop,sok",
            quirks: "df,id+",
            payload_class: 0,
        }
    }

    /// macOS Sonoma/Sequoia (Darwin 23.x/24.x) SYN signature.
    ///
    /// Key characteristics:
    /// - TTL=64 (BSD heritage)
    /// - TCP timestamps present (always enabled on macOS)
    /// - MSS=1440 (accounts for TCP timestamp option overhead)
    /// - Window=65535 with WScale=6 → effective 4MB receive window
    /// - TCP options: MSS, NOP, WS, NOP, NOP, TS, SACK-OK, EOL
    /// - DF flag set, zero IP ID (macOS uses DF+id0 pattern)
    pub fn macos() -> Self {
        Self {
            ip_version: "*",
            initial_ttl: 64,
            ip_options_length: 0,
            mss: 1440,
            window_size: 65535,
            window_scale: Some(6),
            tcp_options_layout: "mss,nop,ws,nop,nop,ts,sok,eol",
            quirks: "df,id0",
            payload_class: 0,
        }
    }

    /// Canonical Linux 6.x kernel SYN signature.
    ///
    /// Key characteristics:
    /// - TTL=64 (standard Linux default)
    /// - TCP timestamps present (enabled by default since Linux 2.6)
    /// - MSS=1460 (kernel auto-calculates from interface MTU)
    /// - Window=65535 with WScale=7 → effective 8MB receive window
    /// - TCP options: MSS, SACK-OK, TS, NOP, WS
    /// - DF flag set, non-zero IP ID
    pub fn linux() -> Self {
        Self {
            ip_version: "*",
            initial_ttl: 64,
            ip_options_length: 0,
            mss: 1460,
            window_size: 65535,
            window_scale: Some(7),
            tcp_options_layout: "mss,sok,ts,nop,ws",
            quirks: "df,id+",
            payload_class: 0,
        }
    }

    /// Formats as p0f-compatible signature string.
    ///
    /// Output format: `ver:ittl:olen:mss:wsize,wscale:olayout:quirks:pclass`
    pub fn to_p0f_string(&self) -> String {
        let ws = self
            .window_scale
            .map(|s| format!("{},{s}", self.window_size))
            .unwrap_or_else(|| self.window_size.to_string());

        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            self.ip_version,
            self.initial_ttl,
            self.ip_options_length,
            self.mss,
            ws,
            self.tcp_options_layout,
            self.quirks,
            self.payload_class,
        )
    }
}

impl fmt::Display for P0fSynSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_p0f_string())
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. TCP FINGERPRINT PROFILE (3-Tier Architecture)
// ══════════════════════════════════════════════════════════════════════════════

/// Comprehensive Layer 4 TCP/IP fingerprint specification.
/// Explicitly categorizes mechanisms across sysctl, Netfilter, and Routing tiers.
///
/// ## Tier Architecture
///
/// | Tier | Mechanism | Parameters | Kernel Interface |
/// |------|-----------|------------|------------------|
/// | 1 | sysctl | TTL, TS, WS, SACK, FIN, SYN-R | `/proc/sys/net/ipv4/` |
/// | 2 | Netfilter | MSS clamping | `iptables -t mangle -j TCPMSS` |
/// | 3 | FIB Routing | initcwnd, initrwnd | `ip route change ... initcwnd N initrwnd N` |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpFingerprintProfile {
    /// Human-readable profile label.
    pub name: String,
    /// Target operating system taxonomy.
    pub kind: TcpProfileKind,

    // ─── Tier 1: In-Namespace sysctl (/proc/sys/net/ipv4/) ───────────────────
    /// Default IP Time-To-Live (`net.ipv4.ip_default_ttl`).
    /// Windows=128, Linux/macOS=64. This is the single highest-entropy p0f discriminator.
    pub default_ttl: u8,
    /// RFC 7323 TCP Window Scale option (`net.ipv4.tcp_window_scaling`).
    pub tcp_window_scaling: bool,
    /// RFC 7323 TCP Timestamps option (`net.ipv4.tcp_timestamps`: 0=off, 1=on, 2=randomized).
    /// Windows=0 (absent from SYN), Linux/macOS=1.
    /// **OPSEC**: Timestamps leak kernel uptime via monotonic clock. Windows omission is intentional.
    pub tcp_timestamps: u8,
    /// RFC 2018 Selective Acknowledgments (`net.ipv4.tcp_sack`).
    pub tcp_sack: bool,
    /// TCP FIN connection timeout in seconds (`net.ipv4.tcp_fin_timeout`).
    pub tcp_fin_timeout: u8,
    /// TCP SYN retransmission limit (`net.ipv4.tcp_syn_retries`).
    pub tcp_syn_retries: u8,
    /// Ephemeral local port range (`net.ipv4.ip_local_port_range`).
    /// Windows=49152-65535 (IANA dynamic), Linux=32768-60999.
    pub local_port_range: Option<(u16, u16)>,
    /// Explicit Congestion Notification (`net.ipv4.tcp_ecn`).
    pub tcp_ecn: Option<u8>,
    /// RFC 1337 TIME-WAIT Assassination & RST protection (`net.ipv4.tcp_rfc1337`).
    pub tcp_rfc1337: Option<u8>,

    // ─── Tier 2: Netfilter (iptables mangle) ─────────────────────────────────
    /// Forced SYN Maximum Segment Size via `iptables -t mangle -j TCPMSS --set-mss <mss>`.
    /// **WARNING**: This is NOT a sysctl parameter. `tcp_mss` does not exist as a sysctl.
    /// Must be enforced through Netfilter's TCPMSS target in the mangle table.
    pub forced_syn_mss: Option<u16>,

    // ─── Tier 3: Routing (FIB) Metrics ───────────────────────────────────────
    /// Initial Congestion Window in segments (`ip route ... initcwnd <N>`).
    pub init_cwnd: Option<u8>,
    /// Initial Receive Window in segments (`ip route ... initrwnd <N>`).
    /// This controls the `window_size` field in the SYN header.
    /// Windows11: 44 segments → 44 × 1460 = 64240 bytes ≈ 65535 after WScale
    pub init_rwnd: Option<u8>,
}

impl TcpFingerprintProfile {
    // ──────────────────────────────────────────────────────────────────────────
    // PROFILE CONSTRUCTORS
    // ──────────────────────────────────────────────────────────────────────────

    /// Authentic Windows 11 (23H2/24H2) TCP/IP stack configuration.
    ///
    /// ## p0f Wire Signature
    /// ```text
    /// *:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
    /// ```
    ///
    /// ## Discriminating Features vs Linux
    /// | Parameter | Windows 11 | Linux 6.x | Detection Impact |
    /// |-----------|-----------|-----------|------------------|
    /// | TTL | 128 | 64 | **CRITICAL** - instant OS detection |
    /// | Timestamps | OFF (0) | ON (1) | **HIGH** - uptime leak + option layout change |
    /// | SYN Retries | 2 | 6 | MEDIUM - retransmission timing analysis |
    /// | FIN Timeout | 30s | 60s | LOW - requires connection teardown observation |
    /// | Port Range | 49152-65535 | 32768-60999 | MEDIUM - ephemeral port entropy |
    pub fn windows11() -> Self {
        Self {
            name: "Windows 11 x86_64 (NT 10.0)".to_string(),
            kind: TcpProfileKind::Windows11,
            default_ttl: 128,
            tcp_window_scaling: true,
            tcp_timestamps: 0,
            tcp_sack: true,
            tcp_fin_timeout: 30,
            tcp_syn_retries: 2,
            local_port_range: Some((49152, 65535)),
            tcp_ecn: Some(0),
            tcp_rfc1337: Some(1),
            forced_syn_mss: Some(1460),
            init_cwnd: Some(10),
            init_rwnd: Some(44),
        }
    }

    /// Authentic macOS Sonoma / Sequoia (Darwin 23.x / 24.x) TCP/IP stack configuration.
    ///
    /// ## p0f Wire Signature
    /// ```text
    /// *:64:0:1440:65535,6:mss,nop,ws,nop,nop,ts,sok,eol:df,id0:0
    /// ```
    ///
    /// ## Discriminating Features vs Linux
    /// | Parameter | macOS | Linux 6.x | Detection Impact |
    /// |-----------|-------|-----------|------------------|
    /// | MSS | 1440 | 1460 | HIGH - timestamp option overhead accounting |
    /// | WScale | 6 | 7 | MEDIUM - receive window sizing difference |
    /// | IP ID | 0 (DF) | non-zero | HIGH - macOS uses DF+id0 pattern |
    /// | TCP Options | mss,nop,ws,nop,nop,ts,sok,eol | mss,sok,ts,nop,ws | **CRITICAL** - option ordering |
    pub fn macos() -> Self {
        Self {
            name: "macOS Sonoma/Sequoia (Darwin ARM64/x86_64)".to_string(),
            kind: TcpProfileKind::MacOS,
            default_ttl: 64,
            tcp_window_scaling: true,
            tcp_timestamps: 1,
            tcp_sack: true,
            tcp_fin_timeout: 30,
            tcp_syn_retries: 3,
            local_port_range: Some((49152, 65535)),
            tcp_ecn: Some(0),
            tcp_rfc1337: Some(0),
            forced_syn_mss: Some(1440),
            init_cwnd: Some(10),
            init_rwnd: Some(45),
        }
    }

    /// Canonical Linux Kernel (6.x) default stack configuration.
    ///
    /// ## p0f Wire Signature
    /// ```text
    /// *:64:0:1460:65535,7:mss,sok,ts,nop,ws:df,id+:0
    /// ```
    ///
    /// This is the "native" signature that a bare Linux host would emit.
    /// When masking as Windows 11 or macOS, this is what we're hiding FROM.
    pub fn linux_default() -> Self {
        Self {
            name: "Canonical Linux Kernel 6.x Default".to_string(),
            kind: TcpProfileKind::LinuxDefault,
            default_ttl: 64,
            tcp_window_scaling: true,
            tcp_timestamps: 1,
            tcp_sack: true,
            tcp_fin_timeout: 60,
            tcp_syn_retries: 6,
            local_port_range: Some((32768, 60999)),
            tcp_ecn: Some(2),
            tcp_rfc1337: Some(0),
            forced_syn_mss: None,
            init_cwnd: None,
            init_rwnd: None,
        }
    }

    /// Construct profile from `TcpProfileKind`.
    pub fn from_kind(kind: TcpProfileKind) -> Self {
        match kind {
            TcpProfileKind::Windows11 => Self::windows11(),
            TcpProfileKind::MacOS => Self::macos(),
            TcpProfileKind::LinuxDefault => Self::linux_default(),
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // L7 → L4 CROSS-LAYER MAPPING
    // ──────────────────────────────────────────────────────────────────────────

    /// Dynamically maps an L7 TLS emulation profile (browser name / User-Agent tag)
    /// to its matching L4 TCP profile, resolving the L7↔L4 fingerprint paradox.
    ///
    /// ## Mapping Table
    ///
    /// | L7 TLS Profile | Implied OS | L4 TCP Profile |
    /// |----------------|------------|----------------|
    /// | Chrome / Edge / Brave | Windows 11 | TTL=128, TS=0, MSS=1460 |
    /// | Safari | macOS | TTL=64, TS=1, MSS=1440 |
    /// | Firefox (Linux UA) | Linux | TTL=64, TS=1, MSS=auto |
    ///
    /// ## Why Chrome → Windows?
    /// Chrome on Windows is the dominant browser/OS combination globally (~65% market share).
    /// An observer seeing a Chrome JA3 hash statistically expects Windows TCP parameters.
    /// If they see Chrome JA3 + Linux TTL=64, the probability of "privacy tool" increases
    /// by approximately 40× compared to seeing Chrome JA3 + Windows TTL=128.
    pub fn from_tls_profile(tls_profile: &str) -> Self {
        let p = tls_profile.to_ascii_lowercase();
        if p.contains("chrome") || p.contains("win") || p.contains("edge") || p.contains("brave") {
            Self::windows11()
        } else if p.contains("safari") || p.contains("mac") || p.contains("darwin") || p.contains("apple") {
            Self::macos()
        } else {
            Self::linux_default()
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // p0f SIGNATURE GENERATION
    // ──────────────────────────────────────────────────────────────────────────

    /// Returns the expected p0f SYN signature for this profile.
    pub fn expected_p0f_signature(&self) -> P0fSynSignature {
        match self.kind {
            TcpProfileKind::Windows11 => P0fSynSignature::windows11(),
            TcpProfileKind::MacOS => P0fSynSignature::macos(),
            TcpProfileKind::LinuxDefault => P0fSynSignature::linux(),
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // TIER 1: SYSCTL PARAMETER GENERATION
    // ──────────────────────────────────────────────────────────────────────────

    /// Alias for backwards compatibility with earlier draft.
    pub fn syn_mss(&self) -> Option<u16> {
        self.forced_syn_mss
    }

    /// Core sysctl parameters strictly present in `struct netns_ipv4` across modern kernels.
    /// These are atomically enforced — failure on any core parameter triggers full rollback.
    pub fn core_sysctl_entries(&self) -> Vec<(&'static str, String)> {
        vec![
            ("net.ipv4.ip_default_ttl", self.default_ttl.to_string()),
            (
                "net.ipv4.tcp_window_scaling",
                if self.tcp_window_scaling { "1" } else { "0" }.to_string(),
            ),
            ("net.ipv4.tcp_timestamps", self.tcp_timestamps.to_string()),
            (
                "net.ipv4.tcp_sack",
                if self.tcp_sack { "1" } else { "0" }.to_string(),
            ),
            ("net.ipv4.tcp_fin_timeout", self.tcp_fin_timeout.to_string()),
            ("net.ipv4.tcp_syn_retries", self.tcp_syn_retries.to_string()),
        ]
    }

    /// Extended sysctl parameters for deep p0f normalisation (may be optional on older kernels).
    /// These employ graceful fallback on kernel variance.
    pub fn extended_sysctl_entries(&self) -> Vec<(&'static str, String)> {
        let mut entries = Vec::new();
        if let Some((start, end)) = self.local_port_range {
            entries.push(("net.ipv4.ip_local_port_range", format!("{start} {end}")));
        }
        if let Some(ecn) = self.tcp_ecn {
            entries.push(("net.ipv4.tcp_ecn", ecn.to_string()));
        }
        if let Some(rfc1337) = self.tcp_rfc1337 {
            entries.push(("net.ipv4.tcp_rfc1337", rfc1337.to_string()));
        }
        entries
    }

    /// All sysctl entries (core followed by extended).
    pub fn sysctl_entries(&self) -> Vec<(&'static str, String)> {
        let mut entries = self.core_sysctl_entries();
        entries.extend(self.extended_sysctl_entries());
        entries
    }

    // ──────────────────────────────────────────────────────────────────────────
    // TIER 2: NETFILTER (iptables) RULE GENERATION
    // ──────────────────────────────────────────────────────────────────────────

    /// Generates the iptables mangle TCPMSS clamping rule for this profile.
    ///
    /// The MSS value is NOT a sysctl parameter. It must be enforced through the Netfilter
    /// TCPMSS target which intercepts outgoing SYN packets and rewrites the MSS TCP option.
    ///
    /// ## Command
    /// ```bash
    /// iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
    ///   -o <iface> -j TCPMSS --set-mss <mss>
    /// ```
    ///
    /// Returns `None` if no MSS override is needed (Linux default auto-calculates from MTU).
    pub fn netfilter_mss_rule(&self, interface: &str) -> Option<Vec<String>> {
        self.forced_syn_mss.map(|mss| {
            vec![
                "-t".into(), "mangle".into(),
                "-A".into(), "POSTROUTING".into(),
                "-p".into(), "tcp".into(),
                "--tcp-flags".into(), "SYN,RST".into(), "SYN".into(),
                "-o".into(), interface.into(),
                "-j".into(), "TCPMSS".into(),
                "--set-mss".into(), mss.to_string(),
            ]
        })
    }

    /// Generates the deletion counterpart of the Netfilter MSS rule for rollback.
    pub fn netfilter_mss_delete_rule(&self, interface: &str) -> Option<Vec<String>> {
        self.forced_syn_mss.map(|mss| {
            vec![
                "-t".into(), "mangle".into(),
                "-D".into(), "POSTROUTING".into(),
                "-p".into(), "tcp".into(),
                "--tcp-flags".into(), "SYN,RST".into(), "SYN".into(),
                "-o".into(), interface.into(),
                "-j".into(), "TCPMSS".into(),
                "--set-mss".into(), mss.to_string(),
            ]
        })
    }

    // ──────────────────────────────────────────────────────────────────────────
    // TIER 3: FIB ROUTING METRIC GENERATION
    // ──────────────────────────────────────────────────────────────────────────

    /// Generates `ip route change` arguments for setting initcwnd and initrwnd.
    ///
    /// These routing metrics control the TCP initial window sizes at the FIB level,
    /// which directly affects the `window_size` field in SYN packets.
    ///
    /// ## Why routing metrics instead of sysctl?
    /// `window_size` and `initrwnd` are NOT sysctl parameters. They are per-route
    /// FIB metrics set via `ip route change <route> initcwnd <N> initrwnd <N>`.
    ///
    /// Returns args to append to `ip route change default` inside the namespace.
    pub fn fib_route_metrics(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(cwnd) = self.init_cwnd {
            args.extend_from_slice(&["initcwnd".into(), cwnd.to_string()]);
        }
        if let Some(rwnd) = self.init_rwnd {
            args.extend_from_slice(&["initrwnd".into(), rwnd.to_string()]);
        }
        args
    }

    /// Returns true if this profile requires FIB route metric manipulation.
    pub fn requires_route_metrics(&self) -> bool {
        self.init_cwnd.is_some() || self.init_rwnd.is_some()
    }

    /// Returns true if this profile requires Netfilter MSS clamping.
    pub fn requires_netfilter_mss(&self) -> bool {
        self.forced_syn_mss.is_some()
    }

    // ──────────────────────────────────────────────────────────────────────────
    // DIAGNOSTICS & FORMATTING
    // ──────────────────────────────────────────────────────────────────────────

    /// Technical operational summary of the profile.
    pub fn format_summary(&self) -> String {
        let mss_str = self
            .forced_syn_mss
            .map(|m| m.to_string())
            .unwrap_or_else(|| "auto".to_string());
        let rwnd_str = self
            .init_rwnd
            .map(|r| r.to_string())
            .unwrap_or_else(|| "auto".to_string());

        format!(
            "TTL={} │ TS={} │ WS={} │ SACK={} │ MSS={} │ RWND={}",
            self.default_ttl,
            self.tcp_timestamps,
            if self.tcp_window_scaling { "1" } else { "0" },
            if self.tcp_sack { "1" } else { "0" },
            mss_str,
            rwnd_str
        )
    }

    /// Returns a detailed multi-line diagnostic report of all three tiers.
    pub fn format_diagnostic(&self) -> String {
        let p0f = self.expected_p0f_signature();
        let mut lines = Vec::new();

        lines.push(format!("╔══ L4 TCP Profile: {} ══╗", self.name));
        lines.push(format!("║ OS Target: {}", self.kind));
        lines.push(format!("║ p0f Signature: {}", p0f));
        lines.push("║".to_string());
        lines.push("║ ── Tier 1: Sysctl ──".to_string());
        for (key, val) in self.sysctl_entries() {
            lines.push(format!("║   {key} = {val}"));
        }
        lines.push("║".to_string());
        lines.push("║ ── Tier 2: Netfilter ──".to_string());
        if let Some(mss) = self.forced_syn_mss {
            lines.push(format!("║   TCPMSS --set-mss {mss}"));
        } else {
            lines.push("║   (kernel auto-MSS from MTU)".to_string());
        }
        lines.push("║".to_string());
        lines.push("║ ── Tier 3: FIB Routing ──".to_string());
        if let Some(cwnd) = self.init_cwnd {
            lines.push(format!("║   initcwnd = {cwnd} segments"));
        }
        if let Some(rwnd) = self.init_rwnd {
            lines.push(format!("║   initrwnd = {rwnd} segments"));
        }
        if !self.requires_route_metrics() {
            lines.push("║   (kernel default routing metrics)".to_string());
        }
        lines.push("╚══════════════════════════════════════╝".to_string());

        lines.join("\n")
    }
}

impl Default for TcpFingerprintProfile {
    fn default() -> Self {
        Self::windows11()
    }
}

impl From<TcpProfileKind> for TcpFingerprintProfile {
    fn from(kind: TcpProfileKind) -> Self {
        Self::from_kind(kind)
    }
}

impl FromStr for TcpFingerprintProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kind = TcpProfileKind::from_str(s)?;
        Ok(Self::from_kind(kind))
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. CROSS-LAYER CORRELATION ENGINE (L4 ↔ L7)
// ══════════════════════════════════════════════════════════════════════════════

/// L7 browser type identifiers mirroring `BrowserType` in `wraith-tor::grease`.
/// Duplicated here to avoid circular dependency between `wraith-core` and `wraith-tor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum L7BrowserHint {
    ChromeWindows,
    EdgeWindows,
    FirefoxLinux,
    SafariMacOS,
}

impl L7BrowserHint {
    /// Infers the expected L4 operating system from the L7 browser identity.
    ///
    /// This is the critical cross-layer mapping that resolves the paradox.
    pub fn implied_os(&self) -> TcpProfileKind {
        match self {
            Self::ChromeWindows | Self::EdgeWindows => TcpProfileKind::Windows11,
            Self::FirefoxLinux => TcpProfileKind::LinuxDefault,
            Self::SafariMacOS => TcpProfileKind::MacOS,
        }
    }

    /// Returns the expected TLS JA4 protocol prefix for this browser.
    /// JA4 format: `t{tls_version}d{num_ciphers}{num_extensions}h{alpn_first_letter}_{hash1}_{hash2}`
    pub fn expected_ja4_prefix(&self) -> &'static str {
        match self {
            Self::ChromeWindows | Self::EdgeWindows => "t13d",
            Self::FirefoxLinux => "t13d",
            Self::SafariMacOS => "t13d",
        }
    }

    /// Derives L7BrowserHint from a TLS profile description string or user-agent tag
    pub fn from_tls_name(name: &str) -> Self {
        let n = name.to_ascii_lowercase();
        if n.contains("edge") {
            Self::EdgeWindows
        } else if n.contains("safari") || n.contains("darwin") || n.contains("apple") || (n.contains("mac") && !n.contains("machine")) {
            Self::SafariMacOS
        } else if n.contains("firefox") || n.contains("linux") {
            Self::FirefoxLinux
        } else {
            Self::ChromeWindows
        }
    }
}

impl fmt::Display for L7BrowserHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChromeWindows => write!(f, "Chrome/Windows"),
            Self::EdgeWindows => write!(f, "Edge/Windows"),
            Self::FirefoxLinux => write!(f, "Firefox/Linux"),
            Self::SafariMacOS => write!(f, "Safari/macOS"),
        }
    }
}

/// Cross-layer profile binding: ties an L7 TLS fingerprint to its L4 TCP counterpart.
///
/// ## Purpose
/// When Wraith selects an L7 TLS profile (e.g., "Chrome 131 on Windows 11"), the
/// `CrossLayerProfile` automatically resolves the correct L4 TCP parameters and
/// validates that both layers are consistent.
///
/// ## Anomaly Detection
/// The `validate()` method detects paradoxes like:
/// - L7 = Chrome/Windows → L4 expects TTL=128, but L4 profile has TTL=64 → **PARADOX**
/// - L7 = Safari/macOS → L4 expects TS=1, but L4 profile has TS=0 → **PARADOX**
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossLayerProfile {
    /// The L7 browser identity driving this session.
    pub l7_browser: L7BrowserHint,
    /// The resolved L4 TCP fingerprint profile.
    pub l4_profile: TcpFingerprintProfile,
    /// The expected p0f signature string for external verification.
    pub expected_p0f: String,
}

/// Severity of cross-layer anomalies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalySeverity {
    /// Instant deanonymisation risk (e.g., TTL mismatch).
    Critical,
    /// High correlation risk but not instant detection (e.g., MSS mismatch).
    High,
    /// Observable but statistically ambiguous (e.g., port range mismatch).
    Medium,
    /// Informational only.
    Low,
}

/// A detected cross-layer anomaly between L4 and L7 fingerprints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossLayerAnomaly {
    /// Which parameter is mismatched.
    pub parameter: String,
    /// Expected value based on L7 browser identity.
    pub expected: String,
    /// Actual value in the L4 profile.
    pub actual: String,
    /// Severity of the anomaly.
    pub severity: AnomalySeverity,
    /// Human-readable explanation of the detection risk.
    pub risk_description: String,
}

impl fmt::Display for CrossLayerAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:?}] {}: expected={}, actual={} — {}",
            self.severity, self.parameter, self.expected, self.actual, self.risk_description
        )
    }
}

impl CrossLayerProfile {
    /// Constructs a cross-layer profile from an L7 browser hint.
    /// Automatically resolves the matching L4 TCP fingerprint.
    pub fn from_browser(browser: L7BrowserHint) -> Self {
        let l4_profile = TcpFingerprintProfile::from_kind(browser.implied_os());
        let expected_p0f = l4_profile.expected_p0f_signature().to_p0f_string();
        Self {
            l7_browser: browser,
            l4_profile,
            expected_p0f,
        }
    }

    /// Validates that the L4 profile is consistent with the L7 browser identity.
    /// Returns a list of detected anomalies. Empty list = no paradox.
    pub fn validate(&self) -> Vec<CrossLayerAnomaly> {
        let mut anomalies = Vec::new();
        let expected_os = self.l7_browser.implied_os();
        let expected_profile = TcpFingerprintProfile::from_kind(expected_os);

        // TTL check — the single most critical discriminator
        if self.l4_profile.default_ttl != expected_profile.default_ttl {
            anomalies.push(CrossLayerAnomaly {
                parameter: "default_ttl".into(),
                expected: expected_profile.default_ttl.to_string(),
                actual: self.l4_profile.default_ttl.to_string(),
                severity: AnomalySeverity::Critical,
                risk_description: format!(
                    "TTL mismatch: L7 implies {} (TTL={}) but L4 has TTL={}. \
                     p0f/Nmap will classify this as a different OS family, \
                     creating an instant deanonymisation signal.",
                    expected_os, expected_profile.default_ttl, self.l4_profile.default_ttl
                ),
            });
        }

        // TCP Timestamps — second highest discriminator
        if self.l4_profile.tcp_timestamps != expected_profile.tcp_timestamps {
            anomalies.push(CrossLayerAnomaly {
                parameter: "tcp_timestamps".into(),
                expected: expected_profile.tcp_timestamps.to_string(),
                actual: self.l4_profile.tcp_timestamps.to_string(),
                severity: AnomalySeverity::Critical,
                risk_description: format!(
                    "TCP timestamp presence mismatch: {} {} timestamps in SYN, \
                     but L4 has timestamps={}. This changes the TCP options layout \
                     visible in p0f, which is a high-entropy OS discriminator.",
                    expected_os,
                    if expected_profile.tcp_timestamps > 0 { "includes" } else { "omits" },
                    self.l4_profile.tcp_timestamps
                ),
            });
        }

        // MSS check
        if self.l4_profile.forced_syn_mss != expected_profile.forced_syn_mss {
            anomalies.push(CrossLayerAnomaly {
                parameter: "forced_syn_mss".into(),
                expected: expected_profile.forced_syn_mss
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "auto".into()),
                actual: self.l4_profile.forced_syn_mss
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "auto".into()),
                severity: AnomalySeverity::High,
                risk_description: "MSS value divergence changes the p0f signature \
                    and may indicate OS-level MTU handling differences."
                    .into(),
            });
        }

        // SYN retries
        if self.l4_profile.tcp_syn_retries != expected_profile.tcp_syn_retries {
            anomalies.push(CrossLayerAnomaly {
                parameter: "tcp_syn_retries".into(),
                expected: expected_profile.tcp_syn_retries.to_string(),
                actual: self.l4_profile.tcp_syn_retries.to_string(),
                severity: AnomalySeverity::Medium,
                risk_description: "SYN retransmission count affects timing-based OS fingerprinting \
                    when observers measure inter-retransmit intervals."
                    .into(),
            });
        }

        // Ephemeral port range
        if self.l4_profile.local_port_range != expected_profile.local_port_range {
            anomalies.push(CrossLayerAnomaly {
                parameter: "local_port_range".into(),
                expected: expected_profile.local_port_range
                    .map(|(s, e)| format!("{s}-{e}"))
                    .unwrap_or_else(|| "default".into()),
                actual: self.l4_profile.local_port_range
                    .map(|(s, e)| format!("{s}-{e}"))
                    .unwrap_or_else(|| "default".into()),
                severity: AnomalySeverity::Medium,
                risk_description: "Ephemeral port range leaks OS identity: Windows uses \
                    49152-65535 (IANA dynamic), Linux uses 32768-60999."
                    .into(),
            });
        }

        anomalies
    }

    /// Returns true if the cross-layer binding has no paradoxes.
    pub fn is_consistent(&self) -> bool {
        self.validate().is_empty()
    }

    /// Returns a formatted cross-layer status report.
    pub fn status_report(&self) -> String {
        let anomalies = self.validate();
        let mut lines = Vec::new();

        lines.push("═══ Cross-Layer Coherence Report ═══".to_string());
        lines.push(format!("L7 Browser: {}", self.l7_browser));
        lines.push(format!("L7 Implied OS: {}", self.l7_browser.implied_os()));
        lines.push(format!("L4 Profile: {} ({})", self.l4_profile.name, self.l4_profile.kind));
        lines.push(format!("Expected p0f: {}", self.expected_p0f));
        lines.push(format!("L4 Summary: {}", self.l4_profile.format_summary()));

        if anomalies.is_empty() {
            lines.push("Status: ✓ COHERENT — No L4↔L7 paradox detected".to_string());
        } else {
            lines.push(format!("Status: ✗ PARADOX — {} anomalies detected:", anomalies.len()));
            for anomaly in &anomalies {
                lines.push(format!("  ⚠ {anomaly}"));
            }
        }

        lines.join("\n")
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. TESTS
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Profile Invariant Tests ──────────────────────────────────────────────

    #[test]
    fn test_windows11_profile_invariants() {
        let win = TcpFingerprintProfile::windows11();
        assert_eq!(win.kind, TcpProfileKind::Windows11);
        assert_eq!(win.default_ttl, 128);
        assert!(win.tcp_window_scaling);
        assert_eq!(win.tcp_timestamps, 0);
        assert!(win.tcp_sack);
        assert_eq!(win.tcp_fin_timeout, 30);
        assert_eq!(win.tcp_syn_retries, 2);
        assert_eq!(win.forced_syn_mss, Some(1460));
        assert_eq!(win.init_cwnd, Some(10));
        assert_eq!(win.init_rwnd, Some(44));

        let entries = win.sysctl_entries();
        assert!(entries.iter().any(|(k, v)| *k == "net.ipv4.ip_default_ttl" && v == "128"));
        assert!(entries.iter().any(|(k, v)| *k == "net.ipv4.tcp_timestamps" && v == "0"));
        assert!(entries.iter().any(|(k, v)| *k == "net.ipv4.tcp_window_scaling" && v == "1"));
        assert!(entries.iter().any(|(k, v)| *k == "net.ipv4.tcp_sack" && v == "1"));
        assert!(entries.iter().any(|(k, v)| *k == "net.ipv4.tcp_fin_timeout" && v == "30"));
        assert!(entries.iter().any(|(k, v)| *k == "net.ipv4.tcp_syn_retries" && v == "2"));
    }

    #[test]
    fn test_macos_profile_invariants() {
        let mac = TcpFingerprintProfile::macos();
        assert_eq!(mac.kind, TcpProfileKind::MacOS);
        assert_eq!(mac.default_ttl, 64);
        assert!(mac.tcp_window_scaling);
        assert_eq!(mac.tcp_timestamps, 1);
        assert!(mac.tcp_sack);
        assert_eq!(mac.tcp_fin_timeout, 30);
        assert_eq!(mac.tcp_syn_retries, 3);
        assert_eq!(mac.forced_syn_mss, Some(1440));
        assert_eq!(mac.init_rwnd, Some(45));

        let entries = mac.sysctl_entries();
        assert!(entries.iter().any(|(k, v)| *k == "net.ipv4.ip_default_ttl" && v == "64"));
        assert!(entries.iter().any(|(k, v)| *k == "net.ipv4.tcp_timestamps" && v == "1"));
    }

    #[test]
    fn test_linux_default_profile_invariants() {
        let linux = TcpFingerprintProfile::linux_default();
        assert_eq!(linux.kind, TcpProfileKind::LinuxDefault);
        assert_eq!(linux.default_ttl, 64);
        assert!(linux.tcp_window_scaling);
        assert_eq!(linux.tcp_timestamps, 1);
        assert!(linux.tcp_sack);
        assert_eq!(linux.tcp_fin_timeout, 60);
        assert_eq!(linux.tcp_syn_retries, 6);
        assert_eq!(linux.forced_syn_mss, None);
        assert_eq!(linux.init_rwnd, None);
    }

    // ── L7 → L4 Mapping Tests ───────────────────────────────────────────────

    #[test]
    fn test_from_tls_profile_mapping() {
        assert_eq!(
            TcpFingerprintProfile::from_tls_profile("Google Chrome 131 / Win11").kind,
            TcpProfileKind::Windows11
        );
        assert_eq!(
            TcpFingerprintProfile::from_tls_profile("ChromeWin11").kind,
            TcpProfileKind::Windows11
        );
        assert_eq!(
            TcpFingerprintProfile::from_tls_profile("Microsoft Edge Windows").kind,
            TcpProfileKind::Windows11
        );
        assert_eq!(
            TcpFingerprintProfile::from_tls_profile("Brave Browser Windows").kind,
            TcpProfileKind::Windows11
        );
        assert_eq!(
            TcpFingerprintProfile::from_tls_profile("Safari macOS Sonoma").kind,
            TcpProfileKind::MacOS
        );
        assert_eq!(
            TcpFingerprintProfile::from_tls_profile("SafariMacOS").kind,
            TcpProfileKind::MacOS
        );
        assert_eq!(
            TcpFingerprintProfile::from_tls_profile("Firefox Linux").kind,
            TcpProfileKind::LinuxDefault
        );
    }

    // ── String Parsing Tests ────────────────────────────────────────────────

    #[test]
    fn test_string_parsing() {
        assert_eq!(
            TcpProfileKind::from_str("win11").unwrap(),
            TcpProfileKind::Windows11
        );
        assert_eq!(
            TcpProfileKind::from_str("macos").unwrap(),
            TcpProfileKind::MacOS
        );
        assert_eq!(
            TcpProfileKind::from_str("linux").unwrap(),
            TcpProfileKind::LinuxDefault
        );
        assert!(TcpProfileKind::from_str("unknown_os").is_err());
    }

    #[test]
    fn test_format_summary() {
        let win = TcpFingerprintProfile::windows11();
        let summary = win.format_summary();
        assert!(summary.contains("TTL=128"));
        assert!(summary.contains("TS=0"));
        assert!(summary.contains("MSS=1460"));
        assert!(summary.contains("RWND=44"));
    }

    // ── p0f Signature Tests ─────────────────────────────────────────────────

    #[test]
    fn test_p0f_signature_format() {
        let win_sig = P0fSynSignature::windows11();
        let sig_str = win_sig.to_p0f_string();
        assert!(sig_str.contains(":128:"));
        assert!(sig_str.contains(":1460:"));
        assert!(sig_str.contains("mss,nop,ws,nop,nop,sok"));
        assert!(sig_str.contains("df,id+"));

        let mac_sig = P0fSynSignature::macos();
        let mac_str = mac_sig.to_p0f_string();
        assert!(mac_str.contains(":64:"));
        assert!(mac_str.contains(":1440:"));
        assert!(mac_str.contains("df,id0"));

        let linux_sig = P0fSynSignature::linux();
        let linux_str = linux_sig.to_p0f_string();
        assert!(linux_str.contains(":64:"));
        assert!(linux_str.contains("mss,sok,ts,nop,ws"));
    }

    #[test]
    fn test_expected_p0f_matches_kind() {
        let win = TcpFingerprintProfile::windows11();
        let sig = win.expected_p0f_signature();
        assert_eq!(sig.initial_ttl, 128);
        assert_eq!(sig.mss, 1460);

        let mac = TcpFingerprintProfile::macos();
        let sig = mac.expected_p0f_signature();
        assert_eq!(sig.initial_ttl, 64);
        assert_eq!(sig.mss, 1440);
    }

    // ── Netfilter Rule Generation Tests ─────────────────────────────────────

    #[test]
    fn test_netfilter_mss_rule_generation() {
        let win = TcpFingerprintProfile::windows11();
        let rule = win.netfilter_mss_rule("veth-wr-ns").unwrap();
        assert!(rule.contains(&"mangle".to_string()));
        assert!(rule.contains(&"TCPMSS".to_string()));
        assert!(rule.contains(&"1460".to_string()));
        assert!(rule.contains(&"veth-wr-ns".to_string()));

        let linux = TcpFingerprintProfile::linux_default();
        assert!(linux.netfilter_mss_rule("veth-wr-ns").is_none());
    }

    #[test]
    fn test_netfilter_delete_rule_mirrors_add() {
        let win = TcpFingerprintProfile::windows11();
        let add_rule = win.netfilter_mss_rule("eth0").unwrap();
        let del_rule = win.netfilter_mss_delete_rule("eth0").unwrap();

        // Delete rule should be identical except -A → -D
        assert!(add_rule.contains(&"-A".to_string()));
        assert!(del_rule.contains(&"-D".to_string()));
        assert!(!del_rule.contains(&"-A".to_string()));
    }

    // ── FIB Routing Metric Tests ────────────────────────────────────────────

    #[test]
    fn test_fib_route_metrics() {
        let win = TcpFingerprintProfile::windows11();
        let metrics = win.fib_route_metrics();
        assert!(metrics.contains(&"initcwnd".to_string()));
        assert!(metrics.contains(&"10".to_string()));
        assert!(metrics.contains(&"initrwnd".to_string()));
        assert!(metrics.contains(&"44".to_string()));
        assert!(win.requires_route_metrics());

        let linux = TcpFingerprintProfile::linux_default();
        assert!(linux.fib_route_metrics().is_empty());
        assert!(!linux.requires_route_metrics());
    }

    // ── Cross-Layer Correlation Tests ───────────────────────────────────────

    #[test]
    fn test_cross_layer_coherent_profiles() {
        // Chrome/Windows → Windows11 L4 should be fully coherent
        let cl = CrossLayerProfile::from_browser(L7BrowserHint::ChromeWindows);
        assert_eq!(cl.l4_profile.kind, TcpProfileKind::Windows11);
        assert!(cl.is_consistent());
        assert!(cl.validate().is_empty());

        // Safari/macOS → macOS L4 should be fully coherent
        let cl = CrossLayerProfile::from_browser(L7BrowserHint::SafariMacOS);
        assert_eq!(cl.l4_profile.kind, TcpProfileKind::MacOS);
        assert!(cl.is_consistent());

        // Firefox/Linux → Linux L4 should be fully coherent
        let cl = CrossLayerProfile::from_browser(L7BrowserHint::FirefoxLinux);
        assert_eq!(cl.l4_profile.kind, TcpProfileKind::LinuxDefault);
        assert!(cl.is_consistent());
    }

    #[test]
    fn test_cross_layer_detects_paradox() {
        // Manually create a paradoxical binding: Chrome/Windows L7 + Linux L4
        let paradox = CrossLayerProfile {
            l7_browser: L7BrowserHint::ChromeWindows,
            l4_profile: TcpFingerprintProfile::linux_default(),
            expected_p0f: P0fSynSignature::linux().to_p0f_string(),
        };

        let anomalies = paradox.validate();
        assert!(!anomalies.is_empty());

        // Must detect TTL mismatch as Critical
        let ttl_anomaly = anomalies.iter().find(|a| a.parameter == "default_ttl");
        assert!(ttl_anomaly.is_some());
        assert_eq!(ttl_anomaly.unwrap().severity, AnomalySeverity::Critical);

        // Must detect timestamp mismatch as Critical
        let ts_anomaly = anomalies.iter().find(|a| a.parameter == "tcp_timestamps");
        assert!(ts_anomaly.is_some());
        assert_eq!(ts_anomaly.unwrap().severity, AnomalySeverity::Critical);
    }

    #[test]
    fn test_cross_layer_detects_mss_mismatch() {
        // Safari/macOS L7 but with Windows L4 (MSS difference: 1460 vs 1440)
        let paradox = CrossLayerProfile {
            l7_browser: L7BrowserHint::SafariMacOS,
            l4_profile: TcpFingerprintProfile::windows11(),
            expected_p0f: P0fSynSignature::windows11().to_p0f_string(),
        };

        let anomalies = paradox.validate();
        let mss_anomaly = anomalies.iter().find(|a| a.parameter == "forced_syn_mss");
        assert!(mss_anomaly.is_some());
        assert_eq!(mss_anomaly.unwrap().severity, AnomalySeverity::High);
    }

    #[test]
    fn test_l7_browser_implied_os_mapping() {
        assert_eq!(L7BrowserHint::ChromeWindows.implied_os(), TcpProfileKind::Windows11);
        assert_eq!(L7BrowserHint::EdgeWindows.implied_os(), TcpProfileKind::Windows11);
        assert_eq!(L7BrowserHint::FirefoxLinux.implied_os(), TcpProfileKind::LinuxDefault);
        assert_eq!(L7BrowserHint::SafariMacOS.implied_os(), TcpProfileKind::MacOS);
    }

    #[test]
    fn test_status_report_contains_key_fields() {
        let cl = CrossLayerProfile::from_browser(L7BrowserHint::ChromeWindows);
        let report = cl.status_report();
        assert!(report.contains("Chrome/Windows"));
        assert!(report.contains("COHERENT"));
        assert!(report.contains("TTL=128"));
    }

    #[test]
    fn test_diagnostic_report_format() {
        let win = TcpFingerprintProfile::windows11();
        let diag = win.format_diagnostic();
        assert!(diag.contains("Tier 1: Sysctl"));
        assert!(diag.contains("Tier 2: Netfilter"));
        assert!(diag.contains("Tier 3: FIB Routing"));
        assert!(diag.contains("TCPMSS --set-mss 1460"));
        assert!(diag.contains("initrwnd = 44"));
    }

    #[test]
    fn test_from_tls_name_inference() {
        assert_eq!(L7BrowserHint::from_tls_name("Google Chrome v131 (Windows 11 x86_64)"), L7BrowserHint::ChromeWindows);
        assert_eq!(L7BrowserHint::from_tls_name("Microsoft Edge v131 (Windows 11 x86_64)"), L7BrowserHint::EdgeWindows);
        assert_eq!(L7BrowserHint::from_tls_name("Apple Safari v18.0 (macOS Sonoma ARM64)"), L7BrowserHint::SafariMacOS);
        assert_eq!(L7BrowserHint::from_tls_name("Mozilla Firefox v132 (Linux x86_64)"), L7BrowserHint::FirefoxLinux);
        assert_eq!(L7BrowserHint::from_tls_name("unknown-profile"), L7BrowserHint::ChromeWindows);
    }
}
