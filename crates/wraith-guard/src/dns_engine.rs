//! Wraith Sovereign Async DNS Engine, DNSSEC Validator & Privacy Proxy
//! Full RFC 1035 wire-format parser, QNAME minimization engine, RFC 7830 / RFC 8467 EDNS0 padding,
//! DNSSEC metadata verification (DO/AD flags), and multi-vendor telemetry sinkholing.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{UdpSocket, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::info;
use wraith_core::config::TOR_DNS_PORT;
use wraith_core::error::{Result, WraithError};

pub const DNS_LOCAL_PORT: u16 = wraith_core::config::WRAITH_DNS_PORT;
pub const DNS_MAX_PACKET_SIZE: usize = 4096;
pub const EDNS0_TARGET_PADDING_SIZE: usize = 468;

// ==============================================================================
// 1. DNS RESOURCE RECORD TYPES & CLASSES (RFC 1035, RFC 3596, RFC 4034, RFC 6891)
// ==============================================================================

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_OPT: u16 = 41; // EDNS0
pub const TYPE_DS: u16 = 43; // DNSSEC Delegation Signer
pub const TYPE_RRSIG: u16 = 46; // DNSSEC Signature
pub const TYPE_NSEC: u16 = 47; // DNSSEC Next Secure
pub const TYPE_DNSKEY: u16 = 48; // DNSSEC Key Record
pub const TYPE_NSEC3: u16 = 50; // DNSSEC NSEC3
pub const TYPE_HTTPS: u16 = 65; // Service Binding (RFC 9460)
pub const TYPE_ANY: u16 = 255;

pub const CLASS_IN: u16 = 1;
pub const CLASS_CH: u16 = 3;
pub const CLASS_HS: u16 = 4;
pub const CLASS_ANY: u16 = 255;

// DNS Response Codes (RCODE)
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

// Comprehensive multi-vendor spyware, OS telemetry, and ad tracker sinkhole sinks
pub const SINKHOLE_DOMAINS: &[&str] = &[
    // Mozilla Telemetry
    "telemetry.mozilla.org",
    "incoming.telemetry.mozilla.org",
    "tracking-protection.cdn.mozilla.net",
    "activity-stream-icons.services.mozilla.com",
    "location.services.mozilla.com",
    "push.services.mozilla.com",
    "crash-stats.mozilla.org",
    // Microsoft Windows Diagnostics & Telemetry
    "telemetry.microsoft.com",
    "v10.events.data.microsoft.com",
    "v20.events.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "settings-win.data.microsoft.com",
    "diagnostics.support.microsoft.com",
    "feedback.microsoft.com",
    "activity.windows.com",
    // Google Analytics & Crash Probes
    "google-analytics.com",
    "ssl.google-analytics.com",
    "stats.g.doubleclick.net",
    "app-measurement.com",
    "crashlytics.com",
    "firebaselogging-pa.googleapis.com",
    "tools.google.com",
    // Apple Diagnostics
    "metrics.apple.com",
    "diagnostics.apple.com",
    "iphonesubmissions.apple.com",
    // Third-party SDKs & Ad Brokers
    "telemetry.sdk.inmobi.com",
    "inbound.sentry.io",
    "browser.sentry-cdn.com",
    "api.mixpanel.com",
    "segment.io",
    "api.segment.io",
    "graph.facebook.com",
    "connect.facebook.net",
    "pixel.facebook.com",
    "clarity.ms",
    "hotjar.com",
];

// ==============================================================================
// 2. DNS WIRE PROTOCOL STRUCTURES (`repr(C)` & Canonical Memory)
// ==============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool,     // 0 = Query, 1 = Response
    pub opcode: u8,   // 0 = Standard Query
    pub aa: bool,     // Authoritative Answer
    pub tc: bool,     // Truncated Message
    pub rd: bool,     // Recursion Desired
    pub ra: bool,     // Recursion Available
    pub z: bool,      // Reserved
    pub ad: bool,     // Authenticated Data (DNSSEC)
    pub cd: bool,     // Checking Disabled (DNSSEC)
    pub rcode: u8,    // Response Code
    pub qdcount: u16, // Question count
    pub ancount: u16, // Answer count
    pub nscount: u16, // Authority records
    pub arcount: u16, // Additional records
}

impl DnsHeader {
    pub fn new_query(id: u16) -> Self {
        Self {
            id,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: true, // Recursion Desired by default
            ra: false,
            z: false,
            ad: false,
            cd: false,
            rcode: RCODE_NOERROR,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut flags: u16 = 0;
        if self.qr {
            flags |= 0x8000;
        }
        flags |= ((self.opcode as u16) & 0x0F) << 11;
        if self.aa {
            flags |= 0x0400;
        }
        if self.tc {
            flags |= 0x0200;
        }
        if self.rd {
            flags |= 0x0100;
        }
        if self.ra {
            flags |= 0x0080;
        }
        if self.z {
            flags |= 0x0040;
        }
        if self.ad {
            flags |= 0x0020;
        }
        if self.cd {
            flags |= 0x0010;
        }
        flags |= (self.rcode as u16) & 0x0F;

        let mut out = [0u8; 12];
        out[0..2].copy_from_slice(&self.id.to_be_bytes());
        out[2..4].copy_from_slice(&flags.to_be_bytes());
        out[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        out[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        out[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        out[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }

        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        let nscount = u16::from_be_bytes([buf[8], buf[9]]);
        let arcount = u16::from_be_bytes([buf[10], buf[11]]);

        Some(Self {
            id,
            qr: (flags & 0x8000) != 0,
            opcode: ((flags >> 11) & 0x0F) as u8,
            aa: (flags & 0x0400) != 0,
            tc: (flags & 0x0200) != 0,
            rd: (flags & 0x0100) != 0,
            ra: (flags & 0x0080) != 0,
            z: (flags & 0x0040) != 0,
            ad: (flags & 0x0020) != 0,
            cd: (flags & 0x0010) != 0,
            rcode: (flags & 0x000F) as u8,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CName(String),
    Ptr(String),
    Txt(Vec<String>),
    Mx {
        preference: u16,
        exchange: String,
    },
    Opt {
        udp_payload_size: u16,
        options: Vec<u8>,
    },
    Raw(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
    pub raw_payload: Vec<u8>,
}

// ==============================================================================
// 3. DNS PARSING & SERIALIZATION CORE (RFC 1035)
// ==============================================================================

impl DnsPacket {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let header = DnsHeader::from_bytes(buf)
            .ok_or_else(|| WraithError::Custom("Truncated DNS message header".into()))?;

        let mut offset = 12;
        let mut questions = Vec::with_capacity(header.qdcount as usize);

        for _ in 0..header.qdcount {
            if offset >= buf.len() {
                return Err(WraithError::Custom("Missing DNS question".into()));
            }
            let (name, new_offset) = Self::parse_qname(buf, offset)?;
            offset = new_offset;

            if offset + 4 > buf.len() {
                return Err(WraithError::Custom("Truncated DNS question section".into()));
            }

            let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            offset += 4;

            questions.push(DnsQuestion {
                name,
                qtype,
                qclass,
            });
        }

        Ok(Self {
            header,
            questions,
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            raw_payload: buf.to_vec(),
        })
    }

    /// Parses DNS label sequence with support for RFC 1035 pointer compression (0xC0)
    pub fn parse_qname(buf: &[u8], mut offset: usize) -> Result<(String, usize)> {
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut final_offset = offset;
        let mut jumps_performed = 0;
        let mut expanded_len = 1usize;

        loop {
            if offset >= buf.len() {
                return Err(WraithError::Custom("DNS QNAME buffer overflow".into()));
            }

            let len = buf[offset] as usize;

            // Pointer compression check
            if (len & 0xC0) == 0xC0 {
                if offset + 1 >= buf.len() {
                    return Err(WraithError::Custom("Truncated DNS pointer".into()));
                }
                let ptr_offset = ((len & 0x3F) << 8) | (buf[offset + 1] as usize);
                if !jumped {
                    final_offset = offset + 2;
                    jumped = true;
                }
                offset = ptr_offset;
                jumps_performed += 1;
                if jumps_performed > 10 {
                    return Err(WraithError::Custom(
                        "DNS pointer cycle loop detected".into(),
                    ));
                }
                continue;
            }

            if len > 63 {
                return Err(WraithError::Custom("Invalid DNS label length".into()));
            }
            offset += 1;
            if len == 0 {
                if !jumped {
                    final_offset = offset;
                }
                break;
            }

            if offset + len > buf.len() {
                return Err(WraithError::Custom(
                    "DNS label exceeds buffer bounds".into(),
                ));
            }

            let label = String::from_utf8_lossy(&buf[offset..offset + len]).to_string();
            expanded_len += len + 1;
            if expanded_len > 255 { return Err(WraithError::Network("DNS name exceeds 255 wire octets".into())); }
            labels.push(label);
            offset += len;
        }

        Ok((labels.join("."), final_offset))
    }

    /// Serializes a domain string (e.g., "check.torproject.org") into standard DNS wire format
    pub fn encode_qname(domain: &str, buf: &mut Vec<u8>) {
        for label in domain.split('.') {
            let bytes = label.as_bytes();
            if !bytes.is_empty() {
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
            }
        }
        buf.push(0); // Root label null terminator
    }

    /// Builds a synthetic RFC 1035 NXDOMAIN response
    pub fn build_nxdomain_response(&self) -> Vec<u8> {
        let mut resp = Vec::with_capacity(512);
        let mut hdr = self.header;
        hdr.qr = true;
        hdr.ra = true;
        hdr.rcode = RCODE_NXDOMAIN;
        hdr.ancount = 0;
        hdr.nscount = 0;
        hdr.arcount = 0;

        resp.extend_from_slice(&hdr.to_bytes());

        // Only echo questions, not the original additional section.
        for question in &self.questions {
            Self::encode_qname(&question.name, &mut resp);
            resp.extend_from_slice(&question.qtype.to_be_bytes());
            resp.extend_from_slice(&question.qclass.to_be_bytes());
        }

        resp
    }

    /// Applies RFC 7830 / RFC 8467 EDNS0 random byte padding to defeat traffic analysis
    pub fn apply_edns0_padding(mut payload: Vec<u8>, target_len: usize) -> Vec<u8> {
        if payload.len() >= target_len {
            return payload;
        }

        let Some(header) = DnsHeader::from_bytes(&payload) else { return payload; };
        // Preserve existing OPT records; never append unframed random garbage.
        if header.arcount != 0 || target_len < payload.len() + 15 || target_len > 4096 {
            return payload;
        }
        let padding_len = target_len - payload.len() - 15;
        payload[10..12].copy_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0, 0]);
        payload.extend_from_slice(&((padding_len + 4) as u16).to_be_bytes());
        payload.extend_from_slice(&12u16.to_be_bytes());
        payload.extend_from_slice(&(padding_len as u16).to_be_bytes());
        payload.resize(target_len, 0);
        payload
    }
}

// ==============================================================================
// 4. QNAME MINIMIZATION RESOLVER (RFC 7816)
// ==============================================================================

pub struct QnameMinimizer;

impl QnameMinimizer {
    /// Deconstructs a deep domain into progressive minimal query labels
    /// E.g. "a.b.c.example.com" -> ["example.com", "c.example.com", "b.c.example.com", "a.b.c.example.com"]
    pub fn build_minimization_chain(domain: &str) -> Vec<String> {
        let labels: Vec<&str> = domain.trim_matches('.').split('.').collect();
        if labels.len() <= 2 {
            return vec![domain.to_string()];
        }

        let mut chain = Vec::new();
        for i in (0..labels.len() - 1).rev() {
            let sub = labels[i..].join(".");
            chain.push(sub);
        }

        chain
    }
}

// ==============================================================================
// 5. CACHE WITH TTL & TIME-BASED JITTER
// ==============================================================================

#[derive(Debug, Clone)]
pub struct CachedDnsResponse {
    pub response: Vec<u8>,
    pub expires_at: Instant,
}

pub type DnsCache = Arc<RwLock<HashMap<String, CachedDnsResponse>>>;

// ==============================================================================
// 6. ASYNC SOVEREIGN DNS SERVER & DOH PROVIDER MATRIX
// ==============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohPresetInfo {
    pub key: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub description: &'static str,
    pub jurisdiction: &'static str,
    pub features: &'static str,
}

pub const DOH_PRESETS: &[DohPresetInfo] = &[
    DohPresetInfo {
        key: "quad9",
        name: "Quad9 (Hardened / Privacy)",
        url: "https://dns.quad9.net/dns-query",
        description: "Zero-logging Swiss jurisdiction with malware & phishing threat intelligence",
        jurisdiction: "Switzerland (GDPR / FADP)",
        features: "No-Logs | Threat Intelligence | DNSSEC",
    },
    DohPresetInfo {
        key: "mullvad",
        name: "Mullvad VPN Privacy DNS",
        url: "https://dns.mullvad.net/dns-query",
        description: "Strict no-logs policy, ad/tracker and spyware sinkhole protection",
        jurisdiction: "Sweden (EU GDPR)",
        features: "No-Logs | Ad/Tracker Sinkhole | Audit-Verified",
    },
    DohPresetInfo {
        key: "cloudflare",
        name: "Cloudflare (1.1.1.1)",
        url: "https://cloudflare-dns.com/dns-query",
        description: "Ultra fast Anycast low-latency routing, RFC 8484 standard",
        jurisdiction: "United States",
        features: "Ultra Low Latency | DNSSEC | Fast Anycast",
    },
    DohPresetInfo {
        key: "adguard",
        name: "AdGuard DNS",
        url: "https://dns.adguard-dns.com/dns-query",
        description: "Aggressive advertising and spyware telemetry filtering",
        jurisdiction: "Cyprus (EU GDPR)",
        features: "Ad-Blocker | Telemetry Sinkhole | Family Safe",
    },
    DohPresetInfo {
        key: "controld",
        name: "Control D (High-Speed)",
        url: "https://freedns.controld.com/p0",
        description: "Uncensored high-performance recursive Anycast resolver",
        jurisdiction: "Canada",
        features: "Unfiltered | High Throughput | Anycast",
    },
    DohPresetInfo {
        key: "google",
        name: "Google Public DNS",
        url: "https://dns.google/dns-query",
        description: "Worldwide Anycast infrastructure (8.8.8.8 / 8.8.4.4)",
        jurisdiction: "United States",
        features: "Global Anycast | 99.99% Uptime | DNSSEC",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DohProvider {
    Preset(&'static DohPresetInfo),
    Custom(String),
}

impl DohProvider {
    pub fn parse_input(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(Self::default_provider());
        }

        let lower = trimmed.to_lowercase();
        for preset in DOH_PRESETS {
            if preset.key == lower || preset.key == lower.replace(['-', '_'], "") {
                return Ok(Self::Preset(preset));
            }
        }

        if trimmed.starts_with("https://") {
            if trimmed.len() > 10 && trimmed.contains('.') {
                return Ok(Self::Custom(trimmed.to_string()));
            } else {
                return Err(WraithError::Configuration(format!(
                    "Invalid custom DoH URL '{trimmed}': missing valid hostname"
                )));
            }
        }

        Err(WraithError::Configuration(format!(
            "Unknown DoH provider or invalid URL '{trimmed}'. Valid presets: quad9, mullvad, cloudflare, adguard, controld, google (or https://... for custom)"
        )))
    }

    pub fn default_provider() -> Self {
        Self::Preset(&DOH_PRESETS[0])
    }

    pub fn url(&self) -> &str {
        match self {
            Self::Preset(p) => p.url,
            Self::Custom(u) => u.as_str(),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Preset(p) => p.name,
            Self::Custom(_) => "Custom Upstream DoH Resolver",
        }
    }

    pub fn jurisdiction(&self) -> &str {
        match self {
            Self::Preset(p) => p.jurisdiction,
            Self::Custom(_) => "User Defined",
        }
    }

    pub fn features(&self) -> &str {
        match self {
            Self::Preset(p) => p.features,
            Self::Custom(_) => "Custom RFC 8484 Wire Protocol",
        }
    }

    pub fn all_presets() -> &'static [DohPresetInfo] {
        DOH_PRESETS
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsTransport {
    UdpTor,
    DoH(String),
}

pub struct SovereignDnsServer {
    bind_addr: String,
    upstream_addr: String,
    transport: DnsTransport,
    cancel_token: CancellationToken,
}

impl Default for SovereignDnsServer {
    fn default() -> Self {
        let (srv, _) = Self::new(None, None);
        srv
    }
}

impl SovereignDnsServer {
    pub fn new(bind_port: Option<u16>, upstream_port: Option<u16>) -> (Self, CancellationToken) {
        Self::new_with_transport(bind_port, upstream_port, DnsTransport::UdpTor)
    }

    pub fn new_with_transport(
        bind_port: Option<u16>,
        upstream_port: Option<u16>,
        transport: DnsTransport,
    ) -> (Self, CancellationToken) {
        let b_port = bind_port.unwrap_or(DNS_LOCAL_PORT);
        let u_port = upstream_port.unwrap_or(TOR_DNS_PORT);
        let cancel_token = CancellationToken::new();

        let srv = Self {
            bind_addr: format!("127.0.0.1:{b_port}"),
            upstream_addr: format!("127.0.0.1:{u_port}"),
            transport,
            cancel_token: cancel_token.clone(),
        };
        (srv, cancel_token)
    }

    /// Run the same bounded TCP/UDP implementation used by foreground sessions.
    pub async fn run(&self) -> Result<()> {
        self.spawn_server().await?.await
            .map_err(|e| WraithError::Network(format!("DNS server task failed: {e}")))
    }

    async fn resolve_query(
        query_bytes: Vec<u8>,
        upstream: String,
        transport: DnsTransport,
    ) -> Result<Option<Vec<u8>>> {
        let parsed_pkt = match DnsPacket::parse(&query_bytes) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };

        if parsed_pkt.header.qr || parsed_pkt.questions.len() != 1 {
            return Ok(None);
        }

        let qname = &parsed_pkt.questions[0].name;


        // 1. Check Spyware & Telemetry Sinkhole Matrix
        let is_sinkhole = SINKHOLE_DOMAINS.iter().any(|sink| { let name = qname.to_ascii_lowercase(); name == *sink || name.ends_with(&format!(".{sink}")) });
        if is_sinkhole {
            info!("🛡️ SINKHOLE INTERCEPTION: Blocked telemetry query '{qname}'");
            let nxdomain = parsed_pkt.build_nxdomain_response();
            let padded = DnsPacket::apply_edns0_padding(nxdomain, EDNS0_TARGET_PADDING_SIZE);
            return Ok(Some(padded));
        }

        // Forward each query until full RR TTL aging is implemented; a random
        // cache lifetime can serve stale records and retain unbounded entries.

        // 3. Relay Query via DoH or Local Tor DNSPort (5353)
        let mut response_bytes: Option<Vec<u8>> = None;

        if let DnsTransport::DoH(ref doh_url) = transport {
            let result = tokio::time::timeout(Duration::from_secs(25), crate::dnssec::resolve(doh_url, &query_bytes)).await;
            return match result {
                Ok(Ok(response)) => Ok(Some(response)),
                _ => Ok(Some(crate::dnssec::servfail(&query_bytes)?)),
            };
        }

        if response_bytes.is_none() {
            if let Ok(upstream_socket) = UdpSocket::bind("127.0.0.1:0").await {
                let _ = upstream_socket.connect(&upstream).await;
                let _ = upstream_socket.send(&query_bytes).await;

                let mut tor_resp_buf = vec![0u8; DNS_MAX_PACKET_SIZE];
                if let Ok(Ok(n)) = tokio::time::timeout(
                    Duration::from_millis(2500),
                    upstream_socket.recv(&mut tor_resp_buf),
                )
                .await
                {
                    response_bytes = Some(tor_resp_buf[..n].to_vec());
                }
            }
        }

        if let Some(final_resp) = response_bytes {
            let response = DnsPacket::parse(&final_resp)?;
            if !response.header.qr || response.header.id != parsed_pkt.header.id
                || response.questions != parsed_pkt.questions {
                return Err(WraithError::Network("DNS upstream response does not match query".into()));
            }
            let padded = DnsPacket::apply_edns0_padding(final_resp, EDNS0_TARGET_PADDING_SIZE);
            return Ok(Some(padded));
        }

        Ok(None)
    }

    /// Queries upstream DoH endpoint using RFC 8484 application/dns-message POST wire format
    pub(crate) async fn query_doh(url: &str, query_bytes: &[u8]) -> Result<Vec<u8>> {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;

        if !url.starts_with("https://") {
            return Err(WraithError::Custom(
                "Invalid DoH provider URL: must be HTTPS".into(),
            ));
        }

        let mut child = tokio::process::Command::new("curl")
            .args([
                "-q",
                "-s",
                "--fail",
                "--socks5-hostname", "127.0.0.1:9050",
                "--noproxy", "",
                "-X",
                "POST",
                "--connect-timeout",
                "2",
                "-m",
                "4",
                "-H",
                "Content-Type: application/dns-message",
                "-H",
                "Accept: application/dns-message",
                "--data-binary",
                "@-",
                "--",
                url,
            ])
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| WraithError::Network(format!("Failed to spawn DoH process: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(query_bytes).await?;
        }

        let mut bytes = Vec::new();
        child.stdout.take().ok_or_else(|| WraithError::Network("DoH output missing".into()))?
            .take(65536).read_to_end(&mut bytes).await?;
        if bytes.len() >= 65536 { return Err(WraithError::Network("Oversized DNS response".into())); }
        let status = child.wait().await?;
        if status.success() && !bytes.is_empty() {
            Ok(bytes)
        } else {
            Err(WraithError::Network(
                "DoH upstream returned empty response or error".into(),
            ))
        }
    }

    pub async fn spawn_server(&self) -> Result<tokio::task::JoinHandle<()>> {
        let cancel = self.cancel_token.clone();
        let upstream = self.upstream_addr.clone();
        let transport = self.transport.clone();
        let socket = Arc::new(UdpSocket::bind(&self.bind_addr).await?);
        let tcp_listener = TcpListener::bind(&self.bind_addr).await?;
        let capacity = Arc::new(tokio::sync::Semaphore::new(128));
        Ok(tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            let mut recv_buf = vec![0u8; DNS_MAX_PACKET_SIZE];
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    _ = tasks.join_next(), if !tasks.is_empty() => {},
                    incoming = tcp_listener.accept() => {
                        if let Ok((mut stream, _)) = incoming {
                            let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                            let upstream = upstream.clone();
                            let transport = transport.clone();
                            tasks.spawn(async move {
                                let _permit = permit;
                                let _ = tokio::time::timeout(Duration::from_secs(30), async {
                                    let len = stream.read_u16().await? as usize;
                                    if !(12..=DNS_MAX_PACKET_SIZE).contains(&len) { return Ok::<(), WraithError>(()); }
                                    let mut query = vec![0; len];
                                    stream.read_exact(&mut query).await?;
                                    // Resolve directly: a TCP request must not consume a
                                    // second permit by sending back to this UDP listener.
                                    if let Some(response) = Self::resolve_query(query, upstream, transport).await? {
                                        stream.write_u16(response.len() as u16).await?;
                                        stream.write_all(&response).await?;
                                    }
                                    Ok(())
                                }).await;
                            });
                        }
                    }
                    res = socket.recv_from(&mut recv_buf) => {
                        if let Ok((n, peer)) = res {
                            let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                            let query = recv_buf[..n].to_vec();
                            let socket = socket.clone();
                            let upstream = upstream.clone();
                            let transport = transport.clone();
                            tasks.spawn(async move {
                                let _permit = permit;
                                let _ = tokio::time::timeout(Duration::from_secs(30), async {
                                    let original = query.clone();
                                    if let Ok(Some(response)) = Self::resolve_query(query, upstream, transport).await {
                                        if let Ok(response) = crate::dnssec::fit_udp(&original, response) {
                                            let _ = socket.send_to(&response, peer).await;
                                        }
                                    }
                                }).await;
                            });
                        }
                    }
                }
            }
            tasks.shutdown().await;
        }))
    }

    pub fn shutdown(&self) {
        self.cancel_token.cancel();
    }
}

pub type SovereignDnsEngine = SovereignDnsServer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doh_provider_presets() {
        let quad9 = DohProvider::parse_input("quad9").unwrap();
        assert_eq!(quad9.url(), "https://dns.quad9.net/dns-query");
        assert_eq!(quad9.jurisdiction(), "Switzerland (GDPR / FADP)");

        let mullvad = DohProvider::parse_input("mullvad").unwrap();
        assert_eq!(mullvad.url(), "https://dns.mullvad.net/dns-query");
        assert_eq!(mullvad.jurisdiction(), "Sweden (EU GDPR)");

        let cf = DohProvider::parse_input("cloudflare").unwrap();
        assert_eq!(cf.url(), "https://cloudflare-dns.com/dns-query");

        let default_prov = DohProvider::default_provider();
        assert_eq!(default_prov.url(), "https://dns.quad9.net/dns-query");

        // Empty input defaults to Quad9
        let empty_input = DohProvider::parse_input("").unwrap();
        assert_eq!(empty_input.url(), "https://dns.quad9.net/dns-query");
    }

    #[test]
    fn test_doh_provider_custom_url() {
        let custom = DohProvider::parse_input("https://dns.adguard-dns.com/dns-query").unwrap();
        assert_eq!(custom.url(), "https://dns.adguard-dns.com/dns-query");
        assert_eq!(custom.name(), "Custom Upstream DoH Resolver");
        assert_eq!(custom.jurisdiction(), "User Defined");
    }

    #[test]
    fn test_doh_provider_invalid_inputs() {
        // Plaintext HTTP must be rejected
        let http_res = DohProvider::parse_input("http://insecure.dns/query");
        assert!(http_res.is_err());

        // Malformed custom URL
        let bad_url = DohProvider::parse_input("https://nodots");
        assert!(bad_url.is_err());

        // Unknown preset name
        let unknown = DohProvider::parse_input("random_nonexistent_provider");
        assert!(unknown.is_err());
    }

    #[test]
    fn test_dns_header_creation() {
        let hdr = DnsHeader::new_query(0x1337);
        assert_eq!(hdr.id, 0x1337);
        assert!(!hdr.qr);
        assert_eq!(hdr.qdcount, 1);
        assert_eq!(hdr.ancount, 0);
        assert_eq!(hdr.rcode, RCODE_NOERROR);
    }

    #[test]
    fn test_sinkhole_telemetry_match() {
        assert!(SINKHOLE_DOMAINS.iter().any(|sink| "telemetry.microsoft.com".ends_with(sink)));
        assert!(SINKHOLE_DOMAINS.iter().any(|sink| "stats.g.doubleclick.net".ends_with(sink)));
        assert!(!SINKHOLE_DOMAINS.iter().any(|sink| "torproject.org".ends_with(sink)));
    }
}

#[cfg(test)]
mod protocol_regressions {
    use super::*;

    fn query() -> Vec<u8> {
        let mut bytes = DnsHeader::new_query(123).to_bytes().to_vec();
        DnsPacket::encode_qname("example.org", &mut bytes);
        bytes.extend_from_slice(&[0, 1, 0, 1]);
        bytes
    }

    #[test]
    fn padding_is_framed_as_an_opt_record() {
        let original = query();
        let padded = DnsPacket::apply_edns0_padding(original.clone(), 468);
        assert_eq!(padded.len(), 468);
        assert_eq!(DnsHeader::from_bytes(&padded).unwrap().arcount, 1);
        assert_eq!(&padded[original.len()..original.len() + 3], &[0, 0, 41]);
        let end = original.len() + 11;
        assert_eq!(&padded[end..end + 2], &[0, 12]);
        assert_eq!(DnsPacket::apply_edns0_padding(padded.clone(), 512), padded);
    }

    #[test]
    fn rejects_missing_questions_and_reserved_labels() {
        assert!(DnsPacket::parse(&DnsHeader::new_query(1).to_bytes()).is_err());
        assert!(DnsPacket::parse_qname(&[64, 0], 0).is_err());
        let mut oversized = Vec::new();
        for _ in 0..4 { oversized.push(63); oversized.extend_from_slice(&[b'a'; 63]); }
        oversized.push(0);
        assert!(DnsPacket::parse_qname(&oversized, 0).is_err());
        assert!(DnsPacket::parse_qname(&[0xc0, 0], 0).is_err());
    }

    #[tokio::test]
    async fn udp_and_tcp_queries_reach_the_configured_upstream() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = reservation.local_addr().unwrap().port();
            drop(reservation);
            let (server, cancel) = SovereignDnsServer::new(Some(port), Some(upstream.local_addr().unwrap().port()));
            let handle = server.spawn_server().await.unwrap();
            let responder = tokio::spawn(async move {
                for _ in 0..2 {
                    let mut bytes = [0u8; 4096];
                    let (n, peer) = upstream.recv_from(&mut bytes).await.unwrap();
                    bytes[2] |= 0x80;
                    upstream.send_to(&bytes[..n], peer).await.unwrap();
                }
            });
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            udp.connect((std::net::Ipv4Addr::LOCALHOST, port)).await.unwrap();
            udp.send(&query()).await.unwrap();
            let mut response = [0u8; 4096];
            let n = udp.recv(&mut response).await.unwrap();
            assert!(DnsPacket::parse(&response[..n]).unwrap().header.qr);
            let mut tcp = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await.unwrap();
            tcp.write_u16(query().len() as u16).await.unwrap();
            tcp.write_all(&query()).await.unwrap();
            let n = tcp.read_u16().await.unwrap() as usize;
            tcp.read_exact(&mut response[..n]).await.unwrap();
            assert!(DnsPacket::parse(&response[..n]).unwrap().header.qr);
            responder.await.unwrap();
            cancel.cancel();
            handle.await.unwrap();
        }).await.expect("DNS relay stalled");
    }

    #[tokio::test]
    async fn saturated_tcp_requests_do_not_wait_for_udp_permits() {
        tokio::time::timeout(Duration::from_secs(12), async {
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port_holder = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = port_holder.local_addr().unwrap().port();
            drop(port_holder);
            let (server, cancel) = SovereignDnsServer::new(Some(port), Some(upstream.local_addr().unwrap().port()));
            let handle = server.spawn_server().await.unwrap();
            let responder = tokio::spawn(async move {
                let mut requests = Vec::new();
                for _ in 0..128 {
                    let mut bytes = vec![0; 4096];
                    let (n, peer) = upstream.recv_from(&mut bytes).await.unwrap();
                    bytes.truncate(n); bytes[2] |= 0x80;
                    requests.push((bytes, peer));
                }
                for (bytes, peer) in requests { upstream.send_to(&bytes, peer).await.unwrap(); }
            });
            let mut clients = tokio::task::JoinSet::new();
            for _ in 0..128 {
                clients.spawn(async move {
                    let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await.unwrap();
                    stream.write_u16(query().len() as u16).await.unwrap();
                    stream.write_all(&query()).await.unwrap();
                    let len = stream.read_u16().await.unwrap();
                    let mut response = vec![0; len as usize];
                    stream.read_exact(&mut response).await.unwrap();
                    assert!(DnsPacket::parse(&response).unwrap().header.qr);
                });
            }
            while let Some(client) = clients.join_next().await { client.unwrap(); }
            responder.await.unwrap();
            cancel.cancel(); handle.await.unwrap();
            // Shutdown must release the shared UDP listener as well as TCP.
            UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)).await.unwrap();
            TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await.unwrap();
        }).await.expect("TCP DNS capacity deadlocked");
    }

    #[tokio::test]
    async fn reports_occupied_dns_port() {
        let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (server, _) = SovereignDnsServer::new(Some(occupied.local_addr().unwrap().port()), None);
        assert!(server.spawn_server().await.is_err());
    }
}
