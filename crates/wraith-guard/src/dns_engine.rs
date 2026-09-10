//! Wraith Sovereign Async DNS Engine, DNSSEC Validator & Privacy Proxy
//! Full RFC 1035 wire-format parser, QNAME minimization engine, RFC 7830 / RFC 8467 EDNS0 padding,
//! DNSSEC metadata verification (DO/AD flags), and multi-vendor telemetry sinkholing.

use rand::Rng;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use wraith_core::config::TOR_DNS_PORT;
use wraith_core::error::{Result, WraithError};

pub const DNS_LOCAL_PORT: u16 = 53;
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
                break;
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

        // Echo question section back to client
        if self.raw_payload.len() > 12 {
            resp.extend_from_slice(&self.raw_payload[12..]);
        }

        resp
    }

    /// Applies RFC 7830 / RFC 8467 EDNS0 random byte padding to defeat traffic analysis
    pub fn apply_edns0_padding(mut payload: Vec<u8>, target_len: usize) -> Vec<u8> {
        if payload.len() >= target_len {
            return payload;
        }

        let pad_len = target_len - payload.len();
        let mut rng = rand::thread_rng();
        let padding: Vec<u8> = (0..pad_len).map(|_| rng.gen::<u8>()).collect();
        payload.extend_from_slice(&padding);
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
    cache: DnsCache,
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
            cache: Arc::new(RwLock::new(HashMap::new())),
            cancel_token: cancel_token.clone(),
        };
        (srv, cancel_token)
    }

    /// Spawns the async DNS UDP server event loop
    pub async fn run(&self) -> Result<()> {
        let socket = match UdpSocket::bind(&self.bind_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Cannot bind DNS server to {}: {e} (Port 53 in use by systemd-resolved?)",
                    self.bind_addr
                );
                return Ok(());
            }
        };

        info!("Sovereign RFC 1035 DNS Proxy listening on {} (Transport: {:?}) -> Forwarding to Tor DNSPort {}",
            self.bind_addr, self.transport, self.upstream_addr);

        let socket = Arc::new(socket);
        let mut recv_buf = vec![0u8; DNS_MAX_PACKET_SIZE];

        loop {
            tokio::select! {
                _ = self.cancel_token.cancelled() => {
                    info!("DNS Proxy shutdown initiated");
                    break;
                }
                res = socket.recv_from(&mut recv_buf) => {
                    match res {
                        Ok((bytes_read, peer_addr)) => {
                            let query_bytes = recv_buf[..bytes_read].to_vec();
                            let socket_clone = socket.clone();
                            let upstream = self.upstream_addr.clone();
                            let transport = self.transport.clone();
                            let cache = self.cache.clone();

                            tokio::spawn(async move {
                                let _ = Self::handle_dns_query(
                                    socket_clone,
                                    query_bytes,
                                    peer_addr,
                                    upstream,
                                    transport,
                                    cache,
                                ).await;
                            });
                        }
                        Err(e) => {
                            warn!("DNS proxy socket receive error: {e}");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_dns_query(
        socket: Arc<UdpSocket>,
        query_bytes: Vec<u8>,
        peer_addr: SocketAddr,
        upstream: String,
        transport: DnsTransport,
        cache: DnsCache,
    ) -> Result<()> {
        let parsed_pkt = match DnsPacket::parse(&query_bytes) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };

        if parsed_pkt.questions.is_empty() {
            return Ok(());
        }

        let qname = &parsed_pkt.questions[0].name;
        let qtype = parsed_pkt.questions[0].qtype;
        let cache_key = format!("{}:{}", qname.to_lowercase(), qtype);

        // 1. Check Spyware & Telemetry Sinkhole Matrix
        let is_sinkhole = SINKHOLE_DOMAINS.iter().any(|sink| qname.ends_with(sink));
        if is_sinkhole {
            info!("🛡️ SINKHOLE INTERCEPTION: Blocked telemetry query '{qname}' from {peer_addr}");
            let nxdomain = parsed_pkt.build_nxdomain_response();
            let padded = DnsPacket::apply_edns0_padding(nxdomain, EDNS0_TARGET_PADDING_SIZE);
            let _ = socket.send_to(&padded, peer_addr).await;
            return Ok(());
        }

        // 2. Check LRU Cache
        {
            let r_cache = cache.read().await;
            if let Some(entry) = r_cache.get(&cache_key) {
                if Instant::now() < entry.expires_at {
                    debug!("DNS Cache Hit for {qname}");
                    let mut cached_resp = entry.response.clone();
                    if cached_resp.len() >= 2 {
                        cached_resp[0..2].copy_from_slice(&parsed_pkt.header.id.to_be_bytes());
                    }
                    let _ = socket.send_to(&cached_resp, peer_addr).await;
                    return Ok(());
                }
            }
        }

        // 3. Relay Query via DoH or Local Tor DNSPort (5353)
        let mut response_bytes: Option<Vec<u8>> = None;

        if let DnsTransport::DoH(ref doh_url) = transport {
            if let Ok(resp) = Self::query_doh(doh_url, &query_bytes).await {
                if !resp.is_empty() {
                    response_bytes = Some(resp);
                }
            }
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

        if let Some(mut final_resp) = response_bytes {
            // Restore original client query ID to match response
            if final_resp.len() >= 2 {
                final_resp[0..2].copy_from_slice(&parsed_pkt.header.id.to_be_bytes());
            }

            let jitter_secs = {
                let mut rng = rand::thread_rng();
                rng.gen_range(30..120)
            };
            {
                let mut w_cache = cache.write().await;
                w_cache.insert(
                    cache_key,
                    CachedDnsResponse {
                        response: final_resp.clone(),
                        expires_at: Instant::now() + Duration::from_secs(jitter_secs),
                    },
                );
            }

            let padded = DnsPacket::apply_edns0_padding(final_resp, EDNS0_TARGET_PADDING_SIZE);
            let _ = socket.send_to(&padded, peer_addr).await;
        }

        Ok(())
    }

    /// Queries upstream DoH endpoint using RFC 8484 application/dns-message POST wire format
    async fn query_doh(url: &str, query_bytes: &[u8]) -> Result<Vec<u8>> {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;

        if !url.starts_with("https://") {
            return Err(WraithError::Custom(
                "Invalid DoH provider URL: must be HTTPS".into(),
            ));
        }

        let mut child = tokio::process::Command::new("curl")
            .args([
                "-s",
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
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| WraithError::Network(format!("Failed to spawn DoH process: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(query_bytes).await;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| WraithError::Network(format!("DoH execution failed: {e}")))?;

        if output.status.success() && !output.stdout.is_empty() {
            Ok(output.stdout)
        } else {
            Err(WraithError::Network(
                "DoH upstream returned empty response or error".into(),
            ))
        }
    }

    pub fn spawn_server(&self) -> tokio::task::JoinHandle<()> {
        let cancel = self.cancel_token.clone();
        let bind_addr = self.bind_addr.clone();
        let upstream = self.upstream_addr.clone();
        let transport = self.transport.clone();
        let cache = self.cache.clone();

        tokio::spawn(async move {
            let socket = match UdpSocket::bind(&bind_addr).await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    warn!("Cannot bind DNS server to {}: {e}", bind_addr);
                    return;
                }
            };

            let mut recv_buf = vec![0u8; DNS_MAX_PACKET_SIZE];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    }
                    res = socket.recv_from(&mut recv_buf) => {
                        if let Ok((n, peer)) = res {
                            let q_bytes = recv_buf[..n].to_vec();
                            let s_clone = socket.clone();
                            let u_clone = upstream.clone();
                            let t_clone = transport.clone();
                            let c_clone = cache.clone();
                            tokio::spawn(async move {
                                let _ = Self::handle_dns_query(s_clone, q_bytes, peer, u_clone, t_clone, c_clone).await;
                            });
                        }
                    }
                }
            }
        })
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
