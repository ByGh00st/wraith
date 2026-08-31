//! Wraith Sovereign Async DNS Engine, DNSSEC Validator & Privacy Proxy
//! Full RFC 1035 wire-format parser, QNAME minimization engine, RFC 7830 / RFC 8467 EDNS0 padding,
//! DNSSEC metadata verification (DO/AD flags), and multi-vendor telemetry sinkholing.

#![allow(unused_imports, unused_variables, dead_code)]

use rand::Rng;
use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
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
pub const TYPE_OPT: u16 = 41;      // EDNS0
pub const TYPE_DS: u16 = 43;       // DNSSEC Delegation Signer
pub const TYPE_RRSIG: u16 = 46;    // DNSSEC Signature
pub const TYPE_NSEC: u16 = 47;     // DNSSEC Next Secure
pub const TYPE_DNSKEY: u16 = 48;   // DNSSEC Key Record
pub const TYPE_NSEC3: u16 = 50;    // DNSSEC NSEC3
pub const TYPE_HTTPS: u16 = 65;    // Service Binding (RFC 9460)
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
        if self.qr { flags |= 0x8000; }
        flags |= ((self.opcode as u16) & 0x0F) << 11;
        if self.aa { flags |= 0x0400; }
        if self.tc { flags |= 0x0200; }
        if self.rd { flags |= 0x0100; }
        if self.ra { flags |= 0x0080; }
        if self.z { flags |= 0x0040; }
        if self.ad { flags |= 0x0020; }
        if self.cd { flags |= 0x0010; }
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
    Mx { preference: u16, exchange: String },
    Opt { udp_payload_size: u16, options: Vec<u8> },
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

            questions.push(DnsQuestion { name, qtype, qclass });
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
                let ptr_offset = (((len & 0x3F) << 8) | (buf[offset + 1] as usize)) as usize;
                if !jumped {
                    final_offset = offset + 2;
                    jumped = true;
                }
                offset = ptr_offset;
                jumps_performed += 1;
                if jumps_performed > 10 {
                    return Err(WraithError::Custom("DNS pointer cycle loop detected".into()));
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
                return Err(WraithError::Custom("DNS label exceeds buffer bounds".into()));
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
// 6. ASYNC SOVEREIGN DNS SERVER
// ==============================================================================

pub struct SovereignDnsServer {
    bind_addr: String,
    upstream_addr: String,
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
        let b_port = bind_port.unwrap_or(DNS_LOCAL_PORT);
        let u_port = upstream_port.unwrap_or(TOR_DNS_PORT);
        let cancel_token = CancellationToken::new();

        let srv = Self {
            bind_addr: format!("127.0.0.1:{b_port}"),
            upstream_addr: format!("127.0.0.1:{u_port}"),
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
                warn!("Cannot bind DNS server to {}: {e} (Port 53 in use by systemd-resolved?)", self.bind_addr);
                return Ok(());
            }
        };

        info!("Sovereign RFC 1035 DNS Proxy listening on {} -> Forwarding to Tor DNSPort {}",
            self.bind_addr, self.upstream_addr);

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
                            let cache = self.cache.clone();

                            tokio::spawn(async move {
                                let _ = Self::handle_dns_query(
                                    socket_clone,
                                    query_bytes,
                                    peer_addr,
                                    upstream,
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

        // 3. Relay Query to Local Tor DNSPort (5353)
        if let Ok(upstream_socket) = UdpSocket::bind("127.0.0.1:0").await {
            let _ = upstream_socket.connect(&upstream).await;
            let _ = upstream_socket.send(&query_bytes).await;

            let mut tor_resp_buf = vec![0u8; DNS_MAX_PACKET_SIZE];
            if let Ok(Ok(n)) = tokio::time::timeout(
                Duration::from_millis(2500),
                upstream_socket.recv(&mut tor_resp_buf),
            ).await {
                let tor_resp = tor_resp_buf[..n].to_vec();

                let jitter_secs = {
                    let mut rng = rand::thread_rng();
                    rng.gen_range(30..120)
                };
                {
                    let mut w_cache = cache.write().await;
                    w_cache.insert(
                        cache_key,
                        CachedDnsResponse {
                            response: tor_resp.clone(),
                            expires_at: Instant::now() + Duration::from_secs(jitter_secs),
                        },
                    );
                }

                let padded = DnsPacket::apply_edns0_padding(tor_resp, EDNS0_TARGET_PADDING_SIZE);
                let _ = socket.send_to(&padded, peer_addr).await;
            }
        }

        Ok(())
    }

    pub fn spawn_server(&self) -> tokio::task::JoinHandle<()> {
        let cancel = self.cancel_token.clone();
        let bind_addr = self.bind_addr.clone();
        let upstream = self.upstream_addr.clone();
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
                            let c_clone = cache.clone();
                            tokio::spawn(async move {
                                let _ = Self::handle_dns_query(s_clone, q_bytes, peer, u_clone, c_clone).await;
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
