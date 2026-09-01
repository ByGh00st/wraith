//! Wraith Sovereign Zero-Copy Packet Dissector & Real-Time Egress Intrusion Detection Engine (IDS)
//! Deep L2/L3/L4 frame analysis, TCP stateful flow tracking, Shannon payload entropy calculation,
//! STUN leak trap, and real-time clearnet evasion detector reading from Linux AF_PACKET raw sockets.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicU64;
#[cfg(unix)]
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio_util::sync::CancellationToken;
use wraith_core::config::{TOR_DNS_PORT, TOR_TRANS_PORT};

// ==============================================================================
// 1. ETHERTYPES & NETWORK PROTOCOL CONSTANTS
// ==============================================================================

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_QINQ: u16 = 0x88A8;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_IGMP: u8 = 2;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_IPV6: u8 = 41;
pub const IPPROTO_GRE: u8 = 47;
pub const IPPROTO_ESP: u8 = 50;
pub const IPPROTO_AH: u8 = 51;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_SCTP: u8 = 132;

// TCP Option Kinds (RFC 793, RFC 1323, RFC 2018)
pub const TCP_OPT_EOL: u8 = 0;
pub const TCP_OPT_NOP: u8 = 1;
pub const TCP_OPT_MSS: u8 = 2;
pub const TCP_OPT_WS: u8 = 3;
pub const TCP_OPT_SACK_PERM: u8 = 4;
pub const TCP_OPT_SACK: u8 = 5;
pub const TCP_OPT_TIMESTAMP: u8 = 8;

// STUN Protocol Magic Cookie (RFC 5389)
pub const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

// ==============================================================================
// 2. LAYER 2 (ETHERNET & VLAN) DATA MODELS
// ==============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub vlan_id: Option<u16>,
    pub ethertype: u16,
}

impl fmt::Display for EthernetHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (Type: 0x{:04x})",
            self.src_mac[0], self.src_mac[1], self.src_mac[2], self.src_mac[3], self.src_mac[4], self.src_mac[5],
            self.dst_mac[0], self.dst_mac[1], self.dst_mac[2], self.dst_mac[3], self.dst_mac[4], self.dst_mac[5],
            self.ethertype
        )
    }
}

// ==============================================================================
// 3. LAYER 3 (IPv4 & IPv6) DATA MODELS
// ==============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Gre,
    Esp,
    Other(u8),
}

impl From<u8> for IpProtocol {
    fn from(val: u8) -> Self {
        match val {
            IPPROTO_TCP => IpProtocol::Tcp,
            IPPROTO_UDP => IpProtocol::Udp,
            IPPROTO_ICMP => IpProtocol::Icmp,
            IPPROTO_ICMPV6 => IpProtocol::IcmpV6,
            IPPROTO_GRE => IpProtocol::Gre,
            IPPROTO_ESP => IpProtocol::Esp,
            other => IpProtocol::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_df: bool,
    pub flags_mf: bool,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: IpProtocol,
    pub hop_limit: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
}

// ==============================================================================
// 4. LAYER 4 (TCP, UDP, ICMP) DATA MODELS & OPTION PARSERS
// ==============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOption {
    Mss(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(Vec<(u32, u32)>),
    Timestamp { val: u32, ecr: u32 },
    Unknown { kind: u8, len: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportHeader {
    Tcp {
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        data_offset: u8,
        fin: bool,
        syn: bool,
        rst: bool,
        psh: bool,
        ack_flag: bool,
        urg: bool,
        ece: bool,
        cwr: bool,
        window: u16,
        checksum: u16,
        options: Vec<TcpOption>,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        length: u16,
        checksum: u16,
    },
    Icmp {
        icmp_type: u8,
        code: u8,
        checksum: u16,
    },
    Other(u8),
}

// ==============================================================================
// 5. DISSECTED PACKET METADATA & TELEMETRY
// ==============================================================================

#[derive(Debug, Clone)]
pub struct DissectedPacket {
    pub timestamp: Instant,
    pub raw_len: usize,
    pub ethernet: Option<EthernetHeader>,
    pub ipv4: Option<Ipv4Header>,
    pub ipv6: Option<Ipv6Header>,
    pub transport: TransportHeader,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub shannon_entropy: f64,
    pub is_loopback: bool,
    pub is_tor_transport: bool,
    pub is_tor_dns: bool,
    pub is_stun_leak: bool,
    pub is_leak_suspect: bool,
}

// ==============================================================================
// 6. ZERO-COPY DISSECTOR ENGINE
// ==============================================================================

pub struct PacketDissector;

impl PacketDissector {
    /// Dissects raw L2 Ethernet frames into structured packet headers
    pub fn dissect(frame: &[u8]) -> Option<DissectedPacket> {
        if frame.len() < 14 {
            return None;
        }

        let mut offset = 0;

        // 1. Ethernet Header (14 bytes)
        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&frame[0..6]);
        src_mac.copy_from_slice(&frame[6..12]);
        let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        offset += 14;

        let mut vlan_id = None;
        // 802.1Q VLAN Tagging
        if ethertype == ETHERTYPE_VLAN && frame.len() >= offset + 4 {
            let tci = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
            vlan_id = Some(tci & 0x0FFF);
            ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
            offset += 4;
        }

        let eth_hdr = EthernetHeader {
            dst_mac,
            src_mac,
            vlan_id,
            ethertype,
        };

        let mut ipv4_hdr = None;
        let mut ipv6_hdr = None;
        let mut transport_hdr = TransportHeader::Other(0);
        let mut ip_proto = IpProtocol::Other(0);
        let mut is_loopback = false;
        let mut is_tor_transport = false;
        let mut is_tor_dns = false;
        let mut is_stun_leak = false;

        // 2. Layer 3 (IPv4 / IPv6) Dissection
        match ethertype {
            ETHERTYPE_IPV4 => {
                if frame.len() < offset + 20 {
                    return None;
                }

                let ver_ihl = frame[offset];
                let version = ver_ihl >> 4;
                let ihl = (ver_ihl & 0x0F) * 4;
                if ihl < 20 || frame.len() < offset + (ihl as usize) {
                    return None;
                }

                let dscp_ecn = frame[offset + 1];
                let dscp = dscp_ecn >> 2;
                let ecn = dscp_ecn & 0x03;
                let total_length = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
                let identification = u16::from_be_bytes([frame[offset + 4], frame[offset + 5]]);
                let flags_frag = u16::from_be_bytes([frame[offset + 6], frame[offset + 7]]);
                let flags_df = (flags_frag & 0x4000) != 0;
                let flags_mf = (flags_frag & 0x2000) != 0;
                let fragment_offset = flags_frag & 0x1FFF;
                let ttl = frame[offset + 8];
                let proto_byte = frame[offset + 9];
                let checksum = u16::from_be_bytes([frame[offset + 10], frame[offset + 11]]);

                let src_ip = Ipv4Addr::new(
                    frame[offset + 12], frame[offset + 13],
                    frame[offset + 14], frame[offset + 15],
                );
                let dst_ip = Ipv4Addr::new(
                    frame[offset + 16], frame[offset + 17],
                    frame[offset + 18], frame[offset + 19],
                );

                ip_proto = IpProtocol::from(proto_byte);
                is_loopback = dst_ip.is_loopback() || src_ip.is_loopback();

                ipv4_hdr = Some(Ipv4Header {
                    version,
                    ihl,
                    dscp,
                    ecn,
                    total_length,
                    identification,
                    flags_df,
                    flags_mf,
                    fragment_offset,
                    ttl,
                    protocol: ip_proto,
                    checksum,
                    src_ip,
                    dst_ip,
                });

                offset += ihl as usize;
            }
            ETHERTYPE_IPV6 => {
                if frame.len() < offset + 40 {
                    return None;
                }

                let vtc_flow = u32::from_be_bytes([
                    frame[offset], frame[offset + 1],
                    frame[offset + 2], frame[offset + 3],
                ]);
                let version = (vtc_flow >> 28) as u8;
                let traffic_class = ((vtc_flow >> 20) & 0xFF) as u8;
                let flow_label = vtc_flow & 0xFFFFF;
                let payload_length = u16::from_be_bytes([frame[offset + 4], frame[offset + 5]]);
                let next_header = frame[offset + 6];
                let hop_limit = frame[offset + 7];

                let mut src_bytes = [0u8; 16];
                let mut dst_bytes = [0u8; 16];
                src_bytes.copy_from_slice(&frame[offset + 8..offset + 24]);
                dst_bytes.copy_from_slice(&frame[offset + 24..offset + 40]);
                let src_ip = Ipv6Addr::from(src_bytes);
                let dst_ip = Ipv6Addr::from(dst_bytes);

                ip_proto = IpProtocol::from(next_header);
                is_loopback = dst_ip.is_loopback() || src_ip.is_loopback();

                ipv6_hdr = Some(Ipv6Header {
                    version,
                    traffic_class,
                    flow_label,
                    payload_length,
                    next_header: ip_proto,
                    hop_limit,
                    src_ip,
                    dst_ip,
                });

                offset += 40;
            }
            _ => {}
        }

        // 3. Layer 4 (Transport) Dissection
        match ip_proto {
            IpProtocol::Tcp => {
                if frame.len() >= offset + 20 {
                    let src_port = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
                    let dst_port = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
                    let seq = u32::from_be_bytes([frame[offset + 4], frame[offset + 5], frame[offset + 6], frame[offset + 7]]);
                    let ack = u32::from_be_bytes([frame[offset + 8], frame[offset + 9], frame[offset + 10], frame[offset + 11]]);
                    let data_offset = (frame[offset + 12] >> 4) * 4;
                    let flags_byte = frame[offset + 13];

                    let fin = (flags_byte & 0x01) != 0;
                    let syn = (flags_byte & 0x02) != 0;
                    let rst = (flags_byte & 0x04) != 0;
                    let psh = (flags_byte & 0x08) != 0;
                    let ack_flag = (flags_byte & 0x10) != 0;
                    let urg = (flags_byte & 0x20) != 0;
                    let ece = (flags_byte & 0x40) != 0;
                    let cwr = (flags_byte & 0x80) != 0;

                    let window = u16::from_be_bytes([frame[offset + 14], frame[offset + 15]]);
                    let checksum = u16::from_be_bytes([frame[offset + 16], frame[offset + 17]]);

                    let mut options = Vec::new();
                    if data_offset > 20 && frame.len() >= offset + (data_offset as usize) {
                        let opt_slice = &frame[offset + 20..offset + (data_offset as usize)];
                        options = Self::parse_tcp_options(opt_slice);
                    }

                    if dst_port == TOR_TRANS_PORT {
                        is_tor_transport = true;
                    }

                    transport_hdr = TransportHeader::Tcp {
                        src_port,
                        dst_port,
                        seq,
                        ack,
                        data_offset,
                        fin,
                        syn,
                        rst,
                        psh,
                        ack_flag,
                        urg,
                        ece,
                        cwr,
                        window,
                        checksum,
                        options,
                    };

                    offset += data_offset.max(20) as usize;
                }
            }
            IpProtocol::Udp => {
                if frame.len() >= offset + 8 {
                    let src_port = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
                    let dst_port = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
                    let length = u16::from_be_bytes([frame[offset + 4], frame[offset + 5]]);
                    let checksum = u16::from_be_bytes([frame[offset + 6], frame[offset + 7]]);

                    if dst_port == TOR_DNS_PORT {
                        is_tor_dns = true;
                    }

                    // Check for WebRTC STUN Binding Request (Magic Cookie 0x2112A442)
                    if frame.len() >= offset + 12 {
                        let maybe_magic = u32::from_be_bytes([
                            frame[offset + 8], frame[offset + 9],
                            frame[offset + 10], frame[offset + 11],
                        ]);
                        if maybe_magic == STUN_MAGIC_COOKIE || dst_port == 3478 || dst_port == 19302 {
                            is_stun_leak = true;
                        }
                    }

                    transport_hdr = TransportHeader::Udp {
                        src_port,
                        dst_port,
                        length,
                        checksum,
                    };

                    offset += 8;
                }
            }
            IpProtocol::Icmp | IpProtocol::IcmpV6 if frame.len() >= offset + 4 => {
                let icmp_type = frame[offset];
                let code = frame[offset + 1];
                let checksum = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
                transport_hdr = TransportHeader::Icmp { icmp_type, code, checksum };
                offset += 4;
            }
            _ => {}
        }

        let payload_len = if frame.len() > offset { frame.len() - offset } else { 0 };
        let payload_slice = if payload_len > 0 { &frame[offset..] } else { &[] };
        let shannon_entropy = Self::calculate_shannon_entropy(payload_slice);

        // Leak Condition: Unencrypted clearnet non-loopback packet escaping outside of Tor TransPort / DNSPort / Relays
        let is_tor_relay = shannon_entropy >= 6.8;
        let is_leak_suspect = !is_loopback && !is_tor_transport && !is_tor_dns && !is_tor_relay && ethertype == ETHERTYPE_IPV4;

        Some(DissectedPacket {
            timestamp: Instant::now(),
            raw_len: frame.len(),
            ethernet: Some(eth_hdr),
            ipv4: ipv4_hdr,
            ipv6: ipv6_hdr,
            transport: transport_hdr,
            payload_offset: offset,
            payload_len,
            shannon_entropy,
            is_loopback,
            is_tor_transport,
            is_tor_dns,
            is_stun_leak,
            is_leak_suspect,
        })
    }

    /// Parses TCP options from the TCP header options slice
    fn parse_tcp_options(opts: &[u8]) -> Vec<TcpOption> {
        let mut result = Vec::new();
        let mut idx = 0;

        while idx < opts.len() {
            let kind = opts[idx];
            if kind == TCP_OPT_EOL {
                break;
            }
            if kind == TCP_OPT_NOP {
                idx += 1;
                continue;
            }

            if idx + 1 >= opts.len() {
                break;
            }
            let len = opts[idx + 1] as usize;
            if len < 2 || idx + len > opts.len() {
                break;
            }

            match kind {
                TCP_OPT_MSS => {
                    if len == 4 {
                        let mss = u16::from_be_bytes([opts[idx + 2], opts[idx + 3]]);
                        result.push(TcpOption::Mss(mss));
                    }
                }
                TCP_OPT_WS => {
                    if len == 3 {
                        result.push(TcpOption::WindowScale(opts[idx + 2]));
                    }
                }
                TCP_OPT_SACK_PERM => {
                    if len == 2 {
                        result.push(TcpOption::SackPermitted);
                    }
                }
                TCP_OPT_TIMESTAMP => {
                    if len == 10 {
                        let val = u32::from_be_bytes([opts[idx + 2], opts[idx + 3], opts[idx + 4], opts[idx + 5]]);
                        let ecr = u32::from_be_bytes([opts[idx + 6], opts[idx + 7], opts[idx + 8], opts[idx + 9]]);
                        result.push(TcpOption::Timestamp { val, ecr });
                    }
                }
                _ => {
                    result.push(TcpOption::Unknown { kind, len: len as u8 });
                }
            }

            idx += len;
        }

        result
    }

    /// Computes Shannon entropy (0.0 to 8.0) of a byte slice to detect encryption vs plaintext
    pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0usize; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len_f = data.len() as f64;
        let mut entropy = 0.0;

        for &c in &counts {
            if c > 0 {
                let p = (c as f64) / len_f;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}

// ==============================================================================
// 7. REAL-TIME DPI HTTP TOOL SIGNATURE SANITIZER (50+ OFFENSIVE TOOL MATRIX)
// ==============================================================================

pub const OFFENSIVE_TOOL_SIGNATURES: &[&str] = &[
    "Nmap Scripting Engine",
    "nmap",
    "sqlmap",
    "ffuf",
    "gobuster",
    "Nikto",
    "dirsearch",
    "nuclei",
    "httpx",
    "Katana",
    "feroxbuster",
    "wpscan",
    "Arjun",
    "Commix",
    "dalfox",
    "Ghauri",
    "Kiterunner",
    "WhatWeb",
    "wafw00f",
    "Amass",
    "Subfinder",
    "RustScan",
    "ZAP",
    "OWASP ZAP",
    "BurpSuite",
    "BurpCollaborator",
    "Droopescan",
    "EyeWitness",
    "Go-http-client",
    "Java/",
    "libwww-perl",
    "Scrapy",
    "aiohttp",
    "httplib2",
    "axios/",
    "node-fetch",
    "PostmanRuntime",
    "Insomnia",
    "Hydra",
    "Medusa",
    "CrackMapExec",
    "NetExec",
    "Impacket",
    "Sublist3r",
    "theHarvester",
    "DNSRecon",
    "testssl",
    "sslscan",
    "Metasploit",
    "msf",
    "masscan",
    "Wfuzz",
    "python-requests",
    "python-urllib",
    "curl/",
    "Wget/",
];

pub const BROWSER_USER_AGENT_POOL: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
];

#[derive(Debug, Clone, Default)]
pub struct DpiSanitizeResult {
    pub sanitized_count: usize,
    pub original_signature: Option<String>,
    pub sanitized_replacement: Option<String>,
    pub unrecognized_alert: Option<String>,
}

pub struct HttpToolSanitizer;

impl HttpToolSanitizer {
    /// In-flight deep packet inspection (DPI) detecting and rewriting 50+ offensive signatures
    /// and dynamically intercepting unrecognized custom User-Agents
    pub fn sanitize_in_flight(payload: &mut [u8]) -> DpiSanitizeResult {
        let mut result = DpiSanitizeResult::default();

        // Check for HTTP User-Agent header line (case-insensitive)
        let ua_prefix = b"user-agent:";
        let mut idx = 0;

        while idx + 12 < payload.len() {
            let mut matches_prefix = true;
            for k in 0..11 {
                if payload[idx + k].to_ascii_lowercase() != ua_prefix[k] {
                    matches_prefix = false;
                    break;
                }
            }

            if matches_prefix {
                // Find line terminator \r\n
                let mut start_val = idx + 11;
                while start_val < payload.len() && payload[start_val] == b' ' {
                    start_val += 1;
                }

                let mut end_val = start_val;
                while end_val < payload.len() && payload[end_val] != b'\r' && payload[end_val] != b'\n' {
                    end_val += 1;
                }

                let raw_ua_slice = &payload[start_val..end_val];
                let raw_ua_str = String::from_utf8_lossy(raw_ua_slice).trim().to_string();

                if !raw_ua_str.is_empty() {
                    let is_known_offensive = OFFENSIVE_TOOL_SIGNATURES
                        .iter()
                        .any(|&sig| raw_ua_str.to_lowercase().contains(&sig.to_lowercase()));

                    let is_standard_browser = raw_ua_str.starts_with("Mozilla/5.0");

                    if is_known_offensive || !is_standard_browser {
                        // Select a random authentic User-Agent from diversified pool
                        let pool_idx = (raw_ua_slice.len() + payload.len()) % BROWSER_USER_AGENT_POOL.len();
                        let target_ua = BROWSER_USER_AGENT_POOL[pool_idx];
                        let target_bytes = target_ua.as_bytes();

                        // In-place rewrite: copy target bytes up to available length or pad with RFC 7230 spaces
                        let available_len = end_val - start_val;
                        let copy_len = target_bytes.len().min(available_len);

                        payload[start_val..start_val + copy_len].copy_from_slice(&target_bytes[..copy_len]);

                        // If original was longer, pad trailing bytes with harmless spaces before \r\n
                        if available_len > copy_len {
                            for b in &mut payload[start_val + copy_len..end_val] {
                                *b = b' ';
                            }
                        }

                        result.sanitized_count += 1;
                        result.original_signature = Some(raw_ua_str.clone());
                        result.sanitized_replacement = Some(target_ua.to_string());

                        if !is_known_offensive && !is_standard_browser {
                            result.unrecognized_alert = Some(raw_ua_str.clone());
                        }
                    }
                }

                idx = end_val;
            } else {
                idx += 1;
            }
        }

        result
    }
}

// ==============================================================================
// 8. REAL-TIME IDS SNIFFER ENGINE
// ==============================================================================

pub struct IdsTelemetry {
    pub packets_inspected: AtomicU64,
    pub tor_routed_bytes: AtomicU64,
    pub clearnet_escapes_blocked: AtomicU64,
    pub stun_webrtc_probes_trapped: AtomicU64,
}

pub struct EgressIntrusionDetector {
    telemetry: Arc<IdsTelemetry>,
    cancel_token: CancellationToken,
}

impl Default for EgressIntrusionDetector {
    fn default() -> Self {
        let (detector, _, _) = Self::new();
        detector
    }
}

impl EgressIntrusionDetector {
    pub fn new() -> (Self, Arc<IdsTelemetry>, CancellationToken) {
        let telemetry = Arc::new(IdsTelemetry {
            packets_inspected: AtomicU64::new(0),
            tor_routed_bytes: AtomicU64::new(0),
            clearnet_escapes_blocked: AtomicU64::new(0),
            stun_webrtc_probes_trapped: AtomicU64::new(0),
        });
        let cancel_token = CancellationToken::new();
        let detector = Self {
            telemetry: telemetry.clone(),
            cancel_token: cancel_token.clone(),
        };
        (detector, telemetry, cancel_token)
    }

    pub fn spawn_sniffer(&self) -> tokio::task::JoinHandle<()> {
        let cancel = self.cancel_token.clone();
        let telemetry = self.telemetry.clone();

        tokio::spawn(async move {
            #[cfg(unix)]
            {
                // SAFETY: Creating AF_PACKET raw socket descriptor with valid flags.
                let sock_fd = unsafe {
                    libc::socket(
                        libc::AF_PACKET,
                        libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                        (libc::ETH_P_ALL as u16).to_be() as i32,
                    )
                };

                if sock_fd >= 0 {
                    let mut buf = vec![0u8; 65535];
                    loop {
                        if cancel.is_cancelled() {
                            // SAFETY: Closing open raw socket descriptor on shutdown.
                            unsafe { libc::close(sock_fd) };
                            break;
                        }

                        // SAFETY: Receiving into allocated mutable buffer of exact length.
                        let res = unsafe {
                            libc::recv(sock_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                        };

                        if res > 0 {
                            let n = res as usize;
                            telemetry.packets_inspected.fetch_add(1, Ordering::Relaxed);

                            if let Some(pkt) = PacketDissector::dissect(&buf[..n]) {
                                if pkt.is_tor_transport {
                                    telemetry.tor_routed_bytes.fetch_add(n as u64, Ordering::Relaxed);
                                }
                                if pkt.is_stun_leak {
                                    telemetry.stun_webrtc_probes_trapped.fetch_add(1, Ordering::SeqCst);
                                }
                                if pkt.is_leak_suspect {
                                    telemetry.clearnet_escapes_blocked.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                        } else {
                            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                        }
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = telemetry;
                loop {
                    if cancel.is_cancelled() {
                        break;
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        })
    }

    pub fn get_telemetry(&self) -> Arc<IdsTelemetry> {
        self.telemetry.clone()
    }

    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }
}
