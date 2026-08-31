//! Wraith Sovereign Pure-Linux Netlink Kernel Engine (AF_NETLINK / NETLINK_ROUTE)
//! Direct zero-subprocess binary communication with the Linux kernel network subsystem.
//! Implements link management, veth creation, namespace migration, address assignment,
//! FIB routing table injection, policy routing rules, and ARP neighbor table control.

#![allow(unused_imports, unused_variables, dead_code)]

use std::ffi::{CStr, CString};
use std::fmt;
use std::io::{Error, ErrorKind};
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::{debug, error, info, warn};
use wraith_core::error::{Result, WraithError};

// ==============================================================================
// 1. NETLINK PROTOCOL CONSTANTS & MESSAGE TYPES (<linux/netlink.h> & <linux/rtnetlink.h>)
// ==============================================================================

pub const NETLINK_ROUTE: i32 = 0;

// Standard Netlink Message Types
pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_OVERRUN: u16 = 4;

// Routing Table Netlink Message Types (RTM_*)
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;

pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;

pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;

pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;

pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;
pub const RTM_GETRULE: u16 = 34;

// Netlink Message Flags (nlmsg_flags)
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_ECHO: u16 = 0x08;
pub const NLM_F_DUMP_INTR: u16 = 0x10;
pub const NLM_F_DUMP_FILTERED: u16 = 0x20;

// Modifiers to GET request
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_ATOMIC: u16 = 0x400;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

// Modifiers to NEW request
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

// Address Families
pub const AF_UNSPEC: u8 = 0;
pub const AF_UNIX: u8 = 1;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const AF_PACKET: u8 = 17;
pub const AF_NETLINK: i32 = 16;

// Device Link Flags (IFF_*)
pub const IFF_UP: u32 = 1 << 0;
pub const IFF_BROADCAST: u32 = 1 << 1;
pub const IFF_DEBUG: u32 = 1 << 2;
pub const IFF_LOOPBACK: u32 = 1 << 3;
pub const IFF_POINTOPOINT: u32 = 1 << 4;
pub const IFF_NOTRAILERS: u32 = 1 << 5;
pub const IFF_RUNNING: u32 = 1 << 6;
pub const IFF_NOARP: u32 = 1 << 7;
pub const IFF_PROMISC: u32 = 1 << 8;
pub const IFF_ALLMULTI: u32 = 1 << 9;
pub const IFF_MASTER: u32 = 1 << 10;
pub const IFF_SLAVE: u32 = 1 << 11;
pub const IFF_MULTICAST: u32 = 1 << 12;
pub const IFF_PORTSEL: u32 = 1 << 13;
pub const IFF_AUTOMEDIA: u32 = 1 << 14;
pub const IFF_DYNAMIC: u32 = 1 << 15;
pub const IFF_LOWER_UP: u32 = 1 << 16;
pub const IFF_DORMANT: u32 = 1 << 17;
pub const IFF_ECHO: u32 = 1 << 18;

// Link Attributes (IFLA_*)
pub const IFLA_UNSPEC: u16 = 0;
pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_BROADCAST: u16 = 2;
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MTU: u16 = 4;
pub const IFLA_LINK: u16 = 5;
pub const IFLA_QDISC: u16 = 6;
pub const IFLA_STATS: u16 = 7;
pub const IFLA_COST: u16 = 8;
pub const IFLA_PRIORITY: u16 = 9;
pub const IFLA_MASTER: u16 = 10;
pub const IFLA_WIRELESS: u16 = 11;
pub const IFLA_PROTINFO: u16 = 12;
pub const IFLA_TXQLEN: u16 = 13;
pub const IFLA_MAP: u16 = 14;
pub const IFLA_WEIGHT: u16 = 15;
pub const IFLA_OPERSTATE: u16 = 16;
pub const IFLA_LINKMODE: u16 = 17;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_NET_NS_PID: u16 = 19;
pub const IFLA_IFALIAS: u16 = 20;
pub const IFLA_NUM_VF: u16 = 21;
pub const IFLA_VFINFO_LIST: u16 = 22;
pub const IFLA_STATS64: u16 = 23;
pub const IFLA_VF_PORTS: u16 = 24;
pub const IFLA_PORT_SELF: u16 = 25;
pub const IFLA_AF_SPEC: u16 = 26;
pub const IFLA_GROUP: u16 = 27;
pub const IFLA_NET_NS_FD: u16 = 28;
pub const IFLA_EXT_MASK: u16 = 29;
pub const IFLA_PROMISCUITY: u16 = 30;

// Link Info Nested Attributes (IFLA_INFO_*)
pub const IFLA_INFO_UNSPEC: u16 = 0;
pub const IFLA_INFO_KIND: u16 = 1;
pub const IFLA_INFO_DATA: u16 = 2;
pub const IFLA_INFO_XSTATS: u16 = 3;
pub const IFLA_INFO_SLAVE_KIND: u16 = 4;
pub const IFLA_INFO_SLAVE_DATA: u16 = 5;

// VETH Nested Info Attributes (VETH_INFO_*)
pub const VETH_INFO_UNSPEC: u16 = 0;
pub const VETH_INFO_PEER: u16 = 1;

// Address Attributes (IFA_*)
pub const IFA_UNSPEC: u16 = 0;
pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_LABEL: u16 = 3;
pub const IFA_BROADCAST: u16 = 4;
pub const IFA_ANYCAST: u16 = 5;
pub const IFA_CACHEINFO: u16 = 6;
pub const IFA_MULTICAST: u16 = 7;
pub const IFA_FLAGS: u16 = 8;

// Route Attributes (RTA_*)
pub const RTA_UNSPEC: u16 = 0;
pub const RTA_DST: u16 = 1;
pub const RTA_SRC: u16 = 2;
pub const RTA_IIF: u16 = 3;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_PREFSRC: u16 = 7;
pub const RTA_METRICS: u16 = 8;
pub const RTA_MULTIPATH: u16 = 9;
pub const RTA_PROTOINFO: u16 = 10;
pub const RTA_FLOW: u16 = 11;
pub const RTA_CACHEINFO: u16 = 12;
pub const RTA_SESSION: u16 = 13;
pub const RTA_MP_ALGO: u16 = 14;
pub const RTA_TABLE: u16 = 15;
pub const RTA_MARK: u16 = 16;
pub const RTA_MFC_STATS: u16 = 17;
pub const RTA_VIA: u16 = 18;
pub const RTA_NEWDST: u16 = 19;
pub const RTA_PREF: u16 = 20;
pub const RTA_ENCAP_TYPE: u16 = 21;
pub const RTA_ENCAP: u16 = 22;
pub const RTA_EXPIRES: u16 = 23;
pub const RTA_PAD: u16 = 24;
pub const RTA_UID: u16 = 25;
pub const RTA_TTL_PROPAGATE: u16 = 26;
pub const RTA_IP_PROTO: u16 = 27;
pub const RTA_SPORT: u16 = 28;
pub const RTA_DPORT: u16 = 29;

// Route Types (rtm_type)
pub const RTN_UNSPEC: u8 = 0;
pub const RTN_UNICAST: u8 = 1;
pub const RTN_LOCAL: u8 = 2;
pub const RTN_BROADCAST: u8 = 3;
pub const RTN_ANYCAST: u8 = 4;
pub const RTN_MULTICAST: u8 = 5;
pub const RTN_BLACKHOLE: u8 = 6;
pub const RTN_UNREACHABLE: u8 = 7;
pub const RTN_PROHIBIT: u8 = 8;
pub const RTN_THROW: u8 = 9;
pub const RTN_NAT: u8 = 10;
pub const RTN_XRESOLVE: u8 = 11;

// Route Protocol & Scope & Table IDs
pub const RTPROT_UNSPEC: u8 = 0;
pub const RTPROT_REDIRECT: u8 = 1;
pub const RTPROT_KERNEL: u8 = 2;
pub const RTPROT_BOOT: u8 = 3;
pub const RTPROT_STATIC: u8 = 4;

pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_SITE: u8 = 200;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RT_SCOPE_HOST: u8 = 254;
pub const RT_SCOPE_NOWHERE: u8 = 255;

pub const RT_TABLE_UNSPEC: u8 = 0;
pub const RT_TABLE_COMPAT: u8 = 252;
pub const RT_TABLE_DEFAULT: u8 = 253;
pub const RT_TABLE_MAIN: u8 = 254;
pub const RT_TABLE_LOCAL: u8 = 255;

// Routing Rules Attributes (FRA_*)
pub const FRA_UNSPEC: u16 = 0;
pub const FRA_DST: u16 = 1;
pub const FRA_SRC: u16 = 2;
pub const FRA_IIFNAME: u16 = 3;
pub const FRA_GOTO: u16 = 4;
pub const FRA_UNUSED2: u16 = 5;
pub const FRA_PRIORITY: u16 = 6;
pub const FRA_UNUSED3: u16 = 7;
pub const FRA_UNUSED4: u16 = 8;
pub const FRA_UNUSED5: u16 = 9;
pub const FRA_FWMARK: u16 = 10;
pub const FRA_FLOW: u16 = 11;
pub const FRA_TUN_ID: u16 = 12;
pub const FRA_SUPPRESS_IFGROUP: u16 = 13;
pub const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
pub const FRA_TABLE: u16 = 15;
pub const FRA_FWMASK: u16 = 16;
pub const FRA_OIFNAME: u16 = 17;

// Neighbor Table Attributes (NDA_*)
pub const NDA_UNSPEC: u16 = 0;
pub const NDA_DST: u16 = 1;
pub const NDA_LLADDR: u16 = 2;
pub const NDA_CACHEINFO: u16 = 3;
pub const NDA_PROBES: u16 = 4;
pub const NDA_VLAN: u16 = 5;
pub const NDA_PORT: u16 = 6;
pub const NDA_VNI: u16 = 7;
pub const NDA_IFINDEX: u16 = 8;
pub const NDA_MASTER: u16 = 9;
pub const NDA_LINK_NETNSID: u16 = 10;

// Neighbor States (NUD_*)
pub const NUD_INCOMPLETE: u16 = 0x01;
pub const NUD_REACHABLE: u16 = 0x02;
pub const NUD_STALE: u16 = 0x04;
pub const NUD_DELAY: u16 = 0x08;
pub const NUD_PROBE: u16 = 0x10;
pub const NUD_FAILED: u16 = 0x20;
pub const NUD_NOARP: u16 = 0x40;
pub const NUD_PERMANENT: u16 = 0x80;
pub const NUD_NONE: u16 = 0x00;

// ==============================================================================
// 2. NETLINK C STRUCTURE WIRE DEFINITIONS (`repr(C)`)
// ==============================================================================

/// Standard Netlink Message Header (`struct nlmsghdr`)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

/// Netlink Error Message (`struct nlmsgerr`)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlMsgErr {
    pub error: i32, // Negative errno or 0 for ACK
    pub msg: NlMsgHdr,
}

/// Interface Info Message (`struct ifinfomsg`)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IfInfoMsg {
    pub ifi_family: u8,
    pub __ifi_pad: u8,
    pub ifi_type: u16,
    pub ifi_index: i32,
    pub ifi_flags: u32,
    pub ifi_change: u32,
}

/// Interface Address Message (`struct ifaddrmsg`)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IfAddrMsg {
    pub ifa_family: u8,
    pub ifa_prefixlen: u8,
    pub ifa_flags: u8,
    pub ifa_scope: u8,
    pub ifa_index: u32,
}

/// Route Message (`struct rtmsg`)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtMsg {
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,
    pub rtm_table: u8,
    pub rtm_protocol: u8,
    pub rtm_scope: u8,
    pub rtm_type: u8,
    pub rtm_flags: u32,
}

/// Neighbor Message (`struct ndmsg`)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NdMsg {
    pub ndm_family: u8,
    pub __ndm_pad1: u8,
    pub __ndm_pad2: u16,
    pub ndm_ifindex: i32,
    pub ndm_state: u16,
    pub ndm_flags: u8,
    pub ndm_type: u8,
}

/// Netlink Routing Attribute Header (`struct rtattr`)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtAttr {
    pub rta_len: u16,
    pub rta_type: u16,
}

// ==============================================================================
// 3. HIGH-LEVEL STRUCTURES & DATA MODELS
// ==============================================================================

#[derive(Debug, Clone)]
pub struct LinkDetails {
    pub ifindex: i32,
    pub ifname: String,
    pub flags: u32,
    pub is_up: bool,
    pub is_loopback: bool,
    pub mac_address: Option<[u8; 6]>,
    pub mtu: u32,
    pub qdisc: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AddressDetails {
    pub ifindex: u32,
    pub family: u8,
    pub prefix_len: u8,
    pub ip_address: String,
    pub scope: u8,
}

#[derive(Debug, Clone)]
pub struct RouteDetails {
    pub table: u32,
    pub family: u8,
    pub destination: Option<String>,
    pub dst_prefix_len: u8,
    pub gateway: Option<String>,
    pub oif_index: Option<u32>,
    pub priority: Option<u32>,
    pub protocol: u8,
}

#[derive(Debug, Clone)]
pub struct NeighborDetails {
    pub ifindex: i32,
    pub family: u8,
    pub ip: String,
    pub lladdr: Option<[u8; 6]>,
    pub state: u16,
}

// ==============================================================================
// 4. NETLINK ATTRIBUTE ALIGNMENT & SERIALIZATION HELPERS
// ==============================================================================

#[inline]
pub fn rta_align(len: usize) -> usize {
    (len + 3) & !3
}

#[inline]
pub fn rta_length(len: usize) -> usize {
    rta_align(size_of::<RtAttr>()) + len
}

#[inline]
pub fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

// ==============================================================================
// 5. SOVEREIGN NETLINK SOCKET CONTROLLER
// ==============================================================================

pub struct NetlinkSocket {
    #[cfg(unix)]
    fd: i32,
    seq: u32,
    pid: u32,
}

impl NetlinkSocket {
    /// Opens and binds an `AF_NETLINK` (NETLINK_ROUTE) kernel socket descriptor
    pub fn open() -> Result<Self> {
        #[cfg(unix)]
        {
            let fd = unsafe { libc::socket(AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_ROUTE) };
            if fd < 0 {
                return Err(WraithError::Custom(format!(
                    "Failed opening AF_NETLINK socket: {}",
                    Error::last_os_error()
                )));
            }

            // Tune socket buffer for high-throughput link dumping
            let buf_size: libc::c_int = 1024 * 1024; // 1 MB
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &buf_size as *const _ as *const libc::c_void,
                    size_of::<libc::c_int>() as u32,
                );
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &buf_size as *const _ as *const libc::c_void,
                    size_of::<libc::c_int>() as u32,
                );
            }

            let mut sa: libc::sockaddr_nl = unsafe { zeroed() };
            sa.nl_family = AF_NETLINK as u16;
            sa.nl_pid = 0; // Kernel will assign PID
            sa.nl_groups = 0; // Unicast

            let bind_res = unsafe {
                libc::bind(
                    fd,
                    &sa as *const _ as *const libc::sockaddr,
                    size_of::<libc::sockaddr_nl>() as u32,
                )
            };

            if bind_res < 0 {
                unsafe { libc::close(fd) };
                return Err(WraithError::Custom(format!(
                    "Failed binding AF_NETLINK socket: {}",
                    Error::last_os_error()
                )));
            }

            // Fetch assigned PID
            let mut addr_len = size_of::<libc::sockaddr_nl>() as u32;
            let getsock_res = unsafe {
                libc::getsockname(
                    fd,
                    &mut sa as *mut _ as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };
            let assigned_pid = if getsock_res == 0 { sa.nl_pid } else { std::process::id() };

            debug!("AF_NETLINK socket opened successfully (fd: {fd}, pid: {assigned_pid})");

            Ok(Self {
                fd,
                seq: 1,
                pid: assigned_pid,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self { seq: 1, pid: 0 })
        }
    }

    /// Serializes and appends an `rtattr` with payload to an outgoing Netlink message buffer
    pub fn append_attr(buf: &mut Vec<u8>, rta_type: u16, data: &[u8]) {
        let rta_len = (size_of::<RtAttr>() + data.len()) as u16;
        let attr = RtAttr { rta_len, rta_type };

        unsafe {
            let attr_slice = std::slice::from_raw_parts(
                &attr as *const _ as *const u8,
                size_of::<RtAttr>(),
            );
            buf.extend_from_slice(attr_slice);
        }

        buf.extend_from_slice(data);

        // Pad to 4-byte boundary
        let pad = rta_align(data.len()) - data.len();
        for _ in 0..pad {
            buf.push(0);
        }
    }

    /// Starts a nested `rtattr` container, returning the offset where length must be updated later
    pub fn start_nested_attr(buf: &mut Vec<u8>, rta_type: u16) -> usize {
        let offset = buf.len();
        let attr = RtAttr {
            rta_len: 0, // Placeholder
            rta_type: rta_type | 0x8000, // NLA_F_NESTED flag
        };
        unsafe {
            let attr_slice = std::slice::from_raw_parts(
                &attr as *const _ as *const u8,
                size_of::<RtAttr>(),
            );
            buf.extend_from_slice(attr_slice);
        }
        offset
    }

    /// Closes a nested `rtattr` container by updating its length header
    pub fn end_nested_attr(buf: &mut [u8], offset: usize) {
        let total_len = (buf.len() - offset) as u16;
        buf[offset..offset + 2].copy_from_slice(&total_len.to_le_bytes());
    }

    /// Appends a string attribute (null-terminated string)
    pub fn append_attr_str(buf: &mut Vec<u8>, rta_type: u16, s: &str) {
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0); // C-string terminator
        Self::append_attr(buf, rta_type, &bytes);
    }

    /// Appends a 32-bit integer attribute
    pub fn append_attr_u32(buf: &mut Vec<u8>, rta_type: u16, val: u32) {
        Self::append_attr(buf, rta_type, &val.to_ne_bytes());
    }

    /// Appends a 16-bit integer attribute
    pub fn append_attr_u16(buf: &mut Vec<u8>, rta_type: u16, val: u16) {
        Self::append_attr(buf, rta_type, &val.to_ne_bytes());
    }

    /// Appends an 8-bit integer attribute
    pub fn append_attr_u8(buf: &mut Vec<u8>, rta_type: u16, val: u8) {
        Self::append_attr(buf, rta_type, &[val]);
    }

    /// Sends a Netlink request buffer and validates kernel ACK response
    pub fn send_and_recv_ack(&mut self, buf: &[u8]) -> Result<()> {
        #[cfg(unix)]
        {
            let send_res = unsafe {
                libc::send(
                    self.fd,
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                    0,
                )
            };

            if send_res < 0 {
                return Err(WraithError::Custom(format!(
                    "Failed sending Netlink frame: {}",
                    Error::last_os_error()
                )));
            }

            self.seq += 1;

            let mut resp_buf = vec![0u8; 4096];
            let recv_res = unsafe {
                libc::recv(
                    self.fd,
                    resp_buf.as_mut_ptr() as *mut libc::c_void,
                    resp_buf.len(),
                    0,
                )
            };

            if recv_res < 0 {
                return Err(WraithError::Custom(format!(
                    "Failed receiving Netlink ACK: {}",
                    Error::last_os_error()
                )));
            }

            let bytes_read = recv_res as usize;
            if bytes_read < size_of::<NlMsgHdr>() {
                return Err(WraithError::Custom("Truncated Netlink response".into()));
            }

            let nl_hdr: NlMsgHdr = unsafe { std::ptr::read_unaligned(resp_buf.as_ptr() as *const _) };

            if nl_hdr.nlmsg_type == NLMSG_ERROR {
                if bytes_read < size_of::<NlMsgErr>() {
                    return Err(WraithError::Custom("Truncated NLMSG_ERROR payload".into()));
                }
                let err_msg: NlMsgErr = unsafe { std::ptr::read_unaligned(resp_buf.as_ptr() as *const _) };
                if err_msg.error != 0 {
                    let os_err = Error::from_raw_os_error(-err_msg.error);
                    return Err(WraithError::Custom(format!(
                        "Netlink kernel execution error: {} (code {})",
                        os_err, -err_msg.error
                    )));
                }
            }

            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = buf;
            Ok(())
        }
    }

    /// Sends a multi-part dump request and collects all response frames until `NLMSG_DONE`
    pub fn send_dump_request(&mut self, msg_type: u16, family: u8) -> Result<Vec<Vec<u8>>> {
        #[cfg(unix)]
        {
            let mut req_buf = Vec::with_capacity(size_of::<NlMsgHdr>() + size_of::<IfInfoMsg>());

            let hdr = NlMsgHdr {
                nlmsg_len: (size_of::<NlMsgHdr>() + size_of::<IfInfoMsg>()) as u32,
                nlmsg_type: msg_type,
                nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
                nlmsg_seq: self.seq,
                nlmsg_pid: 0,
            };

            let ifinfo = IfInfoMsg {
                ifi_family: family,
                __ifi_pad: 0,
                ifi_type: 0,
                ifi_index: 0,
                ifi_flags: 0,
                ifi_change: 0,
            };

            unsafe {
                let hdr_slice = std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>());
                req_buf.extend_from_slice(hdr_slice);
                let ifinfo_slice = std::slice::from_raw_parts(&ifinfo as *const _ as *const u8, size_of::<IfInfoMsg>());
                req_buf.extend_from_slice(ifinfo_slice);
            }

            let send_res = unsafe {
                libc::send(self.fd, req_buf.as_ptr() as *const libc::c_void, req_buf.len(), 0)
            };

            if send_res < 0 {
                return Err(WraithError::Custom(format!("Dump send failed: {}", Error::last_os_error())));
            }

            self.seq += 1;

            let mut frames = Vec::new();
            let mut recv_buf = vec![0u8; 16384];

            'dump_loop: loop {
                let recv_res = unsafe {
                    libc::recv(self.fd, recv_buf.as_mut_ptr() as *mut libc::c_void, recv_buf.len(), 0)
                };

                if recv_res < 0 {
                    return Err(WraithError::Custom(format!("Dump recv failed: {}", Error::last_os_error())));
                }

                let bytes_read = recv_res as usize;
                let mut offset = 0;

                while offset + size_of::<NlMsgHdr>() <= bytes_read {
                    let nl_hdr: NlMsgHdr = unsafe { std::ptr::read_unaligned(recv_buf[offset..].as_ptr() as *const _) };
                    let msg_len = nl_hdr.nlmsg_len as usize;

                    if msg_len < size_of::<NlMsgHdr>() || offset + msg_len > bytes_read {
                        break;
                    }

                    if nl_hdr.nlmsg_type == NLMSG_DONE {
                        break 'dump_loop;
                    }

                    if nl_hdr.nlmsg_type == NLMSG_ERROR {
                        let err_msg: NlMsgErr = unsafe { std::ptr::read_unaligned(recv_buf[offset..].as_ptr() as *const _) };
                        if err_msg.error != 0 {
                            return Err(WraithError::Custom(format!("Dump error: {}", -err_msg.error)));
                        }
                    }

                    frames.push(recv_buf[offset..offset + msg_len].to_vec());
                    offset += nlmsg_align(msg_len);
                }
            }

            Ok(frames)
        }
        #[cfg(not(unix))]
        {
            let _ = (msg_type, family);
            Ok(Vec::new())
        }
    }

    /// Resolves an interface name string to its Linux kernel numeric index (`ifindex`)
    pub fn get_ifindex(ifname: &str) -> Result<i32> {
        #[cfg(unix)]
        {
            let c_str = CString::new(ifname).map_err(|e| WraithError::Custom(e.to_string()))?;
            let idx = unsafe { libc::if_nametoindex(c_str.as_ptr()) };
            if idx == 0 {
                return Err(WraithError::Custom(format!("Interface '{ifname}' does not exist")));
            }
            Ok(idx as i32)
        }
        #[cfg(not(unix))]
        {
            let _ = ifname;
            Ok(1)
        }
    }

    // ==============================================================================
    // 6. LINK & INTERFACE OPERATIONS (RTM_NEWLINK / RTM_DELLINK / RTM_GETLINK)
    // ==============================================================================

    /// Sets interface administrative state (UP / DOWN)
    pub fn set_link_state(&mut self, ifname: &str, up: bool) -> Result<()> {
        let ifindex = Self::get_ifindex(ifname)?;
        let mut msg_buf = Vec::with_capacity(128);

        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: RTM_NEWLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };

        let ifinfo = IfInfoMsg {
            ifi_family: AF_UNSPEC,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: ifindex,
            ifi_flags: if up { IFF_UP } else { 0 },
            ifi_change: IFF_UP,
        };

        unsafe {
            let hdr_slice = std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>());
            msg_buf.extend_from_slice(hdr_slice);
            let ifinfo_slice = std::slice::from_raw_parts(&ifinfo as *const _ as *const u8, size_of::<IfInfoMsg>());
            msg_buf.extend_from_slice(ifinfo_slice);
        }

        let total_len = msg_buf.len() as u32;
        msg_buf[0..4].copy_from_slice(&total_len.to_le_bytes());

        self.send_and_recv_ack(&msg_buf)?;
        info!("Kernel Netlink: Interface {ifname} state set to {}", if up { "UP" } else { "DOWN" });
        Ok(())
    }

    /// Sets interface MTU
    pub fn set_link_mtu(&mut self, ifname: &str, mtu: u32) -> Result<()> {
        let ifindex = Self::get_ifindex(ifname)?;
        let mut msg_buf = Vec::with_capacity(128);

        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: RTM_NEWLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };

        let ifinfo = IfInfoMsg {
            ifi_family: AF_UNSPEC,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: ifindex,
            ifi_flags: 0,
            ifi_change: 0,
        };

        unsafe {
            let hdr_slice = std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>());
            msg_buf.extend_from_slice(hdr_slice);
            let ifinfo_slice = std::slice::from_raw_parts(&ifinfo as *const _ as *const u8, size_of::<IfInfoMsg>());
            msg_buf.extend_from_slice(ifinfo_slice);
        }

        Self::append_attr_u32(&mut msg_buf, IFLA_MTU, mtu);

        let total_len = msg_buf.len() as u32;
        msg_buf[0..4].copy_from_slice(&total_len.to_le_bytes());

        self.send_and_recv_ack(&msg_buf)?;
        info!("Kernel Netlink: MTU for {ifname} set to {mtu}");
        Ok(())
    }

    /// Spoofs hardware MAC address on interface via binary Netlink RTM_NEWLINK (IFLA_ADDRESS)
    pub fn set_link_mac(&mut self, ifname: &str, mac_bytes: &[u8; 6]) -> Result<()> {
        let ifindex = Self::get_ifindex(ifname)?;
        let mut msg_buf = Vec::with_capacity(128);

        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: RTM_NEWLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };

        let ifinfo = IfInfoMsg {
            ifi_family: AF_UNSPEC,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: ifindex,
            ifi_flags: 0,
            ifi_change: 0,
        };

        unsafe {
            let hdr_slice = std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>());
            msg_buf.extend_from_slice(hdr_slice);
            let ifinfo_slice = std::slice::from_raw_parts(&ifinfo as *const _ as *const u8, size_of::<IfInfoMsg>());
            msg_buf.extend_from_slice(ifinfo_slice);
        }

        Self::append_attr(&mut msg_buf, IFLA_ADDRESS, mac_bytes);

        let total_len = msg_buf.len() as u32;
        msg_buf[0..4].copy_from_slice(&total_len.to_le_bytes());

        self.send_and_recv_ack(&msg_buf)?;
        info!("Kernel Netlink: Injected L2 MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} into {ifname}",
            mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        Ok(())
    }

    /// Migrates a network interface into a target Linux network namespace FD
    pub fn set_link_netns(&mut self, ifname: &str, netns_fd: i32) -> Result<()> {
        let ifindex = Self::get_ifindex(ifname)?;
        let mut msg_buf = Vec::with_capacity(128);

        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: RTM_NEWLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };

        let ifinfo = IfInfoMsg {
            ifi_family: AF_UNSPEC,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: ifindex,
            ifi_flags: 0,
            ifi_change: 0,
        };

        unsafe {
            let hdr_slice = std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>());
            msg_buf.extend_from_slice(hdr_slice);
            let ifinfo_slice = std::slice::from_raw_parts(&ifinfo as *const _ as *const u8, size_of::<IfInfoMsg>());
            msg_buf.extend_from_slice(ifinfo_slice);
        }

        Self::append_attr_u32(&mut msg_buf, IFLA_NET_NS_FD, netns_fd as u32);

        let total_len = msg_buf.len() as u32;
        msg_buf[0..4].copy_from_slice(&total_len.to_le_bytes());

        self.send_and_recv_ack(&msg_buf)?;
        info!("Kernel Netlink: Migrated interface {ifname} into NetNS (fd: {netns_fd})");
        Ok(())
    }

    /// Creates a virtual Ethernet pair (`veth`) completely in kernel space
    pub fn create_veth_pair(&mut self, host_ifname: &str, peer_ifname: &str) -> Result<()> {
        let mut msg_buf = Vec::with_capacity(256);

        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: RTM_NEWLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };

        let ifinfo = IfInfoMsg {
            ifi_family: AF_UNSPEC,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: 0,
            ifi_flags: 0,
            ifi_change: 0,
        };

        unsafe {
            let hdr_slice = std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>());
            msg_buf.extend_from_slice(hdr_slice);
            let ifinfo_slice = std::slice::from_raw_parts(&ifinfo as *const _ as *const u8, size_of::<IfInfoMsg>());
            msg_buf.extend_from_slice(ifinfo_slice);
        }

        Self::append_attr_str(&mut msg_buf, IFLA_IFNAME, host_ifname);

        // IFLA_LINKINFO container
        let linkinfo_offset = Self::start_nested_attr(&mut msg_buf, IFLA_LINKINFO);
        Self::append_attr_str(&mut msg_buf, IFLA_INFO_KIND, "veth");

        // IFLA_INFO_DATA container
        let infodata_offset = Self::start_nested_attr(&mut msg_buf, IFLA_INFO_DATA);

        // VETH_INFO_PEER container
        let peer_offset = Self::start_nested_attr(&mut msg_buf, VETH_INFO_PEER);
        let peer_ifinfo = IfInfoMsg {
            ifi_family: AF_UNSPEC,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: 0,
            ifi_flags: 0,
            ifi_change: 0,
        };
        unsafe {
            let p_slice = std::slice::from_raw_parts(&peer_ifinfo as *const _ as *const u8, size_of::<IfInfoMsg>());
            msg_buf.extend_from_slice(p_slice);
        }
        Self::append_attr_str(&mut msg_buf, IFLA_IFNAME, peer_ifname);

        Self::end_nested_attr(&mut msg_buf, peer_offset);
        Self::end_nested_attr(&mut msg_buf, infodata_offset);
        Self::end_nested_attr(&mut msg_buf, linkinfo_offset);

        let total_len = msg_buf.len() as u32;
        msg_buf[0..4].copy_from_slice(&total_len.to_le_bytes());

        self.send_and_recv_ack(&msg_buf)?;
        info!("Kernel Netlink: Created veth pair '{host_ifname}' <-> '{peer_ifname}'");
        Ok(())
    }

    /// Deletes a virtual link or interface via RTM_DELLINK
    pub fn delete_link(&mut self, ifname: &str) -> Result<()> {
        let ifindex = Self::get_ifindex(ifname)?;
        let mut msg_buf = Vec::with_capacity(128);

        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: RTM_DELLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };

        let ifinfo = IfInfoMsg {
            ifi_family: AF_UNSPEC,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: ifindex,
            ifi_flags: 0,
            ifi_change: 0,
        };

        unsafe {
            let hdr_slice = std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>());
            msg_buf.extend_from_slice(hdr_slice);
            let ifinfo_slice = std::slice::from_raw_parts(&ifinfo as *const _ as *const u8, size_of::<IfInfoMsg>());
            msg_buf.extend_from_slice(ifinfo_slice);
        }

        let total_len = msg_buf.len() as u32;
        msg_buf[0..4].copy_from_slice(&total_len.to_le_bytes());

        self.send_and_recv_ack(&msg_buf)?;
        info!("Kernel Netlink: Deleted interface '{ifname}'");
        Ok(())
    }

    /// Dumps all network interfaces from kernel FIB
    pub fn dump_links(&mut self) -> Result<Vec<LinkDetails>> {
        let frames = self.send_dump_request(RTM_GETLINK, AF_UNSPEC)?;
        let mut links = Vec::new();

        for frame in frames {
            if frame.len() < size_of::<NlMsgHdr>() + size_of::<IfInfoMsg>() {
                continue;
            }

            let ifinfo_offset = size_of::<NlMsgHdr>();
            let ifinfo: IfInfoMsg = unsafe { std::ptr::read_unaligned(frame[ifinfo_offset..].as_ptr() as *const _) };

            let mut ifname = String::new();
            let mut mac_address = None;
            let mut mtu = 0;
            let mut qdisc = None;

            let mut offset = ifinfo_offset + size_of::<IfInfoMsg>();
            while offset + size_of::<RtAttr>() <= frame.len() {
                let attr: RtAttr = unsafe { std::ptr::read_unaligned(frame[offset..].as_ptr() as *const _) };
                let attr_len = attr.rta_len as usize;
                if attr_len < size_of::<RtAttr>() || offset + attr_len > frame.len() {
                    break;
                }

                let payload = &frame[offset + size_of::<RtAttr>()..offset + attr_len];
                match attr.rta_type {
                    IFLA_IFNAME => {
                        if let Ok(c_str) = CStr::from_bytes_until_nul(payload) {
                            ifname = c_str.to_string_lossy().to_string();
                        }
                    }
                    IFLA_ADDRESS => {
                        if payload.len() == 6 {
                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(payload);
                            mac_address = Some(mac);
                        }
                    }
                    IFLA_MTU => {
                        if payload.len() >= 4 {
                            mtu = u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        }
                    }
                    IFLA_QDISC => {
                        if let Ok(c_str) = CStr::from_bytes_until_nul(payload) {
                            qdisc = Some(c_str.to_string_lossy().to_string());
                        }
                    }
                    _ => {}
                }

                offset += rta_align(attr_len);
            }

            if !ifname.is_empty() {
                links.push(LinkDetails {
                    ifindex: ifinfo.ifi_index,
                    ifname,
                    flags: ifinfo.ifi_flags,
                    is_up: (ifinfo.ifi_flags & IFF_UP) != 0,
                    is_loopback: (ifinfo.ifi_flags & IFF_LOOPBACK) != 0,
                    mac_address,
                    mtu,
                    qdisc,
                });
            }
        }

        Ok(links)
    }

    // ==============================================================================
    // 7. ADDRESS OPERATIONS (RTM_NEWADDR / RTM_DELADDR / RTM_GETADDR)
    // ==============================================================================

    /// Assigns an IPv4 address and subnet mask prefix to an interface via RTM_NEWADDR
    pub fn add_ipv4_address(&mut self, ifname: &str, ip: Ipv4Addr, prefix_len: u8) -> Result<()> {
        let ifindex = Self::get_ifindex(ifname)?;
        let mut msg_buf = Vec::with_capacity(128);

        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: RTM_NEWADDR,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };

        let ifaddr = IfAddrMsg {
            ifa_family: AF_INET,
            ifa_prefixlen: prefix_len,
            ifa_flags: 0,
            ifa_scope: RT_SCOPE_UNIVERSE,
            ifa_index: ifindex as u32,
        };

        unsafe {
            let hdr_slice = std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>());
            msg_buf.extend_from_slice(hdr_slice);
            let ifaddr_slice = std::slice::from_raw_parts(&ifaddr as *const _ as *const u8, size_of::<IfAddrMsg>());
            msg_buf.extend_from_slice(ifaddr_slice);
        }

        let ip_octets = ip.octets();
        Self::append_attr(&mut msg_buf, IFA_LOCAL, &ip_octets);
        Self::append_attr(&mut msg_buf, IFA_ADDRESS, &ip_octets);

        let total_len = msg_buf.len() as u32;
        msg_buf[0..4].copy_from_slice(&total_len.to_le_bytes());

        self.send_and_recv_ack(&msg_buf)?;
        info!("Kernel Netlink: Bound IPv4 {ip}/{prefix_len} to {ifname} (ifindex {ifindex})");
        Ok(())
    }

    /// Deletes an assigned IPv4 address from an interface via RTM_DELADDR
    pub fn del_ipv4_address(&mut self, ifname: &str, ip: Ipv4Addr, prefix_len: u8) -> Result<()> {
        let ifindex = Self::get_ifindex(ifname)?;
        let mut msg_buf = Vec::with_capacity(128);

        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: RTM_DELADDR,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };

        let ifaddr = IfAddrMsg {
            ifa_family: AF_INET,
            ifa_prefixlen: prefix_len,
            ifa_flags: 0,
            ifa_scope: RT_SCOPE_UNIVERSE,
            ifa_index: ifindex as u32,
        };

        unsafe {
            let hdr_slice = std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>());
            msg_buf.extend_from_slice(hdr_slice);
            let ifaddr_slice = std::slice::from_raw_parts(&ifaddr as *const _ as *const u8, size_of::<IfAddrMsg>());
            msg_buf.extend_from_slice(ifaddr_slice);
        }

        let ip_octets = ip.octets();
        Self::append_attr(&mut msg_buf, IFA_LOCAL, &ip_octets);
        Self::append_attr(&mut msg_buf, IFA_ADDRESS, &ip_octets);

        let total_len = msg_buf.len() as u32;
        msg_buf[0..4].copy_from_slice(&total_len.to_le_bytes());

        self.send_and_recv_ack(&msg_buf)?;
        info!("Kernel Netlink: Removed IPv4 {ip}/{prefix_len} from {ifname}");
        Ok(())
    }

    // ==============================================================================
    // 8. FIB ROUTING TABLE OPERATIONS (RTM_NEWROUTE / RTM_DELROUTE / RTM_GETROUTE)
    // ==============================================================================

    /// Injects an IPv4 Default Gateway Route into the Linux routing table via RTM_NEWROUTE
    pub fn add_default_route(&mut self, gateway: Ipv4Addr, oif_name: &str) -> Result<()> {
        let oif_index = Self::get_ifindex(oif_name)?;
        let mut msg_buf = Vec::with_capacity(128);

        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: RTM_NEWROUTE,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };

        let rtmsg = RtMsg {
            rtm_family: AF_INET,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: RT_TABLE_MAIN,
            rtm_protocol: RTPROT_BOOT,
            rtm_scope: RT_SCOPE_UNIVERSE,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };

        unsafe {
            let hdr_slice = std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>());
            msg_buf.extend_from_slice(hdr_slice);
            let rtmsg_slice = std::slice::from_raw_parts(&rtmsg as *const _ as *const u8, size_of::<RtMsg>());
            msg_buf.extend_from_slice(rtmsg_slice);
        }

        let gw_octets = gateway.octets();
        Self::append_attr(&mut msg_buf, RTA_GATEWAY, &gw_octets);
        Self::append_attr_u32(&mut msg_buf, RTA_OIF, oif_index as u32);

        let total_len = msg_buf.len() as u32;
        msg_buf[0..4].copy_from_slice(&total_len.to_le_bytes());

        self.send_and_recv_ack(&msg_buf)?;
        info!("Kernel Netlink: Injected IPv4 Default Gateway 0.0.0.0/0 via {gateway} dev {oif_name}");
        Ok(())
    }

    /// Injects a Subnet Route into a specific Routing Table
    pub fn add_subnet_route(
        &mut self,
        dst_subnet: Ipv4Addr,
        prefix_len: u8,
        gateway: Option<Ipv4Addr>,
        oif_name: &str,
        table_id: u8,
    ) -> Result<()> {
        let oif_index = Self::get_ifindex(oif_name)?;
        let mut msg_buf = Vec::with_capacity(128);

        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: RTM_NEWROUTE,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };

        let rtmsg = RtMsg {
            rtm_family: AF_INET,
            rtm_dst_len: prefix_len,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: table_id,
            rtm_protocol: RTPROT_STATIC,
            rtm_scope: if gateway.is_some() { RT_SCOPE_UNIVERSE } else { RT_SCOPE_LINK },
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };

        unsafe {
            let hdr_slice = std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>());
            msg_buf.extend_from_slice(hdr_slice);
            let rtmsg_slice = std::slice::from_raw_parts(&rtmsg as *const _ as *const u8, size_of::<RtMsg>());
            msg_buf.extend_from_slice(rtmsg_slice);
        }

        let dst_octets = dst_subnet.octets();
        Self::append_attr(&mut msg_buf, RTA_DST, &dst_octets);
        Self::append_attr_u32(&mut msg_buf, RTA_OIF, oif_index as u32);

        if let Some(gw) = gateway {
            let gw_octets = gw.octets();
            Self::append_attr(&mut msg_buf, RTA_GATEWAY, &gw_octets);
        }

        let total_len = msg_buf.len() as u32;
        msg_buf[0..4].copy_from_slice(&total_len.to_le_bytes());

        self.send_and_recv_ack(&msg_buf)?;
        info!("Kernel Netlink: Injected route {dst_subnet}/{prefix_len} table {table_id} dev {oif_name}");
        Ok(())
    }

    // ==============================================================================
    // 9. POLICY ROUTING RULES (RTM_NEWRULE / RTM_DELRULE)
    // ==============================================================================

    /// Adds a policy routing rule to direct firewall-marked (fwmark) packets to a specific routing table
    pub fn add_fwmark_rule(&mut self, fwmark: u32, table_id: u32, priority: u32) -> Result<()> {
        let mut msg_buf = Vec::with_capacity(128);

        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: RTM_NEWRULE,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };

        let rtmsg = RtMsg {
            rtm_family: AF_INET,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: if table_id < 256 { table_id as u8 } else { RT_TABLE_UNSPEC },
            rtm_protocol: RTPROT_STATIC,
            rtm_scope: RT_SCOPE_UNIVERSE,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };

        unsafe {
            let hdr_slice = std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>());
            msg_buf.extend_from_slice(hdr_slice);
            let rtmsg_slice = std::slice::from_raw_parts(&rtmsg as *const _ as *const u8, size_of::<RtMsg>());
            msg_buf.extend_from_slice(rtmsg_slice);
        }

        Self::append_attr_u32(&mut msg_buf, FRA_FWMARK, fwmark);
        Self::append_attr_u32(&mut msg_buf, FRA_PRIORITY, priority);
        Self::append_attr_u32(&mut msg_buf, FRA_TABLE, table_id);

        let total_len = msg_buf.len() as u32;
        msg_buf[0..4].copy_from_slice(&total_len.to_le_bytes());

        self.send_and_recv_ack(&msg_buf)?;
        info!("Kernel Netlink: Injected Policy Routing Rule fwmark 0x{fwmark:x} -> Table {table_id} (prio {priority})");
        Ok(())
    }

    // ==============================================================================
    // 10. NEIGHBOR / ARP MANAGEMENT (RTM_NEWNEIGH / RTM_DELNEIGH)
    // ==============================================================================

    /// Adds a static ARP neighbor mapping into the kernel neighbor cache via RTM_NEWNEIGH
    pub fn add_static_neighbor(&mut self, ifname: &str, ip: Ipv4Addr, mac: &[u8; 6]) -> Result<()> {
        let ifindex = Self::get_ifindex(ifname)?;
        let mut msg_buf = Vec::with_capacity(128);

        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: RTM_NEWNEIGH,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };

        let ndm = NdMsg {
            ndm_family: AF_INET,
            __ndm_pad1: 0,
            __ndm_pad2: 0,
            ndm_ifindex: ifindex,
            ndm_state: NUD_PERMANENT,
            ndm_flags: 0,
            ndm_type: RTN_UNICAST,
        };

        unsafe {
            let hdr_slice = std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>());
            msg_buf.extend_from_slice(hdr_slice);
            let ndm_slice = std::slice::from_raw_parts(&ndm as *const _ as *const u8, size_of::<NdMsg>());
            msg_buf.extend_from_slice(ndm_slice);
        }

        let ip_octets = ip.octets();
        Self::append_attr(&mut msg_buf, NDA_DST, &ip_octets);
        Self::append_attr(&mut msg_buf, NDA_LLADDR, mac);

        let total_len = msg_buf.len() as u32;
        msg_buf[0..4].copy_from_slice(&total_len.to_le_bytes());

        self.send_and_recv_ack(&msg_buf)?;
        info!("Kernel Netlink: Bound static ARP neighbor {ip} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} on {ifname}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        Ok(())
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            if self.fd >= 0 {
                unsafe { libc::close(self.fd) };
                debug!("Closed Netlink socket descriptor {}", self.fd);
            }
        }
    }
}
