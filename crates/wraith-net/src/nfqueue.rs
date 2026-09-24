//! Minimal NFQUEUE transport using owned, close-on-exec netlink sockets.
//! All wire fields are decoded from checked slices, without pointer casts.

use std::io;

const CONFIG: u16 = 0x0302;
const PACKET: u16 = 0x0300;
const VERDICT: u16 = 0x0301;
const NL_ERROR: u16 = 2;
pub(crate) const MAX_PAYLOAD: usize = 65531;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid NFQUEUE netlink message",
    )
}
fn align(length: usize) -> usize {
    (length + 3) & !3
}

fn attribute(kind: u16, payload: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(payload.len() + 4).map_err(|_| invalid())?;
    let mut output = Vec::with_capacity(align(usize::from(length)));
    output.extend_from_slice(&length.to_ne_bytes());
    output.extend_from_slice(&kind.to_ne_bytes());
    output.extend_from_slice(payload);
    output.resize(align(output.len()), 0);
    Ok(output)
}

fn request(
    kind: u16,
    queue: u16,
    seq: u32,
    peer: u32,
    ack: bool,
    attributes: &[Vec<u8>],
) -> Vec<u8> {
    let mut output = vec![0u8; 16];
    output[4..6].copy_from_slice(&kind.to_ne_bytes());
    output[6..8].copy_from_slice(&(if ack { 5u16 } else { 1u16 }).to_ne_bytes());
    output[8..12].copy_from_slice(&seq.to_ne_bytes());
    output[12..16].copy_from_slice(&peer.to_ne_bytes());
    output.extend_from_slice(&[if kind == PACKET { 2 } else { 0 }, 0]); // AF_INET packets, AF_UNSPEC control.
    output.extend_from_slice(&queue.to_be_bytes());
    for bytes in attributes {
        output.extend_from_slice(bytes);
    }
    let length = output.len() as u32;
    output[..4].copy_from_slice(&length.to_ne_bytes());
    output
}

fn frames(mut bytes: &[u8]) -> io::Result<Vec<(u16, u32, &[u8])>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(invalid());
        }
        let length = u32::from_ne_bytes(bytes[..4].try_into().map_err(|_| invalid())?) as usize;
        if length < 16 || length > bytes.len() {
            return Err(invalid());
        }
        let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
        let seq = u32::from_ne_bytes(bytes[8..12].try_into().map_err(|_| invalid())?);
        result.push((kind, seq, &bytes[16..length]));
        let consumed = if length == bytes.len() {
            length
        } else {
            align(length)
        };
        bytes = bytes.get(consumed..).ok_or_else(invalid)?;
    }
    Ok(result)
}

fn attributes(mut bytes: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(invalid());
        }
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        if length < 4 || length > bytes.len() {
            return Err(invalid());
        }
        result.push((
            u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff,
            &bytes[4..length],
        ));
        let consumed = if length == bytes.len() {
            length
        } else {
            align(length)
        };
        bytes = bytes.get(consumed..).ok_or_else(invalid)?;
    }
    Ok(result)
}

#[derive(Debug)]
pub(crate) struct Message {
    pub id: u32,
    pub queue: u16,
    pub hook: u8,
    pub uid: Option<u32>,
    pub original_len: usize,
    pub payload: Vec<u8>,
    pub checksum_ready: bool,
    pub gso: bool,
}

fn parse_packet(bytes: &[u8]) -> io::Result<Message> {
    if bytes.len() < 4 || bytes[0] != 2 || bytes[1] != 0 {
        return Err(invalid());
    }
    let mut header = None;
    let mut payload = None;
    let mut uid = None;
    let mut cap_len = None;
    let mut skb_info = None;
    for (kind, data) in attributes(&bytes[4..])? {
        let number = || -> io::Result<u32> {
            Ok(u32::from_be_bytes(data.try_into().map_err(|_| invalid())?))
        };
        let duplicate = match kind {
            1 => {
                if data.len() != 7 || data[4..6] != [0x08, 0] {
                    return Err(invalid());
                }
                header
                    .replace((
                        u32::from_be_bytes(data[..4].try_into().map_err(|_| invalid())?),
                        data[6],
                    ))
                    .is_some()
            }
            10 => payload.replace(data.to_vec()).is_some(),
            13 => cap_len.replace(number()? as usize).is_some(),
            14 => skb_info.replace(number()?).is_some(),
            16 => uid.replace(number()?).is_some(),
            _ => false,
        };
        if duplicate {
            return Err(invalid());
        }
    }
    let (id, hook) = header.ok_or_else(invalid)?;
    let payload = payload.ok_or_else(invalid)?;
    Ok(Message {
        id,
        queue: u16::from_be_bytes([bytes[2], bytes[3]]),
        hook,
        uid,
        original_len: cap_len.unwrap_or(payload.len()),
        payload,
        checksum_ready: skb_info.unwrap_or(0) & 1 == 0,
        gso: skb_info.unwrap_or(0) & 2 != 0,
    })
}

fn check_ack(bytes: &[u8], expected_seq: u32) -> io::Result<()> {
    let frames = frames(bytes)?;
    if frames.len() != 1
        || frames[0].0 != NL_ERROR
        || frames[0].1 != expected_seq
        || frames[0].2.len() < 4
    {
        return Err(invalid());
    }
    let errno = i32::from_ne_bytes(frames[0].2[..4].try_into().map_err(|_| invalid())?);
    if errno == 0 {
        Ok(())
    } else if errno < 0 {
        Err(io::Error::from_raw_os_error(
            errno.checked_neg().ok_or_else(invalid)?,
        ))
    } else {
        Err(invalid())
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct Queue {
    socket: std::os::fd::OwnedFd,
    pub peer_portid: u32,
    queue_num: u16,
    pending: std::collections::VecDeque<Message>,
    buffer: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl Queue {
    pub fn bind(queue_num: u16) -> io::Result<Self> {
        use nix::sys::socket::{
            bind, getsockname, setsockopt, socket, sockopt, AddressFamily, NetlinkAddr, SockFlag,
            SockProtocol, SockType,
        };
        use nix::sys::time::TimeVal;
        use std::os::fd::AsRawFd;
        let socket = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkNetFilter,
        )?;
        bind(socket.as_raw_fd(), &NetlinkAddr::new(0, 0))?;
        let peer_portid = getsockname::<NetlinkAddr>(socket.as_raw_fd())?.pid();
        setsockopt(&socket, sockopt::ReceiveTimeout, &TimeVal::new(5, 0))?;
        setsockopt(&socket, sockopt::SendTimeout, &TimeVal::new(5, 0))?;
        let mut queue = Self {
            socket,
            peer_portid,
            queue_num,
            pending: Default::default(),
            buffer: vec![0; 131072],
        };
        // Queue binding is exclusive; never unbind someone else's queue first.
        queue.configure(1, &[attribute(1, &[1, 0, 0, 0])?])?;
        let mut params = (MAX_PAYLOAD as u32).to_be_bytes().to_vec();
        params.push(2); // NFQNL_COPY_PACKET
        queue.configure(
            2,
            &[
                attribute(2, &params)?,
                attribute(3, &1024u32.to_be_bytes())?,
                attribute(4, &(1u32 | 4 | 8).to_be_bytes())?, // FAIL_OPEN, GSO, UID_GID
                attribute(5, &8u32.to_be_bytes())?, // UID_GID only: fail-closed, complete checksums
            ],
        )?;
        use nix::fcntl::{fcntl, FcntlArg, OFlag};
        let flags = OFlag::from_bits_retain(fcntl(queue.socket.as_raw_fd(), FcntlArg::F_GETFL)?);
        fcntl(
            queue.socket.as_raw_fd(),
            FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK),
        )?;
        Ok(queue)
    }

    fn configure(&mut self, seq: u32, attributes: &[Vec<u8>]) -> io::Result<()> {
        self.send(&request(
            CONFIG,
            self.queue_num,
            seq,
            self.peer_portid,
            true,
            attributes,
        ))?;
        let length = self.receive_datagram()?;
        check_ack(&self.buffer[..length], seq)
    }

    fn send(&self, bytes: &[u8]) -> io::Result<()> {
        use nix::sys::socket::{sendto, MsgFlags, NetlinkAddr};
        use std::os::fd::AsRawFd;
        let count = sendto(
            self.socket.as_raw_fd(),
            bytes,
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )?;
        if count == bytes.len() {
            Ok(())
        } else {
            Err(io::ErrorKind::WriteZero.into())
        }
    }

    fn receive_datagram(&mut self) -> io::Result<usize> {
        use nix::sys::socket::{recv, recvfrom, MsgFlags, NetlinkAddr};
        use std::os::fd::AsRawFd;
        // Linux MSG_TRUNC returns the full datagram length even for this one-byte
        // peek. No other thread reads this owned socket between peek and receive.
        let expected = recv(
            self.socket.as_raw_fd(),
            &mut [0u8; 1],
            MsgFlags::MSG_PEEK | MsgFlags::MSG_TRUNC,
        )?;
        if expected == 0 || expected > self.buffer.len() {
            return Err(invalid());
        }
        let (length, from) = recvfrom::<NetlinkAddr>(self.socket.as_raw_fd(), &mut self.buffer)?;
        if length != expected || !from.is_some_and(|addr| addr.pid() == 0 && addr.groups() == 0) {
            return Err(invalid());
        }
        Ok(length)
    }

    pub fn recv(&mut self) -> io::Result<Message> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(message);
        }
        let length = self.receive_datagram()?;
        for (kind, _, bytes) in frames(&self.buffer[..length])? {
            if kind != PACKET {
                return Err(invalid());
            }
            self.pending.push_back(parse_packet(bytes)?);
        }
        self.pending.pop_front().ok_or_else(invalid)
    }

    pub fn verdict(&self, message: Message, payload: Option<Vec<u8>>) -> io::Result<()> {
        if message.queue != self.queue_num {
            return Err(invalid());
        }
        let accept = payload.is_some();
        let mut header = u32::from(accept).to_be_bytes().to_vec();
        header.extend_from_slice(&message.id.to_be_bytes());
        let mut attrs = vec![attribute(2, &header)?];
        if let Some(payload) = payload {
            attrs.push(attribute(10, &payload)?);
        }
        self.send(&request(
            VERDICT,
            self.queue_num,
            0,
            self.peer_portid,
            false,
            &attrs,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet_message() -> Vec<u8> {
        request(
            PACKET,
            41884,
            0,
            0,
            false,
            &[
                attribute(1, &[0, 0, 0, 42, 8, 0, 3]).unwrap(),
                attribute(16, &109u32.to_be_bytes()).unwrap(),
                attribute(10, &[1, 2, 3, 4, 5]).unwrap(),
            ],
        )
    }

    #[test]
    fn framing_preserves_byte_order_padding_and_multiple_messages() {
        let first = packet_message();
        let mut both = first.clone();
        both.extend_from_slice(&first);
        let frames = frames(&both).unwrap();
        assert_eq!(frames.len(), 2);
        let packet = parse_packet(frames[0].2).unwrap();
        assert_eq!(
            (packet.id, packet.queue, packet.hook, packet.uid),
            (42, 41884, 3, Some(109))
        );
        assert_eq!(packet.payload, [1, 2, 3, 4, 5]);
        assert_eq!(packet.original_len, 5);
        assert!(packet.checksum_ready && !packet.gso);
    }

    #[test]
    fn offload_and_truncation_flags_are_not_ignored() {
        let bytes = request(
            PACKET,
            41884,
            0,
            0,
            false,
            &[
                attribute(1, &[0, 0, 0, 42, 8, 0, 3]).unwrap(),
                attribute(10, &[1]).unwrap(),
                attribute(13, &60u32.to_be_bytes()).unwrap(),
                attribute(14, &3u32.to_be_bytes()).unwrap(),
            ],
        );
        let frame = frames(&bytes).unwrap();
        let packet = parse_packet(frame[0].2).unwrap();
        assert_eq!(packet.original_len, 60);
        assert!(!packet.checksum_ready && packet.gso);
    }

    #[test]
    fn malformed_frames_attributes_and_duplicates_are_rejected() {
        let valid = packet_message();
        for n in 1..valid.len() {
            assert!(frames(&valid[..n]).is_err());
        }
        assert!(attributes(&[1, 0, 1, 0]).is_err());
        assert!(attributes(&[8, 0, 1, 0]).is_err());
        let duplicate = request(
            PACKET,
            41884,
            0,
            0,
            false,
            &[
                attribute(1, &[0, 0, 0, 42, 8, 0, 3]).unwrap(),
                attribute(10, &[1]).unwrap(),
                attribute(10, &[2]).unwrap(),
            ],
        );
        assert!(parse_packet(frames(&duplicate).unwrap()[0].2).is_err());
        assert!(attribute(10, &vec![0; MAX_PAYLOAD + 1]).is_err());
    }

    #[test]
    fn acknowledgments_require_matching_sequence_and_success() {
        let mut reply = vec![0; 20];
        reply[..4].copy_from_slice(&20u32.to_ne_bytes());
        reply[4..6].copy_from_slice(&NL_ERROR.to_ne_bytes());
        reply[8..12].copy_from_slice(&7u32.to_ne_bytes());
        assert!(check_ack(&reply, 7).is_ok());
        assert!(check_ack(&reply, 8).is_err());
        reply[16..20].copy_from_slice(&(-1i32).to_ne_bytes());
        assert_eq!(check_ack(&reply, 7).unwrap_err().raw_os_error(), Some(1));
    }

    #[test]
    fn config_and_verdict_use_the_expected_subsystem_and_flags() {
        let config = request(
            CONFIG,
            41884,
            1,
            42,
            true,
            &[attribute(1, &[1, 0, 0, 0]).unwrap()],
        );
        assert_eq!(u16::from_ne_bytes(config[6..8].try_into().unwrap()), 5);
        assert_eq!(frames(&config).unwrap()[0].0, CONFIG);
        let verdict = request(
            VERDICT,
            41884,
            0,
            42,
            false,
            &[attribute(2, &[0, 0, 0, 1, 0, 0, 0, 42]).unwrap()],
        );
        assert_eq!(frames(&verdict).unwrap()[0].0, VERDICT);
        assert_eq!(u16::from_ne_bytes(verdict[6..8].try_into().unwrap()), 1);
    }
}
