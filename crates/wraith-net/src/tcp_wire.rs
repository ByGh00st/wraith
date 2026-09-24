//! IPv4 SYN normalization for the Tor-to-guard access link.
//! No TCP state machine: preserve sequence numbers, payload, receive window and
//! window scale. Only reduce MSS / timestamp negotiation, never advertise a
//! receive capability that the kernel does not implement.

use wraith_core::tcp_fingerprint::{TcpFingerprintProfile, TcpProfileKind};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireMorphError {
    #[error("invalid, fragmented or truncated IPv4 packet")]
    Ipv4,
    #[error("expected an initial TCP SYN without ACK/RST/FIN")]
    Syn,
    #[error("malformed, duplicate or oversized TCP options")]
    Options,
    #[error("authenticated TCP headers cannot be rewritten")]
    Authenticated,
    #[error("invalid TCP profile")]
    Profile,
}

/// Input is a complete IPv4 packet, without Ethernet framing. NFQUEUE must
/// deliver fully checksummed, non-GSO packets (NFQA_CFG_F_GSO disabled).
pub fn morph_ipv4_syn(
    packet: &[u8],
    profile: &TcpFingerprintProfile,
) -> Result<Vec<u8>, WireMorphError> {
    profile.validate().map_err(|_| WireMorphError::Profile)?;
    if packet.len() < 40 || packet[0] >> 4 != 4 {
        return Err(WireMorphError::Ipv4);
    }
    let ip_len = usize::from(packet[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let fragments = u16::from_be_bytes([packet[6], packet[7]]);
    if ip_len < 20
        || ip_len + 20 > packet.len()
        || total != packet.len()
        || fragments & 0x3fff != 0
        || packet[9] != 6
    {
        return Err(WireMorphError::Ipv4);
    }
    let tcp = &packet[ip_len..];
    let tcp_len = usize::from(tcp[12] >> 4) * 4;
    if tcp_len < 20 || tcp_len > tcp.len() || tcp[13] & 0x17 != 0x02 {
        return Err(WireMorphError::Syn);
    }
    let mut options = parse_options(&tcp[20..tcp_len])?;
    for option in &mut options {
        if option[0] == 2 {
            let original = u16::from_be_bytes([option[2], option[3]]);
            if let Some(cap) = profile.syn_mss {
                option[2..4].copy_from_slice(&original.min(cap).to_be_bytes());
            }
        }
    }
    // A peer that does not receive a timestamp offer will not negotiate it.
    // Inserting timestamps or changing scale would require kernel TCP state.
    if profile.tcp_timestamps == 0 {
        options.retain(|option| option[0] != 8);
    }
    let options = order_options(options, profile.kind)?;
    let new_length = ip_len + 20 + options.len() + tcp.len() - tcp_len;
    let total = u16::try_from(new_length).map_err(|_| WireMorphError::Options)?;
    let mut output = Vec::with_capacity(new_length);
    output.extend_from_slice(&packet[..ip_len + 20]);
    output.extend_from_slice(&options);
    output.extend_from_slice(&tcp[tcp_len..]);
    output[2..4].copy_from_slice(&total.to_be_bytes());
    output[8] = profile.default_ttl;
    output[ip_len + 12] = (((20 + options.len()) / 4) as u8) << 4 | (tcp[12] & 15);
    output[10..12].fill(0);
    let ip_checksum = checksum(&output[..ip_len]);
    output[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    output[ip_len + 16..ip_len + 18].fill(0);
    let tcp_checksum = tcp_checksum(&output, ip_len);
    output[ip_len + 16..ip_len + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    Ok(output)
}

fn parse_options(bytes: &[u8]) -> Result<Vec<Vec<u8>>, WireMorphError> {
    let mut options: Vec<Vec<u8>> = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let kind = bytes[index];
        match kind {
            0 => break,
            1 => {
                index += 1;
                continue;
            }
            19 | 29 => return Err(WireMorphError::Authenticated), // TCP MD5 / AO
            _ => {}
        }
        let length = usize::from(*bytes.get(index + 1).ok_or(WireMorphError::Options)?);
        if length < 2
            || index + length > bytes.len()
            || matches!(kind, 2 | 3 | 4 | 8) && options.iter().any(|opt| opt[0] == kind)
            || matches!(kind, 2) && length != 4
            || matches!(kind, 3) && length != 3
            || matches!(kind, 4) && length != 2
            || matches!(kind, 8) && length != 10
        {
            return Err(WireMorphError::Options);
        }
        if kind == 3 && bytes[index + 2] > 14 {
            return Err(WireMorphError::Options);
        }
        options.push(bytes[index..index + length].to_vec());
        index += length;
    }
    Ok(options)
}

fn order_options(
    mut options: Vec<Vec<u8>>,
    profile: TcpProfileKind,
) -> Result<Vec<u8>, WireMorphError> {
    let mut output = Vec::new();
    let layout: &[(u8, usize)] = match profile {
        TcpProfileKind::Windows11 => &[(2, 0), (3, 1), (4, 2), (8, 0)],
        TcpProfileKind::MacOS => &[(2, 0), (3, 1), (8, 2), (4, 0)],
        TcpProfileKind::LinuxDefault => &[(2, 0), (4, 0), (8, 0), (3, 1)],
    };
    for (kind, padding) in layout {
        if let Some(index) = options.iter().position(|option| option[0] == *kind) {
            output.extend(std::iter::repeat_n(1, *padding));
            output.extend(options.remove(index));
        }
    }
    // Preserve extensions (including Fast Open cookies) and their relative order.
    for option in options {
        output.extend(option);
    }
    while output.len() % 4 != 0 {
        output.push(0);
    }
    if output.len() > 40 {
        return Err(WireMorphError::Options);
    }
    Ok(output)
}

fn sum_words(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)])))
        .sum()
}

fn finish_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum(bytes: &[u8]) -> u16 {
    finish_checksum(sum_words(bytes))
}

fn tcp_checksum(packet: &[u8], ip_len: usize) -> u16 {
    finish_checksum(
        sum_words(&packet[12..20])
            + 6
            + (packet.len() - ip_len) as u32
            + sum_words(&packet[ip_len..]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(options: &[u8], payload: &[u8]) -> Vec<u8> {
        assert_eq!(options.len() % 4, 0);
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[6] = 0x40;
        packet[8] = 64;
        packet[9] = 6;
        packet[12..20].copy_from_slice(&[192, 0, 2, 1, 198, 51, 100, 4]);
        packet[20..24].copy_from_slice(&[0xc0, 0x12, 0x01, 0xbb]);
        packet[24..28].copy_from_slice(&0x01020304u32.to_be_bytes());
        packet[32] = ((20 + options.len()) / 4) as u8 * 16;
        packet[33] = 0xc2; // Preserve kernel ECN negotiation.
        packet[34..36].copy_from_slice(&64240u16.to_be_bytes());
        packet.extend_from_slice(options);
        packet.extend_from_slice(payload);
        let len = packet.len() as u16;
        packet[2..4].copy_from_slice(&len.to_be_bytes());
        let ip_sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        let tcp_sum = tcp_checksum(&packet, 20);
        packet[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
        packet
    }

    const LINUX: &[u8] = &[
        2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 15, 0, 0, 0, 0, 1, 3, 3, 7,
    ];

    #[test]
    fn windows_changes_wire_ttl_and_layout_without_falsifying_tcp_state() {
        let before = packet(LINUX, b"odd payload");
        let after = morph_ipv4_syn(&before, &TcpFingerprintProfile::windows11()).unwrap();
        assert_eq!(after[8], 128);
        assert_eq!(&after[40..52], &[2, 4, 5, 180, 1, 3, 3, 7, 1, 1, 4, 2]);
        assert_eq!(&after[20..32], &before[20..32]); // Ports, SEQ, ACK.
        assert_eq!(&after[33..36], &before[33..36]); // Flags and receive window.
        assert_eq!(&after[52..], b"odd payload");
        // Independently calculated checksums for this fixed IPv4/TCP fixture.
        assert_eq!(&after[10..12], &[0x0e, 0x80]);
        assert_eq!(&after[36..38], &[0x30, 0x94]);
        assert_eq!(checksum(&after[..20]), 0);
        assert_eq!(tcp_checksum(&after, 20), 0);
        assert_eq!(
            after,
            morph_ipv4_syn(&after, &TcpFingerprintProfile::windows11()).unwrap()
        );
    }

    #[test]
    fn macos_reorders_existing_timestamp_and_never_increases_mss() {
        let before = packet(LINUX, b"");
        let after = morph_ipv4_syn(&before, &TcpFingerprintProfile::macos()).unwrap();
        assert_eq!(
            &after[40..64],
            &[2, 4, 5, 160, 1, 3, 3, 7, 1, 1, 8, 10, 0, 0, 0, 15, 0, 0, 0, 0, 4, 2, 0, 0]
        );
        let mut options = LINUX.to_vec();
        options[2..4].copy_from_slice(&1200u16.to_be_bytes());
        let after =
            morph_ipv4_syn(&packet(&options, b""), &TcpFingerprintProfile::macos()).unwrap();
        assert_eq!(&after[42..44], &1200u16.to_be_bytes());
        assert_eq!(tcp_checksum(&after, 20), 0);
    }

    #[test]
    fn no_kernel_capability_is_invented_and_extensions_survive() {
        let options = [2, 4, 5, 180, 34, 6, 1, 2, 3, 4, 0, 0];
        for profile in [
            TcpFingerprintProfile::windows11(),
            TcpFingerprintProfile::macos(),
            TcpFingerprintProfile::linux_default(),
        ] {
            let after = morph_ipv4_syn(&packet(&options, b"TFO"), &profile).unwrap();
            let header = usize::from(after[32] >> 4) * 4;
            let decoded = parse_options(&after[40..20 + header]).unwrap();
            assert_eq!(decoded.len(), 2);
            assert_eq!(decoded[1], [34, 6, 1, 2, 3, 4]);
            assert_eq!(&after[20 + header..], b"TFO");
            assert_eq!(checksum(&after[..20]), 0);
            assert_eq!(tcp_checksum(&after, 20), 0);
        }
    }

    #[test]
    fn malformed_or_authenticated_headers_are_not_forwarded_unmodified() {
        for options in [
            vec![2, 0, 0, 0],
            vec![8, 20, 0, 0],
            vec![3, 3, 15, 0],
            vec![2, 4, 5, 180, 2, 4, 5, 180],
            vec![19, 2, 0, 0],
            vec![29, 2, 0, 0],
        ] {
            assert!(
                morph_ipv4_syn(&packet(&options, b""), &TcpFingerprintProfile::windows11())
                    .is_err()
            );
        }
    }

    #[test]
    fn truncated_fragments_and_non_syn_packets_are_rejected() {
        let valid = packet(LINUX, b"");
        for len in 0..valid.len() {
            assert!(morph_ipv4_syn(&valid[..len], &TcpFingerprintProfile::windows11()).is_err());
        }
        for (index, value) in [
            (0, 0x65),
            (0, 0x44),
            (6, 0x20),
            (7, 1),
            (9, 17),
            (32, 0xf0),
            (33, 0x12),
            (33, 0x03),
            (33, 0x06),
        ] {
            let mut bad = valid.clone();
            bad[index] = value;
            assert!(
                morph_ipv4_syn(&bad, &TcpFingerprintProfile::windows11()).is_err(),
                "{index}/{value}"
            );
        }
    }

    #[test]
    fn ip_options_and_payload_are_preserved_with_fresh_checksums() {
        let mut before = packet(LINUX, &[0, 255, 128]);
        before.splice(20..20, [1, 1, 0, 0]);
        before[0] = 0x46;
        let len = before.len() as u16;
        before[2..4].copy_from_slice(&len.to_be_bytes());
        let after = morph_ipv4_syn(&before, &TcpFingerprintProfile::windows11()).unwrap();
        assert_eq!(&after[20..24], &[1, 1, 0, 0]);
        assert_eq!(&after[56..], &[0, 255, 128]);
        assert_eq!(checksum(&after[..24]), 0);
        assert_eq!(tcp_checksum(&after, 24), 0);
    }
}
