#![no_main]
use libfuzzer_sys::fuzz_target;
use wraith_core::tcp_fingerprint::{TcpFingerprintProfile, TcpProfileKind};
use wraith_net::tcp_wire::morph_ipv4_syn;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Use the first byte to pick a fingerprint profile flavor
    let profile_kind = match data[0] % 4 {
        0 => TcpProfileKind::Linux,
        1 => TcpProfileKind::Windows,
        2 => TcpProfileKind::MacOs,
        _ => TcpProfileKind::Custom,
    };

    let mut profile = TcpFingerprintProfile::default_for(profile_kind);
    // Use second byte to toggle MSS clamping or timestamps
    if data[1] & 0x01 != 0 {
        profile.syn_mss = Some(1400);
    }
    if data[1] & 0x02 != 0 {
        profile.tcp_timestamps = 0;
    }

    // Packet under test starts at offset 2
    let packet = &data[2..];
    // Parsing and morphing must never panic on arbitrary input
    let _ = morph_ipv4_syn(packet, &profile);
});
