#![no_main]
use libfuzzer_sys::fuzz_target;
use wraith_net::netlink::{parse_netlink_ack, parse_netlink_frames};

fuzz_target!(|data: &[u8]| {
    // Both dump frame parsing and ack parsing must never panic or perform UB on raw bytes
    let _ = parse_netlink_frames(data);
    let _ = parse_netlink_ack(data);
});
