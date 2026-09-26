#![no_main]
use libfuzzer_sys::fuzz_target;
use wraith_guard::dns_engine::DnsPacket;

fuzz_target!(|data: &[u8]| {
    // RFC 1035 wire parser must safely return Ok or Err without panic or OOM
    let _ = DnsPacket::parse(data);
    if !data.is_empty() {
        let _ = DnsPacket::parse_qname(data, 0);
    }
});
