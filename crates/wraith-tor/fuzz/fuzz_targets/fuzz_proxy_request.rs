#![no_main]
use libfuzzer_sys::fuzz_target;
use wraith_tor::proxy_request::{parse, private_proxy_header};

fuzz_target!(|data: &[u8]| {
    // Explicit CONNECT, absolute HTTP and transparent origin-form requests
    let _ = parse(data);
    if let Ok(header) = std::str::from_utf8(data) {
        let _ = private_proxy_header(header);
    }
});
