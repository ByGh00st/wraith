#![no_main]
use libfuzzer_sys::fuzz_target;
use wraith_tor::browser_tls::validate_https_url;
use wraith_tor::tls_camouflage::sanitize_http_request;

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz HTTP in-flight header sanitizer and UA normalizer
    let _ = sanitize_http_request(data);

    // 2. Fuzz HTTPS URL parsing if UTF-8 valid
    if let Ok(url_str) = std::str::from_utf8(data) {
        let _ = validate_https_url(url_str);
    }
});
