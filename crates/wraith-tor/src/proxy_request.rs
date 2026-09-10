//! Parse explicit CONNECT, absolute HTTP URLs and transparent origin-form requests.
use wraith_core::error::{Result, WraithError};

pub(crate) struct Request {
    pub host: String,
    pub port: u16,
    pub tunnel: bool,
    pub payload: Vec<u8>,
}

fn invalid() -> WraithError {
    WraithError::Network("Invalid or ambiguous HTTP proxy request".into())
}

fn authority(value: &str, default_port: Option<u16>) -> Result<(String, u16)> {
    if value.is_empty()
        || value.contains(['@', '/', '?', '#', '\\'])
        || value.bytes().any(|b| b <= 32 || b >= 127)
    {
        return Err(invalid());
    }
    let url = url::Url::parse(&format!("http://{value}/")).map_err(|_| invalid())?;
    let host = url
        .host_str()
        .ok_or_else(invalid)?
        .trim_matches(['[', ']'])
        .to_string();
    let explicit_port = if value.starts_with('[') {
        value.rsplit_once("]:").map(|(_, p)| p)
    } else {
        value.rsplit_once(':').map(|(_, p)| p)
    };
    let port = match explicit_port {
        Some(value) => value.parse::<u16>().map_err(|_| invalid())?,
        None => default_port.ok_or_else(invalid)?,
    };
    if host.is_empty() || host.len() > 255 || port == 0 {
        return Err(invalid());
    }
    Ok((host, port))
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Request> {
    let end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(invalid)?
        + 4;
    let text = std::str::from_utf8(&bytes[..end]).map_err(|_| invalid())?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let first = lines.next().ok_or_else(invalid)?;
    let parts: Vec<_> = first.split(' ').collect();
    if parts.len() != 3
        || parts[0].is_empty()
        || !parts[0].bytes().all(|b| b.is_ascii_uppercase())
        || parts[1].bytes().any(|b| b <= 32 || b == 127)
        || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1")
    {
        return Err(invalid());
    }
    let tunnel = parts[0] == "CONNECT";
    let mut host_header = None;
    let mut headers = Vec::new();
    let mut content_length = None;
    let mut transfer_encoding = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
        {
            return Err(invalid());
        }
        match name.to_ascii_lowercase().as_str() {
            "host" => {
                if host_header.replace(value.trim()).is_some() {
                    return Err(invalid());
                }
            }
            "content-length" => {
                let count = value.trim().parse::<u64>().map_err(|_| invalid())?;
                if content_length.replace(count).is_some() {
                    return Err(invalid());
                }
            }
            "transfer-encoding" => {
                if transfer_encoding {
                    return Err(invalid());
                }
                transfer_encoding = true;
            }
            _ => {}
        }
        if !name.eq_ignore_ascii_case("proxy-authorization")
            && !name.eq_ignore_ascii_case("proxy-connection")
        {
            headers.push(line);
        }
    }
    if transfer_encoding && content_length.is_some() {
        return Err(invalid());
    }
    if tunnel && (transfer_encoding || content_length.unwrap_or(0) != 0) {
        return Err(invalid());
    }
    let (host, port, target) = if tunnel {
        let (host, port) = authority(parts[1], None)?;
        (host, port, String::new())
    } else if parts[1].starts_with("http://") {
        let url = url::Url::parse(parts[1]).map_err(|_| invalid())?;
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(invalid());
        }
        let host = url
            .host_str()
            .ok_or_else(invalid)?
            .trim_matches(['[', ']'])
            .to_string();
        let port = url.port_or_known_default().ok_or_else(invalid)?;
        let target = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_string(),
        };
        (host, port, target)
    } else if parts[1].starts_with('/') || (parts[0] == "OPTIONS" && parts[1] == "*") {
        let (host, port) = authority(host_header.ok_or_else(invalid)?, Some(80))?;
        (host, port, parts[1].into())
    } else {
        return Err(invalid());
    };
    if host.is_empty() || host.len() > 255 || port == 0 {
        return Err(invalid());
    }
    if let Some(header) = host_header {
        let (header_host, header_port) = authority(header, Some(if tunnel { port } else { 80 }))?;
        if !header_host.eq_ignore_ascii_case(&host) || header_port != port {
            return Err(invalid());
        }
    } else if parts[2] == "HTTP/1.1" {
        return Err(invalid());
    }
    let payload = if tunnel {
        bytes[end..].to_vec()
    } else {
        let mut payload = format!(
            "{} {target} {}\r\n{}\r\n\r\n",
            parts[0],
            parts[2],
            headers.join("\r\n")
        )
        .into_bytes();
        payload.extend_from_slice(&bytes[end..]);
        payload
    };
    Ok(Request {
        host,
        port,
        tunnel,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supports_connect_ipv6_custom_ports_and_coalesced_tls() {
        let request = parse(
            b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n\x16\x03\x01",
        )
        .unwrap();
        assert_eq!(
            (request.host.as_str(), request.port, request.tunnel),
            ("2001:db8::1", 8443, true)
        );
        assert_eq!(request.payload, b"\x16\x03\x01");
    }
    #[test]
    fn normalizes_absolute_urls_without_forwarding_proxy_credentials() {
        let request = parse(b"POST http://example.org:8080/a?q=1 HTTP/1.1\r\nHost: example.org:8080\r\nProxy-Authorization: Basic secret\r\nContent-Length: 2\r\n\r\n\xff\x00").unwrap();
        assert_eq!(request.port, 8080);
        assert!(request.payload.starts_with(b"POST /a?q=1 HTTP/1.1\r\n"));
        assert!(!request.payload.windows(6).any(|w| w == b"secret"));
        assert!(request.payload.ends_with(b"\xff\x00"));
    }
    #[test]
    fn rejects_ambiguous_authority_and_message_framing() {
        for request in [
            "CONNECT example.org HTTP/1.1\r\nHost: example.org\r\n\r\n",
            "CONNECT example.org:0 HTTP/1.1\r\nHost: example.org:0\r\n\r\n",
            "GET http://example.org/a HTTP/1.1\r\nHost: other.org\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.org\r\nHost: other.org\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: example.org\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] { assert!(parse(request.as_bytes()).is_err(), "{request}"); }
    }
}
