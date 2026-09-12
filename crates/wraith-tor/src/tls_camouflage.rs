//! Local HTTP proxy: initial cleartext header normalization, CONNECT tunneling
//! and transparent port-80 relay over Tor SOCKS. CONNECT preserves client TLS.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use wraith_core::config::TOR_SOCKS_PORT;
use wraith_core::error::{Result, WraithError};

use crate::grease::{BrowserType, DynamicTlsFingerprint};

pub const TLS_PROXY_PORT: u16 = 9055;

pub const BROWSER_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
];

pub const AUDIT_TOOL_SIGNATURES: &[&str] = &[
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "curl",
    "wget",
    "python-requests",
    "python-urllib",
    "gobuster",
    "dirbuster",
    "wfuzz",
    "ffuf",
    "hydra",
    "medusa",
    "burpsuite",
    "owasp zap",
    "zap",
    "metasploit",
    "postman",
];

pub const OFFENSIVE_SIGNATURES: &[&str] = AUDIT_TOOL_SIGNATURES;

/// Legacy fingerprint metadata; actual handshakes use `BrowserTlsClient` profiles.
pub fn get_active_tls_profile() -> DynamicTlsFingerprint {
    DynamicTlsFingerprint::generate(BrowserType::ChromeWin11)
}

/// Spawns the async TLS Camouflage & HTTP DPI Sanitizer Proxy server
pub struct TlsCamouflageServer {
    port: u16,
    cancel_token: CancellationToken,
}

impl TlsCamouflageServer {
    pub fn new(port: Option<u16>) -> (Self, CancellationToken) {
        let cancel_token = CancellationToken::new();
        (
            Self {
                port: port.unwrap_or(TLS_PROXY_PORT),
                cancel_token: cancel_token.clone(),
            },
            cancel_token,
        )
    }

    pub async fn spawn_server(self) -> Result<tokio::task::JoinHandle<()>> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        info!("HTTP proxy listening on {addr}");
        Ok(tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = clients.join_next(), if !clients.is_empty() => {},
                    _ = self.cancel_token.cancelled() => {
                        info!("HTTP DPI Sanitizer Proxy received shutdown signal");
                        break;
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((client_stream, client_addr)) => {
                                debug!("Incoming HTTP/SOCKS connection from {client_addr}");
                                if clients.len() >= 128 { continue; }
                                clients.spawn(async move {
                                    if let Err(e) = handle_proxy_client(client_stream).await {
                                        debug!("Proxy client handler debug: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                debug!("Accept error in HTTP proxy: {e}");
                            }
                        }
                    }
                }
            }
            clients.shutdown().await;
        }))
    }
}

/// Rewrites security auditing or custom User-Agents in-flight in the HTTP header
fn sanitize_http_request(req_data: &[u8]) -> (Vec<u8>, String, bool) {
    let header_end = match req_data.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(pos) => pos + 4,
        None => return (req_data.to_vec(), String::new(), false),
    };
    let req_str = match std::str::from_utf8(&req_data[..header_end]) {
        Ok(headers) => headers,
        Err(_) => return (req_data.to_vec(), String::new(), false),
    };
    let mut target_host = String::new();
    let mut modified_lines = Vec::new();
    let mut was_sanitized = false;

    // Diversified UA pool
    let pool = wraith_core::signatures::BROWSER_USER_AGENT_POOL;
    let pool_idx = req_data.len() % pool.len();
    let target_ua = pool[pool_idx];

    let full_sigs = wraith_core::signatures::get_offensive_tool_signatures();

    for line in req_str.split("\r\n") {
        if line.to_lowercase().starts_with("host:") {
            target_host = line[5..].trim().to_string();
            modified_lines.push(line.to_string());
        } else if line.to_lowercase().starts_with("user-agent:") {
            let current_ua = line[11..].trim();
            let raw_ua_lower = current_ua.to_lowercase();
            
            let is_audit_tool = AUDIT_TOOL_SIGNATURES
                .iter()
                .any(|&sig| raw_ua_lower.contains(sig))
                || full_sigs.iter().any(|sig| raw_ua_lower.contains(sig.as_str()));
                
            let is_browser = current_ua.starts_with("Mozilla/5.0");

            if is_audit_tool || !is_browser {
                was_sanitized = true;
                modified_lines.push(format!("User-Agent: {target_ua}"));
            } else {
                modified_lines.push(line.to_string());
            }
        } else {
            modified_lines.push(line.to_string());
        }
    }

    let mut reconstructed = modified_lines.join("\r\n").into_bytes();
    reconstructed.extend_from_slice(&req_data[header_end..]);
    (reconstructed, target_host, was_sanitized)
}

/// Handles incoming client connection, sanitizes HTTP headers in-flight, and bridges through Tor SOCKS5
async fn handle_proxy_client(client: TcpStream) -> Result<()> {
    handle_proxy_client_with_port(client, TOR_SOCKS_PORT).await
}

async fn handle_proxy_client_with_port(mut client: TcpStream, socks_port: u16) -> Result<()> {
    let mut peek_buf = vec![0u8; 8192];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.peek(&mut peek_buf),
    )
    .await
    .map_err(|_| WraithError::Network("Proxy greeting timeout".into()))??;
    if n == 0 {
        return Ok(());
    }

    // 1. Direct SOCKS5 client protocol check
    if peek_buf[0] == 0x05 {
        let mut tor_stream = TcpStream::connect(format!("127.0.0.1:{socks_port}")).await?;
        tokio::io::copy_bidirectional(&mut client, &mut tor_stream).await?;
        return Ok(());
    }

    // 2. Transparent In-Flight HTTP Request (redirected from iptables port 80)
    let req_buf = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        read_http_headers(&mut client),
    )
    .await
    .map_err(|_| WraithError::Custom("HTTP header timeout".into()))??;
    let request = match crate::proxy_request::parse(&req_buf) {
        Ok(request) => request,
        Err(error) => {
            client
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            return Err(error);
        }
    };
    let mut tor_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        connect_socks(&request.host, request.port, socks_port),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => {
            client
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            return Err(WraithError::Network(
                "Tor SOCKS connection failed or timed out".into(),
            ));
        }
    };
    if request.tunnel {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        // Headers and the first TLS record may arrive in the same read.
        tor_stream.write_all(&request.payload).await?;
    } else {
        let (sanitized, host, was_sanitized) = sanitize_http_request(&request.payload);
        if was_sanitized {
            tracing::info!("DPI Proxy: Sanitized offensive UA in cleartext HTTP to {host}");
        }
        tor_stream.write_all(&sanitized).await?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut tor_stream).await?;
    Ok(())
}

pub(crate) async fn connect_socks(host: &str, port: u16, socks_port: u16) -> Result<TcpStream> {
    if host.is_empty() || host.len() > 255 || port == 0 {
        return Err(WraithError::Network("Invalid SOCKS destination".into()));
    }
    let mut tor_stream = TcpStream::connect(format!("127.0.0.1:{socks_port}"))
        .await
        .map_err(|e| WraithError::Custom(format!("Cannot connect to Tor SOCKS5: {e}")))?;

    // SOCKS5 greeting: Version 5, 1 Auth Method (No Auth: 0x00)
    tor_stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(WraithError::Io)?;
    let mut auth_resp = [0u8; 2];
    tor_stream
        .read_exact(&mut auth_resp)
        .await
        .map_err(WraithError::Io)?;

    if auth_resp[0] != 0x05 || auth_resp[1] != 0x00 {
        return Err(WraithError::Custom("Tor SOCKS5 auth failed".into()));
    }

    // Domain names are resolved by Tor; IP literals use their matching ATYP.
    let mut connect_cmd = vec![0x05, 0x01, 0x00];
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            connect_cmd.push(1);
            connect_cmd.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            connect_cmd.push(4);
            connect_cmd.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            connect_cmd.extend_from_slice(&[3, host.len() as u8]);
            connect_cmd.extend_from_slice(host.as_bytes());
        }
    }
    connect_cmd.extend_from_slice(&port.to_be_bytes());

    tor_stream
        .write_all(&connect_cmd)
        .await
        .map_err(WraithError::Io)?;
    read_socks_reply(&mut tor_stream).await?;

    Ok(tor_stream)
}

async fn read_http_headers<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    const MAX_HEADERS: usize = 64 * 1024;
    let mut request = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Err(WraithError::Custom("Incomplete HTTP headers".into()));
        }
        request.extend_from_slice(&chunk[..n]);
        if let Some(pos) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            if pos + 4 <= MAX_HEADERS {
                return Ok(request);
            }
        }
        if request.len() >= MAX_HEADERS {
            return Err(WraithError::Custom("HTTP headers exceed 64 KiB".into()));
        }
    }
}

async fn read_socks_reply<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    if header[0] != 5 || header[1] != 0 || header[2] != 0 {
        return Err(WraithError::Custom(format!(
            "Invalid SOCKS5 reply: {header:?}"
        )));
    }
    let address_len = match header[3] {
        1 => 4,
        4 => 16,
        3 => reader.read_u8().await? as usize,
        _ => return Err(WraithError::Custom("Invalid SOCKS5 address type".into())),
    };
    let mut bound_address = vec![0u8; address_len + 2];
    reader.read_exact(&mut bound_address).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_binary_body_and_does_not_parse_body_as_headers() {
        let body = b"\xff\x00\r\nHost: wrong.example\r\nUser-Agent: body-data";
        let mut request =
            b"POST / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: Mozilla/5.0\r\n\r\n".to_vec();
        request.extend_from_slice(body);
        let (result, host, changed) = sanitize_http_request(&request);
        assert_eq!(host, "example.org");
        assert!(!changed);
        assert_eq!(result, request);
    }

    #[tokio::test]
    async fn waits_for_fragmented_headers() {
        let (mut sender, mut reader) = tokio::io::duplex(32);
        let task = tokio::spawn(async move {
            sender.write_all(b"GET / HTTP/1.1\r\nHo").await.unwrap();
            tokio::task::yield_now().await;
            sender.write_all(b"st: example.org\r\n\r\n").await.unwrap();
        });
        let request = read_http_headers(&mut reader).await.unwrap();
        assert_eq!(sanitize_http_request(&request).1, "example.org");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_incomplete_and_oversized_headers() {
        assert!(read_http_headers(&mut &b"GET / HTTP/1.1\r\n"[..])
            .await
            .is_err());
        assert!(read_http_headers(&mut vec![b'x'; 65536].as_slice())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn consumes_each_socks_address_type_without_eating_response() {
        for (kind, address) in [
            (1, vec![0; 4]),
            (4, vec![0; 16]),
            (3, vec![3, b'f', b'o', b'o']),
        ] {
            let mut reply = vec![5, 0, 0, kind];
            reply.extend(address);
            reply.extend([0, 80]);
            reply.extend(b"HTTP/1.1");
            let mut reader = reply.as_slice();
            read_socks_reply(&mut reader).await.unwrap();
            assert_eq!(reader, b"HTTP/1.1");
        }
        assert!(read_socks_reply(&mut &b"\x05\x01\x00\x01"[..])
            .await
            .is_err());
        assert!(read_socks_reply(&mut &b"\x05\x00\x00\x09"[..])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn http_response_survives_client_half_close() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let socks_port = socks.local_addr().unwrap().port();
            let upstream = tokio::spawn(async move {
                let (mut stream, _) = socks.accept().await.unwrap();
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut connect = [0; 5];
                stream.read_exact(&mut connect).await.unwrap();
                assert_eq!(&connect[..4], &[5, 1, 0, 3]);
                let mut destination = vec![0; connect[4] as usize + 2];
                stream.read_exact(&mut destination).await.unwrap();
                assert_eq!(&destination[..destination.len() - 2], b"example.org");
                // IPv6 bound-address replies used to leave bytes in the HTTP stream.
                stream.write_all(&[5, 0, 0, 4]).await.unwrap();
                stream.write_all(&[0; 18]).await.unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                assert!(request.ends_with(b"\xff\x00"));
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
            });
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(proxy.local_addr().unwrap())
                .await
                .unwrap();
            let (accepted, _) = proxy.accept().await.unwrap();
            let handler = tokio::spawn(handle_proxy_client_with_port(accepted, socks_port));
            client
                .write_all(
                    b"POST / HTTP/1.1\r\nHost: example.org\r\nContent-Length: 2\r\n\r\n\xff\x00",
                )
                .await
                .unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
            handler.await.unwrap().unwrap();
            upstream.await.unwrap();
        })
        .await
        .expect("proxy stalled after client half-close");
    }

    #[tokio::test]
    async fn connect_preserves_coalesced_tls_and_custom_port() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = socks.local_addr().unwrap().port();
            let upstream = tokio::spawn(async move {
                let (mut stream, _) = socks.accept().await.unwrap();
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                stream.write_all(&[5, 0]).await.unwrap();
                let mut command = [0; 5];
                stream.read_exact(&mut command).await.unwrap();
                assert_eq!(&command[..4], &[5, 1, 0, 3]);
                let mut host = vec![0; command[4] as usize];
                stream.read_exact(&mut host).await.unwrap();
                assert_eq!(host, b"example.org");
                assert_eq!(stream.read_u16().await.unwrap(), 8443);
                stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                let mut tls = Vec::new();
                stream.read_to_end(&mut tls).await.unwrap();
                assert_eq!(tls, b"\x16\x03\x03\x00\x02\xff\x00");
                stream.write_all(b"\x16\x03\x03\x00\x01\xfe").await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
            let (socket, _) = listener.accept().await.unwrap();
            let proxy = tokio::spawn(handle_proxy_client_with_port(socket, port));
            client.write_all(b"CONNECT example.org:8443 HTTP/1.1\r\nHost: example.org:8443\r\n\r\n\x16\x03\x03\x00\x02\xff\x00").await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200 Connection Established\r\n\r\n"));
            assert!(response.ends_with(b"\x16\x03\x03\x00\x01\xfe"));
            upstream.await.unwrap();
            proxy.await.unwrap().unwrap();
        }).await.expect("CONNECT tunnel stalled");
    }

    #[tokio::test]
    async fn bind_failure_is_reported_to_caller() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (server, _) = TlsCamouflageServer::new(Some(occupied.local_addr().unwrap().port()));
        assert!(server.spawn_server().await.is_err());
    }
}
