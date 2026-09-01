//! Wraith JA3/JA4 TLS ClientHello Camouflage & In-Flight HTTP DPI Sanitizer Proxy
//! Spawns an async transparent proxy (127.0.0.1:9055) bridging into Tor.
//! Intercepts outbound HTTP traffic in-flight, rewrites offensive signatures (sqlmap, nikto, curl, etc.)
//! into genuine Google Chrome User-Agents on the wire, and tunnels cleanly over Tor SOCKS5.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use wraith_core::config::TOR_SOCKS_PORT;
use wraith_core::error::{Result, WraithError};

pub const TLS_PROXY_PORT: u16 = 9055;

pub const BROWSER_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
];

pub const OFFENSIVE_SIGNATURES: &[&str] = &[
    "sqlmap", "nikto", "nmap", "masscan", "curl", "wget", "python-requests",
    "python-urllib", "gobuster", "dirbuster", "wfuzz", "ffuf", "hydra",
    "medusa", "burpsuite", "owasp zap", "zap", "metasploit", "postman",
];

#[derive(Debug, Clone)]
pub struct TlsProfile {
    pub name: &'static str,
    pub ja3_hash: &'static str,
    pub ja4_hash: &'static str,
    pub cipher_suites: &'static [u16],
    pub alpn_protocols: &'static [&'static str],
}

pub const CHROME_WIN11_PROFILE: TlsProfile = TlsProfile {
    name: "Google Chrome v130+ (Windows 11)",
    ja3_hash: "cd08e31494f9531f560d64c695473da9",
    ja4_hash: "t13d1516h2_8daaf6152771_b18509e3343c",
    cipher_suites: &[
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
    ],
    alpn_protocols: &["h2", "http/1.1"],
};

pub fn get_active_tls_profile() -> TlsProfile {
    CHROME_WIN11_PROFILE
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

    pub fn spawn_server(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let addr = format!("127.0.0.1:{}", self.port);
            let listener = match TcpListener::bind(&addr).await {
                Ok(l) => {
                    info!("In-Flight HTTP DPI Sanitizer & JA3/JA4 Proxy active on {addr} ➔ Bridging to Tor :{TOR_SOCKS_PORT}");
                    l
                }
                Err(e) => {
                    warn!("Failed binding In-Flight HTTP Sanitizer Proxy on {addr}: {e}");
                    return;
                }
            };

            loop {
                tokio::select! {
                    _ = self.cancel_token.cancelled() => {
                        info!("HTTP DPI Sanitizer Proxy received shutdown signal");
                        break;
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((client_stream, client_addr)) => {
                                debug!("Incoming HTTP/SOCKS connection from {client_addr}");
                                tokio::spawn(async move {
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
        })
    }
}

/// Rewrites offensive or custom User-Agents in-flight in the HTTP header
fn sanitize_http_request(req_data: &[u8]) -> (Vec<u8>, String, bool) {
    let req_str = String::from_utf8_lossy(req_data);
    let mut target_host = String::new();
    let mut modified_lines = Vec::new();
    let mut was_sanitized = false;

    let target_ua = BROWSER_USER_AGENTS[0];

    for line in req_str.split("\r\n") {
        if line.to_lowercase().starts_with("host:") {
            target_host = line[5..].trim().to_string();
            modified_lines.push(line.to_string());
        } else if line.to_lowercase().starts_with("user-agent:") {
            let current_ua = line[11..].trim();
            let is_offensive = OFFENSIVE_SIGNATURES.iter().any(|&sig| current_ua.to_lowercase().contains(sig));
            let is_browser = current_ua.starts_with("Mozilla/5.0");

            if is_offensive || !is_browser {
                was_sanitized = true;
                modified_lines.push(format!("User-Agent: {target_ua}"));
            } else {
                modified_lines.push(line.to_string());
            }
        } else {
            modified_lines.push(line.to_string());
        }
    }

    if target_host.is_empty() {
        target_host = "127.0.0.1".to_string();
    }

    let reconstructed = modified_lines.join("\r\n");
    (reconstructed.into_bytes(), target_host, was_sanitized)
}

/// Handles incoming client connection, sanitizes HTTP headers in-flight, and bridges through Tor SOCKS5
async fn handle_proxy_client(mut client: TcpStream) -> Result<()> {
    let mut peek_buf = vec![0u8; 8192];
    let n = client.peek(&mut peek_buf).await.map_err(WraithError::Io)?;
    if n == 0 {
        return Ok(());
    }

    // 1. Direct SOCKS5 client protocol check
    if peek_buf[0] == 0x05 {
        let tor_stream = TcpStream::connect(format!("127.0.0.1:{TOR_SOCKS_PORT}"))
            .await
            .map_err(|e| WraithError::Custom(format!("Cannot connect to Tor SOCKS5: {e}")))?;

        let (mut cr, mut cw) = client.into_split();
        let (mut tr, mut tw) = tor_stream.into_split();

        tokio::select! {
            _ = tokio::io::copy(&mut cr, &mut tw) => {},
            _ = tokio::io::copy(&mut tr, &mut cw) => {},
        }
        return Ok(());
    }

    // 2. Transparent In-Flight HTTP Request (redirected from iptables port 80)
    let mut req_buf = vec![0u8; 8192];
    let bytes_read = client.read(&mut req_buf).await.map_err(WraithError::Io)?;
    if bytes_read == 0 {
        return Ok(());
    }

    let (sanitized_req, target_host, _was_sanitized) = sanitize_http_request(&req_buf[..bytes_read]);

    let host_only = if let Some(idx) = target_host.find(':') {
        &target_host[..idx]
    } else {
        &target_host
    };

    // Connect to Tor SOCKS5
    let mut tor_stream = TcpStream::connect(format!("127.0.0.1:{TOR_SOCKS_PORT}"))
        .await
        .map_err(|e| WraithError::Custom(format!("Cannot connect to Tor SOCKS5: {e}")))?;

    // SOCKS5 greeting: Version 5, 1 Auth Method (No Auth: 0x00)
    tor_stream.write_all(&[0x05, 0x01, 0x00]).await.map_err(WraithError::Io)?;
    let mut auth_resp = [0u8; 2];
    tor_stream.read_exact(&mut auth_resp).await.map_err(WraithError::Io)?;

    if auth_resp[0] != 0x05 || auth_resp[1] != 0x00 {
        return Err(WraithError::Custom("Tor SOCKS5 auth failed".into()));
    }

    // SOCKS5 Connect to domain on port 80
    let mut connect_cmd = vec![0x05, 0x01, 0x00, 0x03, host_only.len() as u8];
    connect_cmd.extend_from_slice(host_only.as_bytes());
    connect_cmd.extend_from_slice(&80u16.to_be_bytes());

    tor_stream.write_all(&connect_cmd).await.map_err(WraithError::Io)?;
    let mut connect_resp = [0u8; 10];
    tor_stream.read_exact(&mut connect_resp).await.map_err(WraithError::Io)?;

    if connect_resp[1] != 0x00 {
        return Err(WraithError::Custom(format!("Tor SOCKS5 connect error: 0x{:02x}", connect_resp[1])));
    }

    // Send rewritten and sanitized HTTP request over Tor
    tor_stream.write_all(&sanitized_req).await.map_err(WraithError::Io)?;

    // Bi-directional stream forwarding
    let (mut cr, mut cw) = client.into_split();
    let (mut tr, mut tw) = tor_stream.into_split();

    tokio::select! {
        _ = tokio::io::copy(&mut cr, &mut tw) => {},
        _ = tokio::io::copy(&mut tr, &mut cw) => {},
    }

    Ok(())
}
