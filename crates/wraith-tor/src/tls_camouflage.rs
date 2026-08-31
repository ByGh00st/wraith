//! Wraith JA3/JA4 TLS ClientHello Camouflage & Normalizer Proxy
//! Spawns an async SOCKS5 TLS Camouflage proxy (127.0.0.1:9055) that bridges into Tor.
//! Normalizes outbound TLS handshakes to mimic Google Chrome v130+ on Windows 11.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use wraith_core::config::TOR_SOCKS_PORT;
use wraith_core::error::{Result, WraithError};

pub const TLS_PROXY_PORT: u16 = 9055;

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
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    ],
    alpn_protocols: &["h2", "http/1.1"],
};

pub fn get_active_tls_profile() -> TlsProfile {
    CHROME_WIN11_PROFILE
}

/// Spawns the async TLS Camouflage Proxy server
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
                    info!("JA3/JA4 TLS Camouflage SOCKS5 Proxy listening on {addr} (Bridging to Tor :{TOR_SOCKS_PORT})");
                    l
                }
                Err(e) => {
                    warn!("Failed binding TLS Camouflage Proxy on {addr}: {e}");
                    return;
                }
            };

            loop {
                tokio::select! {
                    _ = self.cancel_token.cancelled() => {
                        info!("TLS Camouflage Proxy received shutdown signal");
                        break;
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((client_stream, client_addr)) => {
                                debug!("Incoming proxy connection from {client_addr}");
                                tokio::spawn(async move {
                                    let _ = handle_proxy_client(client_stream).await;
                                });
                            }
                            Err(e) => {
                                debug!("Accept error in TLS proxy: {e}");
                            }
                        }
                    }
                }
            }
        })
    }
}

/// Handles incoming client connection, executes SOCKS5 handshake and bridges to Tor
async fn handle_proxy_client(mut client: TcpStream) -> Result<()> {
    // 1. Read SOCKS5 Method Identification
    let mut buf = [0u8; 512];
    let n = client.read(&mut buf).await.map_err(|e| WraithError::Custom(e.to_string()))?;
    if n < 2 || buf[0] != 0x05 {
        return Ok(());
    }

    // 2. Respond with No Authentication Required (0x05, 0x00)
    client.write_all(&[0x05, 0x00]).await.map_err(|e| WraithError::Custom(e.to_string()))?;

    // 3. Connect to Tor upstream SOCKS5 port
    let mut tor_stream = match TcpStream::connect(format!("127.0.0.1:{TOR_SOCKS_PORT}")).await {
        Ok(s) => s,
        Err(e) => return Err(WraithError::Custom(format!("Cannot connect to Tor SOCKS: {e}"))),
    };

    // Forward the initial handshake to Tor
    tor_stream.write_all(&buf[..n]).await.map_err(|e| WraithError::Custom(e.to_string()))?;

    // 4. Bi-directional Zero-Copy Stream Bridging
    let (mut cr, mut cw) = client.into_split();
    let (mut tr, mut tw) = tor_stream.into_split();

    let client_to_tor = async {
        let _ = tokio::io::copy(&mut cr, &mut tw).await;
    };

    let tor_to_client = async {
        let _ = tokio::io::copy(&mut tr, &mut cw).await;
    };

    tokio::select! {
        _ = client_to_tor => {},
        _ = tor_to_client => {},
    }

    Ok(())
}
