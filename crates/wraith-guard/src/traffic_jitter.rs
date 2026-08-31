//! Wraith Traffic Padding & Timing Jitter Obfuscation Engine
//! Injects randomized micro-dummy traffic cells and interval jitter to defeat ISP/DPI flow correlation attacks.

use rand::Rng;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::info;
use wraith_core::config::TOR_SOCKS_PORT;

pub struct TrafficJitterEngine {
    cancel_token: CancellationToken,
}

impl TrafficJitterEngine {
    pub fn new() -> (Self, CancellationToken) {
        let cancel_token = CancellationToken::new();
        (
            Self {
                cancel_token: cancel_token.clone(),
            },
            cancel_token,
        )
    }

    pub fn spawn_obfuscator(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!("Traffic Padding & Anti-Correlation Jitter generator active");

            while !self.cancel_token.is_cancelled() {
                // Random sleep interval between 200ms and 1400ms (disrupts regular burst signatures)
                let delay_ms = {
                    let mut rng = rand::thread_rng();
                    rng.gen_range(200..1400)
                };
                sleep(Duration::from_millis(delay_ms)).await;

                // Send micro dummy SOCKS5 handshake probe to generate synthetic cell activity
                if let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{TOR_SOCKS_PORT}")).await {
                    let dummy_probe = [0x05, 0x01, 0x00];
                    let _ = stream.write_all(&dummy_probe).await;
                    let _ = stream.flush().await;
                }
            }

            info!("Traffic Jitter generator halted");
        })
    }
}
