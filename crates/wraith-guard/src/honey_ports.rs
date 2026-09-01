//! Wraith Localhost Honeypot & Rogue Lateral Movement Trap
//! Binds deceptive synthetic decoy listeners on unused sensitive localhost ports (22, 3306, 5432, 6379, 8080)
//! to detect and alert on unauthorized local reconnaissance attempts by malware or rogue scripts.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub const DECOY_PORTS: &[u16] = &[2222, 3306, 5432, 6379, 8080, 27017];

pub struct HoneyPortTrap {
    alerts_triggered: Arc<AtomicU32>,
    cancel_token: CancellationToken,
}

impl Default for HoneyPortTrap {
    fn default() -> Self {
        Self::new()
    }
}

impl HoneyPortTrap {
    pub fn new() -> Self {
        Self {
            alerts_triggered: Arc::new(AtomicU32::new(0)),
            cancel_token: CancellationToken::new(),
        }
    }

    /// Spawns decoy honeypot listeners across all configured ports
    pub fn spawn_honeypots(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        for &port in DECOY_PORTS {
            let cancel = self.cancel_token.clone();
            let alerts = self.alerts_triggered.clone();

            let handle = tokio::spawn(async move {
                let bind_addr = format!("127.0.0.1:{port}");
                if let Ok(listener) = TcpListener::bind(&bind_addr).await {
                    info!("Honeypot Decoy Trap listening on {bind_addr}");

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                break;
                            }
                            res = listener.accept() => {
                                match res {
                                    Ok((_stream, peer_addr)) => {
                                        alerts.fetch_add(1, Ordering::SeqCst);
                                        error!("🚨 HONEYPOT INTRUSION: Rogue local process connected to decoy port :{port} from {peer_addr}!");
                                    }
                                    Err(e) => {
                                        warn!("Honeypot accept error on :{port}: {e}");
                                    }
                                }
                            }
                        }
                    }
                }
            });

            handles.push(handle);
        }

        handles
    }

    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }
}
