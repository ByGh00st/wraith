//! Bounded HTTPS cover requests over Tor to an operator-selected endpoint.
//! This produces real application traffic, not a proof of correlation resistance.

use rand::Rng;
use std::time::Duration;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use wraith_core::error::Result;
use wraith_tor::{validate_https_url, BrowserProfile, BrowserTlsClient};

pub struct TrafficJitterEngine {
    cancel_token: CancellationToken,
    client: BrowserTlsClient,
    endpoint: String,
}

impl TrafficJitterEngine {
    pub fn new(endpoint: &str) -> Result<(Self, CancellationToken)> {
        validate_https_url(endpoint)?;
        let cancel_token = CancellationToken::new();
        Ok((
            Self {
                cancel_token: cancel_token.clone(),
                client: BrowserTlsClient::new(BrowserProfile::Chrome)?,
                endpoint: endpoint.into(),
            },
            cancel_token,
        ))
    }

    pub fn spawn_obfuscator(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!("Tor HTTPS cover-request worker active; response cap 16 KiB");

            while !self.cancel_token.is_cancelled() {
                // Bound request frequency and jitter without targeting a built-in third party.
                let delay_ms = {
                    let mut rng = rand::thread_rng();
                    rng.gen_range(15000..45000)
                };
                tokio::select! {
                    _ = self.cancel_token.cancelled() => break,
                    _ = sleep(Duration::from_millis(delay_ms)) => {}
                }
                tokio::select! {
                    _ = self.cancel_token.cancelled() => break,
                    result = self.client.get(&self.endpoint, 16 * 1024) => {
                        match result {
                            Ok(response) => debug!(status = response.status, bytes = response.body.len(), "Cover request completed"),
                            Err(error) => debug!(%error, "Cover request failed; no direct fallback"),
                        }
                    }
                }
            }

            info!("Traffic Jitter generator halted");
        })
    }
}
