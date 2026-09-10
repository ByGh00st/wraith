//! Wraith Fail-Closed Watchdog & Emergency Lockdown
//! Millisecond-interval Tor health monitor with automatic network severance upon connection drop.

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use wraith_net::{apply_ipv6_block, apply_tor_rules};
use wraith_tor::TorControlClient;

pub struct KillSwitch {
    cancel_token: CancellationToken,
    is_killed: Arc<AtomicBool>,
}

impl KillSwitch {
    pub fn new() -> (Self, CancellationToken) {
        let cancel_token = CancellationToken::new();
        (
            Self {
                cancel_token: cancel_token.clone(),
                is_killed: Arc::new(AtomicBool::new(false)),
            },
            cancel_token,
        )
    }

    pub fn is_killed(&self) -> bool {
        self.is_killed.load(Ordering::SeqCst)
    }

    pub fn spawn_monitor(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!("KillSwitch Fail-Closed watchdog active (1000ms polling cycle)");
            let mut failure_count = 0u8;

            while !self.cancel_token.is_cancelled() {
                sleep(Duration::from_millis(1000)).await;

                let mut client = TorControlClient::default();
                let is_alive = client.connect().await.is_ok() && client.is_alive().await;

                if is_alive {
                    if failure_count > 0 {
                        info!("Tor daemon recovered; resetting failure count");
                        failure_count = 0;
                    }

                    if self.is_killed.load(Ordering::SeqCst) {
                        info!("Restoring standard Tor routing rules after recovery...");
                        self.is_killed.store(false, Ordering::SeqCst);
                        let _ = apply_tor_rules();
                        let _ = apply_ipv6_block();
                    }
                } else {
                    failure_count += 1;
                    warn!("Tor health check failed ({failure_count}/2)");

                    if failure_count >= 2 && !self.is_killed.load(Ordering::SeqCst) {
                        self.emergency_lockdown();
                    }
                }
            }

            info!("KillSwitch watchdog deactivated");
        })
    }

    fn emergency_lockdown(&self) {
        error!("KILLSWITCH TRIGGERED — Immediate global egress blackout enforced!");
        self.is_killed.store(true, Ordering::SeqCst);

        // 1. Enforce strict DROP policy FIRST to eliminate race condition window
        let _ = Command::new("iptables").args(["-P", "OUTPUT", "DROP"]).status();
        let _ = Command::new("iptables").args(["-P", "FORWARD", "DROP"]).status();
        let _ = Command::new("iptables").args(["-P", "INPUT", "DROP"]).status();

        // 2. Flush existing filter and NAT rules while DROP policies are strictly holding
        let _ = Command::new("iptables").args(["-F"]).status();
        let _ = Command::new("iptables").args(["-X"]).status();
        let _ = Command::new("iptables").args(["-t", "nat", "-F"]).status();
        let _ = Command::new("iptables").args(["-t", "nat", "-X"]).status();

        // 3. Only allow local loopback communications
        let _ = Command::new("iptables").args(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"]).status();
        let _ = Command::new("iptables").args(["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]).status();

        // 4. Enforce strict IPv6 total blackout
        let _ = Command::new("ip6tables").args(["-P", "INPUT", "DROP"]).status();
        let _ = Command::new("ip6tables").args(["-P", "OUTPUT", "DROP"]).status();
        let _ = Command::new("ip6tables").args(["-P", "FORWARD", "DROP"]).status();
        let _ = Command::new("ip6tables").args(["-F"]).status();
        let _ = Command::new("ip6tables").args(["-X"]).status();

        let _ = apply_ipv6_block();
    }
}
