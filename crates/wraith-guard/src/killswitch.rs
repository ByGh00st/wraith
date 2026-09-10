//! Wraith Fail-Closed Watchdog & Emergency Lockdown
//! Millisecond-interval Tor health monitor with automatic network severance upon connection drop.

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use wraith_net::{apply_ipv6_block, restore_rules, save_rules};
use wraith_tor::TorControlClient;

pub struct KillSwitch {
    cancel_token: CancellationToken,
    is_killed: Arc<AtomicBool>,
}

impl KillSwitch {
    pub fn new() -> (Self, CancellationToken) {
        Self::new_with_mode(false)
    }

    pub fn new_with_mode(_strict: bool) -> (Self, CancellationToken) {
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
            let mut recovery_rules: Option<String> = None;

            while !self.cancel_token.is_cancelled() {
                sleep(Duration::from_millis(1000)).await;

                let mut client = TorControlClient::default();
                let is_alive = tokio::time::timeout(Duration::from_secs(3), async {
                    client.connect().await.is_ok() && client.is_ready().await
                }).await.unwrap_or(false);

                if is_alive {
                    if failure_count > 0 {
                        info!("Tor daemon recovered; resetting failure count");
                        failure_count = 0;
                    }

                    if self.is_killed.load(Ordering::SeqCst) {
                        info!("Restoring standard Tor routing rules after recovery...");
                        // Restore the exact pre-lockdown policy, including namespace
                        // and WireGuard rules, rather than weakening it to defaults.
                        if apply_ipv6_block().is_ok() && recovery_rules.as_deref()
                            .map(|rules| restore_rules(rules).is_ok()).unwrap_or(false) {
                            self.is_killed.store(false, Ordering::SeqCst);
                        } else {
                            error!("Recovery failed; retaining lockdown state");
                        }
                    }
                } else {
                    failure_count = failure_count.saturating_add(1);
                    warn!("Tor health check failed ({failure_count}/2)");

                    if failure_count >= 2 {
                        if !self.is_killed.load(Ordering::SeqCst) { recovery_rules = save_rules(); }
                        self.is_killed.store(true, Ordering::SeqCst);
                        match self.emergency_lockdown() {
                            Ok(()) => { self.is_killed.store(true, Ordering::SeqCst); }
                            Err(e) => error!("Emergency lockdown incomplete; retrying: {e}"),
                        }
                    }
                }
            }

            info!("KillSwitch watchdog deactivated");
        })
    }

    fn emergency_lockdown(&self) -> wraith_core::error::Result<()> {
        // Insert a narrow gate; never flush NAT/mangle or bypass existing
        // WireGuard guards. Tor packets must still traverse the original rules.
        let uid = wraith_net::get_tor_uid()?.to_string();
        for rule in lockdown_rules(&uid) {
            let exists = Command::new("iptables").arg("-w").arg("5").arg("-C").args(&rule).status()?;
            if !exists.success() {
                let status = Command::new("iptables").args(["-w", "5", "-I"]).args(&rule).status()?;
                if !status.success() {
                    return Err(wraith_core::error::WraithError::Firewall(format!("Emergency rule failed: {status}")));
                }
            }
        }
        apply_ipv6_block()?;
        error!("Kill switch application egress gate installed");
        Ok(())
    }
}

fn lockdown_rules(uid: &str) -> Vec<Vec<String>> {
    vec![
        vec!["OUTPUT", "!", "-o", "lo", "-m", "owner", "!", "--uid-owner", uid, "-m", "comment", "--comment", "wraith-emergency", "-j", "DROP"],
        vec!["FORWARD", "-m", "comment", "--comment", "wraith-emergency", "-j", "DROP"],
    ].into_iter().map(|rule| rule.into_iter().map(str::to_owned).collect()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gate_cannot_bypass_existing_tunnel_policy() {
        let rules = lockdown_rules("123");
        assert!(rules.iter().all(|rule| rule.last().unwrap() == "DROP"));
        assert!(rules[0].windows(3).any(|fields| fields == ["!", "--uid-owner", "123"]));
        assert_eq!(rules[1][0], "FORWARD");
    }
}
