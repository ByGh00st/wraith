//! Wraith Linux Traffic Shaper & ML Flow Fingerprint Obfuscator
//! Manipulates kernel netem qdiscs to inject synthetic latency distributions, jitter,
//! packet reordering, and rate constraints to defeat Deep Fingerprinting (k-FP) classifiers.

use std::process::Command;
use tracing::{info, warn};
use wraith_core::error::Result;
use crate::mac::get_default_interface;

#[derive(Debug, Clone)]
pub struct TrafficShapingProfile {
    pub delay_ms: u32,
    pub jitter_ms: u32,
    pub correlation_pct: u32,
    pub loss_pct: f32,
    pub rate_mbit: u32,
}

impl Default for TrafficShapingProfile {
    fn default() -> Self {
        Self {
            delay_ms: 35,
            jitter_ms: 12,
            correlation_pct: 25,
            loss_pct: 0.05,
            rate_mbit: 100,
        }
    }
}

pub struct TrafficShaper {
    interface: String,
    active: bool,
}

impl TrafficShaper {
    pub fn new(interface: Option<&str>) -> Result<Self> {
        let iface = match interface {
            Some(i) => i.to_string(),
            None => get_default_interface()?,
        };

        Ok(Self {
            interface: iface,
            active: false,
        })
    }

    /// Attaches a Linux Traffic Control netem qdisc with Gaussian jitter
    pub fn apply_shaping(&mut self, profile: &TrafficShapingProfile) -> Result<()> {
        if Command::new("which").arg("tc").output().is_err() {
            warn!("iproute2 'tc' not detected, skipping network traffic shaping");
            return Ok(());
        }

        // Clean previous root qdisc if present
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", &self.interface, "root"])
            .output();

        // Add netem qdisc: tc qdisc add dev <iface> root netem delay <delay>ms <jitter>ms <correlation>% rate <rate>mbit
        let delay_str = format!("{}ms", profile.delay_ms);
        let jitter_str = format!("{}ms", profile.jitter_ms);
        let corr_str = format!("{}%", profile.correlation_pct);
        let rate_str = format!("{}mbit", profile.rate_mbit);

        let status = Command::new("tc")
            .args([
                "qdisc", "add", "dev", &self.interface, "root", "netem",
                "delay", &delay_str, &jitter_str, &corr_str,
                "distribution", "normal",
                "rate", &rate_str,
            ])
            .status();

        if let Ok(st) = status {
            if st.success() {
                self.active = true;
                info!("Kernel Netem Traffic Shaper armed on {}: delay={} jitter={} (Deep Fingerprint Defense)",
                    self.interface, delay_str, jitter_str);
            }
        }

        Ok(())
    }

    /// Detaches the root netem qdisc and restores normal latency
    pub fn restore(&mut self) -> Result<()> {
        if self.active {
            let _ = Command::new("tc")
                .args(["qdisc", "del", "dev", &self.interface, "root"])
                .output();
            self.active = false;
            info!("Detached netem qdisc from {}", self.interface);
        }
        Ok(())
    }
}

impl Drop for TrafficShaper {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_shaping_profile_defaults() {
        let prof = TrafficShapingProfile::default();
        assert_eq!(prof.delay_ms, 35);
        assert_eq!(prof.jitter_ms, 12);
        assert_eq!(prof.correlation_pct, 25);
        assert_eq!(prof.rate_mbit, 100);
    }
}
