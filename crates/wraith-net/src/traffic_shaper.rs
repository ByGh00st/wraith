//! Wraith Linux Traffic Shaper & ML Flow Fingerprint Obfuscator
//! Manipulates kernel netem qdiscs to inject synthetic latency distributions, jitter,
//! packet reordering, and rate constraints to defeat Deep Fingerprinting (k-FP) classifiers.

use std::process::Command;
use tracing::info;
use wraith_core::error::{Result, WraithError};
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
        if profile.correlation_pct > 100 || !profile.loss_pct.is_finite()
            || !(0.0..=100.0).contains(&profile.loss_pct) || profile.rate_mbit == 0 {
            return Err(WraithError::Configuration("Invalid netem profile".into()));
        }
        // Never delete or replace another application's root qdisc. `add` must
        // fail if an existing configured root occupies the interface.
        // Add netem qdisc: tc qdisc add dev <iface> root netem delay <delay>ms <jitter>ms <correlation>% rate <rate>mbit
        let delay_str = format!("{}ms", profile.delay_ms);
        let jitter_str = format!("{}ms", profile.jitter_ms);
        let corr_str = format!("{}%", profile.correlation_pct);
        let loss_str = format!("{}%", profile.loss_pct);
        let rate_str = format!("{}mbit", profile.rate_mbit);

        let status = Command::new("tc")
            .args([
                "qdisc", "add", "dev", &self.interface, "root", "handle", "a731:", "netem",
                "delay", &delay_str, &jitter_str, &corr_str,
                "distribution", "normal",
                "loss", &loss_str, "rate", &rate_str,
            ])
            .status();

        let status = status?;
        if !status.success() {
            return Err(WraithError::Network(format!("tc netem setup failed on {}: {status}", self.interface)));
        }
        self.active = true;
        info!("Netem attached on {}", self.interface);

        Ok(())
    }

    /// Detaches the root netem qdisc and restores normal latency
    pub fn restore(&mut self) -> Result<()> {
        let output = Command::new("tc").args(["qdisc", "show", "dev", &self.interface]).output()?;
        if !output.status.success() {
            return Err(WraithError::Network("Cannot inspect qdisc ownership".into()));
        }
        if owns_qdisc(&String::from_utf8_lossy(&output.stdout)) {
            let status = Command::new("tc")
                .args(["qdisc", "del", "dev", &self.interface, "root", "handle", "a731:"])
                .status()?;
            if !status.success() {
                return Err(WraithError::Network("Cannot remove Wraith netem qdisc".into()));
            }
        }
        self.active = false;

        Ok(())
    }
}

impl Drop for TrafficShaper {
    fn drop(&mut self) {
        if self.active { let _ = self.restore(); }
    }
}

// A reserved handle is an ownership convention, not protection against root.
fn owns_qdisc(output: &str) -> bool {
    output.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.starts_with(&["qdisc", "netem", "a731:"]) && fields.contains(&"root")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_requires_kind_handle_and_root() {
        assert!(owns_qdisc("qdisc netem a731: root refcnt 2 limit 1000"));
        for other in ["qdisc fq_codel 0: root", "qdisc netem 1: root", "qdisc netem a731: parent 1:1", "qdisc htb a731: root"] {
            assert!(!owns_qdisc(other));
        }
    }

    #[test]
    fn test_traffic_shaping_profile_defaults() {
        let prof = TrafficShapingProfile::default();
        assert_eq!(prof.delay_ms, 35);
        assert_eq!(prof.jitter_ms, 12);
        assert_eq!(prof.correlation_pct, 25);
        assert_eq!(prof.rate_mbit, 100);
    }
}
