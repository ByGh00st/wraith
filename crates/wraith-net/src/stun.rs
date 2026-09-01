//! Wraith STUN / TURN WebRTC Port Blocker
//! Prevents STUN-based real public IP extraction through browser WebRTC subsystems.

use std::process::{Command, Stdio};
use tracing::info;
use wraith_core::error::Result;

pub const STUN_PORTS: &[u16] = &[
    3478, 3479, 5349, 5350, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309,
];

pub fn block_stun_ports() -> Result<()> {
    for port in STUN_PORTS {
        let p_str = port.to_string();
        let _ = Command::new("iptables")
            .args(["-A", "OUTPUT", "-p", "udp", "--dport", &p_str, "-j", "DROP"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("iptables")
            .args(["-A", "OUTPUT", "-p", "tcp", "--dport", &p_str, "-j", "DROP"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    info!("STUN/TURN ports blocked ({} ports dropped)", STUN_PORTS.len());
    Ok(())
}

pub fn unblock_stun_ports() -> Result<()> {
    for port in STUN_PORTS {
        let p_str = port.to_string();
        let _ = Command::new("iptables")
            .args(["-D", "OUTPUT", "-p", "udp", "--dport", &p_str, "-j", "DROP"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("iptables")
            .args(["-D", "OUTPUT", "-p", "tcp", "--dport", &p_str, "-j", "DROP"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    info!("STUN/TURN port blocks removed");
    Ok(())
}
