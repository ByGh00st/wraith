//! Wraith Tor Daemon Lifecycle & Config Management
//! Handles torrc templating, startup verification, and safe DNS redirection.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};
use wraith_core::config::{
    RESOLV_BACKUP, RESOLV_CONTENT, RESOLV_PATH, TORRC_PATH, TORRC_TEMPLATE, TOR_CONTROL_PORT,
    TOR_DNS_PORT, TOR_TRANS_PORT, TOR_USER,
};
use wraith_core::error::{Result, WraithError};

use crate::control::TorControlClient;

pub fn write_torrc() -> Result<bool> {
    let torrc_content = TORRC_TEMPLATE
        .replace("{trans_port}", &TOR_TRANS_PORT.to_string())
        .replace("{dns_port}", &TOR_DNS_PORT.to_string())
        .replace("{control_port}", &TOR_CONTROL_PORT.to_string());

    let path = Path::new(TORRC_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    if path.exists() {
        if let Ok(current) = fs::read_to_string(path) {
            if current == torrc_content {
                return Ok(false);
            }
        }
    }

    fs::write(path, torrc_content)?;
    info!("Tor configuration written to {TORRC_PATH}");
    Ok(true)
}

pub fn backup_resolv() -> Result<bool> {
    let resolv = Path::new(RESOLV_PATH);
    let backup = Path::new(RESOLV_BACKUP);

    if resolv.exists() {
        let content = fs::read_to_string(resolv)?;
        if content.trim() != RESOLV_CONTENT.trim() {
            fs::copy(resolv, backup)?;
            info!("DNS configuration backed up to {RESOLV_BACKUP}");
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn configure_dns() -> Result<()> {
    let resolv = Path::new(RESOLV_PATH);
    // 1. Remove immutable attribute if present before write
    let _ = Command::new("chattr").args(["-i", RESOLV_PATH]).output();

    if resolv.exists() {
        if let Ok(current) = fs::read_to_string(resolv) {
            if current.trim() == RESOLV_CONTENT.trim() {
                // Ensure immutable attribute is active
                let _ = Command::new("chattr").args(["+i", RESOLV_PATH]).output();
                return Ok(());
            }
        }
    }

    fs::write(resolv, RESOLV_CONTENT)?;
    // Lock /etc/resolv.conf as immutable to prevent NetworkManager or systemd-resolved race-conditions
    let _ = Command::new("chattr").args(["+i", RESOLV_PATH]).output();
    info!("DNS configured to use Tor transparent resolver (127.0.0.1) and locked immutable (+i)");
    Ok(())
}

pub fn restore_dns() -> Result<()> {
    let backup = Path::new(RESOLV_BACKUP);
    let resolv = Path::new(RESOLV_PATH);

    // Remove immutable lock before restoring
    let _ = Command::new("chattr").args(["-i", RESOLV_PATH]).output();

    if backup.exists() {
        fs::rename(backup, resolv)?;
        info!("DNS configuration restored from backup");
    } else {
        fs::write(resolv, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n")?;
        warn!("No backup found; fallback upstream DNS applied");
    }
    Ok(())
}

pub fn stop_existing_tor() {
    let _ = Command::new("systemctl").args(["stop", "tor"]).status();
    let _ = Command::new("fuser").args(["-k", &format!("{TOR_CONTROL_PORT}/tcp")]).status();
    std::thread::sleep(Duration::from_millis(500));
}

pub async fn start_tor_daemon() -> Result<()> {
    stop_existing_tor();

    let tor_bin = if Path::new("/usr/bin/tor").exists() {
        "/usr/bin/tor"
    } else if Path::new("/usr/local/bin/tor").exists() {
        "/usr/local/bin/tor"
    } else {
        "tor"
    };

    info!("Spawning Tor daemon process...");

    let status = Command::new("sudo")
        .args(["-u", TOR_USER, tor_bin, "-f", TORRC_PATH])
        .status()
        .map_err(|e| WraithError::Tor(format!("Failed to spawn Tor daemon: {e}")))?;

    if !status.success() {
        // Fallback: spawn as root/current user if debian-tor user fails
        let _ = Command::new(tor_bin).args(["-f", TORRC_PATH]).status();
    }

    // Wait for Tor bootstrap on ControlPort
    for _ in 0..30 {
        sleep(Duration::from_secs(1)).await;
        let mut client = TorControlClient::default();
        if client.connect().await.is_ok() && client.is_alive().await {
            info!("Tor daemon initialized and responsive on ControlPort");
            return Ok(());
        }
    }

    Err(WraithError::Tor("Tor daemon started but failed to bootstrap within 30s".into()))
}

pub fn stop_tor_daemon() {
    stop_existing_tor();
    info!("Tor daemon stopped");
}
