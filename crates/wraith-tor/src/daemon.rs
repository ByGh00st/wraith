//! Wraith Tor Daemon Lifecycle & Config Management
//! Handles torrc templating, startup verification, and safe DNS redirection.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;
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
    // Replace the resolver entry, never write through systemd-resolved's symlink
    // or change persistent inode flags. The original entry is journaled by CLI.
    wraith_core::file_snapshot::FileSnapshot::File {
        bytes: RESOLV_CONTENT.as_bytes().to_vec(), mode: 0o644, uid: 0, gid: 0,
    }.restore(Path::new(RESOLV_PATH))?;
    info!("DNS configured to use the local validated relay");
    Ok(())
}

pub fn restore_dns() -> Result<()> {
    let backup = Path::new(RESOLV_BACKUP);
    let resolv = Path::new(RESOLV_PATH);

    // Remove immutable lock before restoring
    let _ = Command::new("chattr").args(["-i", RESOLV_PATH]).stdout(Stdio::null()).stderr(Stdio::null()).output();

    if !backup.exists() {
        return Err(WraithError::Configuration("Resolver backup missing; refusing to invent fallback DNS".into()));
    }
    // Retain backup for retries if another cleanup step subsequently fails.
    fs::copy(backup, resolv)?;
    info!("DNS configuration restored from backup");
    Ok(())
}

pub fn restore_dns_snapshot(content: &str) -> Result<()> {
    let _ = Command::new("chattr").args(["-i", RESOLV_PATH]).stdout(Stdio::null()).stderr(Stdio::null()).output();
    fs::write(RESOLV_PATH, content)?;
    if fs::read_to_string(RESOLV_PATH)? != content {
        return Err(WraithError::Configuration("Resolver restoration verification failed".into()));
    }
    Ok(())
}

pub fn stop_existing_tor() {
    // Target only Wraith-managed Tor processes matching our specific torrc configuration
    let _ = Command::new("pkill")
        .args(["-f", &format!("tor.*-f.*{TORRC_PATH}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    std::thread::sleep(Duration::from_millis(500));
}

pub async fn start_tor_daemon_with_timeout(timeout_secs: u64) -> Result<()> {
    stop_existing_tor();

    // Terminate any standard systemd Tor service that may hog ports 9050/9051
    let _ = Command::new("systemctl").args(["stop", "tor"]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    let _ = Command::new("systemctl").args(["stop", "tor@default"]).stdout(Stdio::null()).stderr(Stdio::null()).status();

    let tor_bin = if Path::new("/usr/bin/tor").exists() {
        "/usr/bin/tor"
    } else if Path::new("/usr/local/bin/tor").exists() {
        "/usr/local/bin/tor"
    } else {
        "tor"
    };

    info!("Spawning Tor daemon process...");

    // Ensure Tor runtime and data directories exist with correct permissions and ownership
    for dir in ["/run/tor", "/var/lib/tor"] {
        let p = Path::new(dir);
        if !p.exists() {
            let _ = fs::create_dir_all(p);
        }
        let _ = Command::new("chown").args(["-R", &format!("{TOR_USER}:{TOR_USER}"), dir]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        let _ = Command::new("chmod").args(["700", dir]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }

    let output = Command::new("sudo")
        .args(["-u", TOR_USER, tor_bin, "-f", TORRC_PATH])
        .output()
        .map_err(|e| WraithError::Tor(format!("Failed to spawn Tor daemon: {e}")))?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        return Err(WraithError::Tor(format!("Tor failed to start as {TOR_USER}: {err_msg}")));
    }

    // Wait for Tor bootstrap on ControlPort
    for _ in 0..timeout_secs {
        sleep(Duration::from_secs(1)).await;
        let mut client = TorControlClient::default();
        if client.connect().await.is_ok() && client.is_ready().await {
            info!("Tor daemon initialized and responsive on ControlPort");
            return Ok(());
        }
    }

    Err(WraithError::Tor(format!("Tor daemon started but failed to bootstrap within {timeout_secs}s")))
}

pub async fn start_tor_daemon() -> Result<()> {
    start_tor_daemon_with_timeout(45).await
}

pub fn stop_tor_daemon() {
    stop_existing_tor();
    info!("Tor daemon stopped");
}
