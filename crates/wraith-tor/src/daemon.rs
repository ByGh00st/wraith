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

pub fn resolve_tor_user() -> &'static str {
    for u in ["debian-tor", "tor", "toranon", "_tor"] {
        if Command::new("id")
            .args(["-u", u])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return u;
        }
    }
    TOR_USER
}


const SYSTEM_TOR_SERVICES: &[&str] = &["tor.service", "tor@default.service"];

pub fn active_system_tor_services() -> Result<Vec<String>> {
    if !Path::new("/run/systemd/system").exists() { return Ok(Vec::new()); }
    let mut active = Vec::new();
    for service in SYSTEM_TOR_SERVICES {
        let status = Command::new("systemctl").args(["is-active", "--quiet", service]).status()?;
        match status.code() {
            Some(0) => active.push((*service).into()),
            Some(3 | 4) => {},
            _ => return Err(WraithError::Tor(format!("Cannot determine service state: {service}"))),
        }
    }
    Ok(active)
}

pub fn set_system_tor_services(services: &[String], start: bool) -> Result<()> {
    let mut errors = Vec::new();
    for service in services {
        if !SYSTEM_TOR_SERVICES.contains(&service.as_str()) {
            return Err(WraithError::Tor("Unrecognized saved Tor service".into()));
        }
    }
    for service in services {
        let status = Command::new("systemctl").args([if start { "start" } else { "stop" }, service]).status();
        if !status.is_ok_and(|status| status.success()) { errors.push(service.clone()); }
    }
    if errors.is_empty() { Ok(()) }
    else { Err(WraithError::Tor(format!("Service transition failed: {}", errors.join(", ")))) }
}

#[cfg(any(target_os = "linux", test))]
fn managed_tor_command(cmdline: &[u8]) -> bool {
    let args: Vec<_> = cmdline.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
    args.first().is_some_and(|arg| arg.rsplit(|b| *b == b'/').next() == Some(b"tor".as_slice()))
        && args.windows(2).any(|pair| pair == [b"-f".as_slice(), TORRC_PATH.as_bytes()])
}

/// Stop only Tor processes launched with our exact configuration argument.
pub fn stop_existing_tor() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut targets = Vec::new();
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<i32>().ok()).filter(|pid| *pid > 1) else { continue; };
            if fs::read(entry.path().join("cmdline")).is_ok_and(|line| managed_tor_command(&line)) {
                let before = fs::read(entry.path().join("stat"))?;
                let start = process_start(&before).ok_or_else(|| WraithError::Tor("Invalid Tor process identity".into()))?.to_vec();
                // A pidfd binds the signal to one process lifetime even if a PID
                // is recycled between inspection and delivery.
                use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
                let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
                if raw < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::ESRCH) { continue; }
                    return Err(error.into());
                }
                let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
                if !fs::read(entry.path().join("stat")).is_ok_and(|stat| process_start(&stat) == Some(start.as_slice())) { continue; }
                if unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd.as_raw_fd(), libc::SIGTERM, std::ptr::null::<libc::siginfo_t>(), 0) } != 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) { return Err(error.into()); }
                }
                targets.push((pid, start));
            }
        }
        for _ in 0..50 {
            targets.retain(|(pid, start)| fs::read(format!("/proc/{pid}/stat")).ok()
                .is_some_and(|stat| process_start(&stat) == Some(start.as_slice()) && !stat.windows(4).any(|w| w == b") Z ")));
            if targets.is_empty() { return Ok(()); }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(WraithError::Tor("Managed Tor has not stopped; recovery record must be retained".into()))
    }
    #[cfg(not(target_os = "linux"))]
    { Err(WraithError::UnsupportedPlatform) }
}

#[cfg(target_os = "linux")]
fn process_start(stat: &[u8]) -> Option<&[u8]> {
    let end = stat.iter().rposition(|b| *b == b')')?;
    stat.get(end + 2..)?.split(|b| *b == b' ').nth(19)
}

fn prepare_tor_directory(path: &str, user: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() =>
            return Err(WraithError::Tor(format!("Unsafe Tor directory: {path}"))),
        Ok(_) => {},
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        Err(e) => return Err(e.into()),
    }
    for (command, args) in [("chown", vec![user, path]), ("chmod", vec!["700", path])] {
        if !Command::new(command).args(args).status()?.success() {
            return Err(WraithError::Tor(format!("Cannot prepare Tor directory: {path}")));
        }
    }
    Ok(())
}

pub async fn start_tor_daemon_with_timeout(timeout_secs: u64) -> Result<()> {
    stop_existing_tor()?;
    // Keep every reservation until the final probe has succeeded.
    let mut probes = Vec::new();
    for port in [TOR_TRANS_PORT, TOR_DNS_PORT, 9050, TOR_CONTROL_PORT] {
        probes.push(std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .map_err(|e| WraithError::Tor(format!("Tor port {port} is occupied: {e}; no unrelated process was killed")))?);
    }
    let udp_probe = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, TOR_DNS_PORT))?;
    let tor_user = resolve_tor_user();
    for dir in ["/var/lib/wraith/tor", "/run/wraith-tor"] { prepare_tor_directory(dir, tor_user)?; }
    let group = Command::new("id").args(["-g", tor_user]).output()?;
    if !group.status.success() || !fs::symlink_metadata(TORRC_PATH)?.is_file() {
        return Err(WraithError::Tor("Cannot prepare managed Tor configuration permissions".into()));
    }
    let gid = String::from_utf8_lossy(&group.stdout).trim().parse::<u32>()
        .map_err(|_| WraithError::Tor("Invalid Tor group ID".into()))?;
    for (program, args) in [("chown", vec![format!("0:{gid}"), TORRC_PATH.into()]), ("chmod", vec!["640".into(), TORRC_PATH.into()])] {
        if !Command::new(program).args(args).status()?.success() {
            return Err(WraithError::Tor("Cannot set managed Tor configuration permissions".into()));
        }
    }
    let tor_bin = ["/usr/bin/tor", "/usr/local/bin/tor"].into_iter().find(|p| Path::new(p).is_file())
        .ok_or_else(|| WraithError::Tor("Tor executable is missing".into()))?;
    let runuser = ["/usr/sbin/runuser", "/sbin/runuser", "/usr/bin/runuser", "/bin/runuser"].into_iter().find(|p| Path::new(p).is_file())
        .ok_or_else(|| WraithError::Tor("runuser is required to drop Tor privileges".into()))?;
    drop(probes); drop(udp_probe);
    let output = tokio::time::timeout(Duration::from_secs(15), tokio::process::Command::new(runuser)
        .args(["-u", tor_user, "--", tor_bin, "-f", TORRC_PATH]).kill_on_drop(true).output()).await
        .map_err(|_| WraithError::Tor("Tor launcher timed out".into()))??;
    if !output.status.success() {
        return Err(WraithError::Tor(format!("Tor startup failed: {}", String::from_utf8_lossy(&output.stderr))));
    }
    tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        loop {
            let mut client = TorControlClient::default();
            if client.connect().await.is_ok() && client.is_ready().await { return; }
            sleep(Duration::from_secs(1)).await;
        }
    }).await.map_err(|_| WraithError::Tor(format!("Tor failed to bootstrap within {timeout_secs}s")))?;
    info!("Managed Tor initialized");
    Ok(())
}

pub async fn start_tor_daemon() -> Result<()> { start_tor_daemon_with_timeout(45).await }
pub fn stop_tor_daemon() -> Result<()> { stop_existing_tor() }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_matching_requires_tor_and_exact_configuration_argument() {
        assert!(managed_tor_command(b"/usr/bin/tor\0-f\0/etc/tor/wraithrc\0"));
        for unrelated in [b"tor\0-f\0/etc/tor/torrc\0".as_slice(), b"editor\0/etc/tor/wraithrc\0", b"tor\0-f\0/etc/tor/wraithrc.other\0", b"other-tor\0-f\0/etc/tor/wraithrc\0"] {
            assert!(!managed_tor_command(unrelated));
        }
    }
}
