//! Wraith Log, History & Network Neighbor Eviction
//! Cleans logs, histories and neighbor caches while retaining active conntrack mappings.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tracing::info;
use wraith_core::error::Result;

use crate::anti_forensic_stealth::{scrub_system_logs, wipe_all_user_histories};
use crate::shred::secure_delete_file;

pub fn clear_shell_histories() -> Result<usize> {
    let cleared = wipe_all_user_histories()?;
    info!("Wiped {cleared} shell/interpreter history files via DoD 5220.22-M sanitization");
    Ok(cleared)
}

pub fn clear_dns_and_arp_caches() -> Result<()> {
    // DNS Flushes
    let _ = Command::new("systemd-resolve")
        .arg("--flush-caches")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = Command::new("resolvectl")
        .arg("flush-caches")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = Command::new("nscd")
        .args(["-i", "hosts"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    if !Command::new("ip").args(["neigh", "flush", "all"]).status()?.success() {
        return Err(wraith_core::error::WraithError::Forensic("Neighbor cache flush failed".into()));
    }
    // Conntrack entries carry active transparent-proxy translations. Flushing
    // them breaks existing Tor sockets and is not a DNS-cache operation.
    info!("Neighbor cache flushed; available DNS cache services were requested to flush");
    Ok(())
}

pub fn clear_system_logs() -> Result<usize> {
    let mut cleared = scrub_system_logs()?;
    let log_dirs = ["/var/log/wraith", "/var/log/specternet", "/var/log/tor"];

    for d in &log_dirs {
        let path = PathBuf::from(d);
        if path.exists() && path.is_dir() {
            if let Ok(entries) = fs::read_dir(&path) {
                for entry in entries.flatten() {
                    if let Ok(file_type) = entry.file_type() {
                        if file_type.is_file() {
                            secure_delete_file(&entry.path(), 1)?;
                            cleared += 1;
                        }
                    }
                }
            }
        }
    }

    info!("Scrubbed {cleared} log files and journal sinks");
    Ok(cleared)
}

pub fn fast_ram_and_arp_purge() -> Result<()> {
    crate::memory::clear_memory_caches()?;
    clear_dns_and_arp_caches()?;
    Ok(())
}

pub fn run_full_cleanup(thorough: bool, is_emergency: bool) -> Result<usize> {
    if thorough && is_emergency {
        return Err(wraith_core::error::WraithError::Forensic("Full swap cleanup is unavailable in emergency mode".into()));
    }
    clear_dns_and_arp_caches()?;
    let mut total_ops = 1 + clear_system_logs()?;
    if thorough {
        total_ops += clear_shell_histories()?;
        crate::memory::clear_memory_caches()?;
        crate::memory::overwrite_swap(false)?;
        total_ops += 2;
    }
    Ok(total_ops)
}

pub fn panic_emergency_purge(self_destruct: bool) -> Result<usize> {
    if self_destruct && wraith_core::StateManager::default().exists() {
        return Err(wraith_core::error::WraithError::Forensic("Restore the session before removing its recovery executable".into()));
    }
    let mut ops = run_full_cleanup(false, true)?;
    // Recovery state and torrc are intentionally retained until restoration.
    if self_destruct {
        secure_delete_file(&std::env::current_exe()?, 2)?;
        ops += 1;
    }
    Ok(ops)
}
