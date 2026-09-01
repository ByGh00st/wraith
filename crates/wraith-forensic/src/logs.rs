//! Wraith Log, History & Network Neighbor Eviction
//! Cleans volatile logs, shell histories, ARP tables, and connection tracking tables.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::info;
use wraith_core::error::Result;

use crate::shred::secure_delete_file;

pub fn clear_shell_histories() -> Result<usize> {
    let mut cleared = 0;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());

    let target_histories = [
        format!("{home}/.bash_history"),
        format!("{home}/.zsh_history"),
        format!("{home}/.python_history"),
        "/root/.bash_history".to_string(),
        "/root/.zsh_history".to_string(),
    ];

    for hist in &target_histories {
        let p = Path::new(hist);
        if p.exists() {
            let _ = secure_delete_file(p, 1);
            let _ = fs::write(p, "");
            cleared += 1;
        }
    }

    let _ = Command::new("history").args(["-c"]).status();
    info!("Wiped {cleared} shell/interpreter history files");
    Ok(cleared)
}

pub fn clear_dns_and_arp_caches() -> Result<()> {
    // DNS Flushes
    let _ = Command::new("systemd-resolve").arg("--flush-caches").status();
    let _ = Command::new("resolvectl").arg("flush-caches").status();
    let _ = Command::new("nscd").args(["-i", "hosts"]).status();

    // ARP neighbor table flush
    let _ = Command::new("ip").args(["neigh", "flush", "all"]).status();

    // Netfilter Connection Tracking flush
    let _ = Command::new("conntrack").arg("-F").status();

    info!("DNS, ARP neighbors, and Netfilter conntrack tables flushed");
    Ok(())
}

pub fn clear_system_logs() -> Result<usize> {
    let mut cleared = 0;
    let log_dirs = ["/var/log/wraith", "/var/log/specternet", "/var/log/tor"];

    for d in &log_dirs {
        let path = PathBuf::from(d);
        if path.exists() && path.is_dir() {
            if let Ok(entries) = fs::read_dir(&path) {
                for entry in entries.flatten() {
                    if let Ok(file_type) = entry.file_type() {
                        if file_type.is_file() {
                            let _ = secure_delete_file(&entry.path(), 1);
                            cleared += 1;
                        }
                    }
                }
            }
        }
    }

    info!("Scrubbed {cleared} log files");
    Ok(cleared)
}

pub fn fast_ram_and_arp_purge() -> Result<()> {
    // 1. Instantly drop kernel pagecache, dentries, and inodes
    let _ = fs::write("/proc/sys/vm/drop_caches", "3");
    let _ = fs::write("/proc/sys/vm/compact_memory", "1");

    // 2. Instantly flush ARP neighbor cache
    let _ = Command::new("ip")
        .args(["neigh", "flush", "all"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    // 3. Instantly flush routing / conntrack cache
    let _ = Command::new("ip")
        .args(["route", "flush", "cache"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let _ = Command::new("conntrack")
        .arg("-F")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    // 4. Instantly flush DNS caches
    let _ = Command::new("resolvectl")
        .arg("flush-caches")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let _ = Command::new("systemd-resolve")
        .arg("--flush-caches")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    info!("High-speed RAM, ARP, and routing cache purge complete (<10ms)");
    Ok(())
}

pub fn run_full_cleanup(thorough: bool, is_emergency: bool) -> Result<usize> {
    let mut total_ops = 0;

    let _ = clear_dns_and_arp_caches();
    total_ops += 1;

    if let Ok(count) = clear_system_logs() {
        total_ops += count;
    }

    if thorough {
        if let Ok(count) = clear_shell_histories() {
            total_ops += count;
        }
        let _ = crate::memory::clear_memory_caches();
        let _ = crate::memory::overwrite_swap(is_emergency);
        total_ops += 2;
    }

    Ok(total_ops)
}

pub fn panic_emergency_purge(self_destruct: bool) -> Result<usize> {
    info!("EXECUTING EMERGENCY PANIC PURGE (Ctrl+C / SIGINT)");
    let mut ops = run_full_cleanup(true, true)?;

    // Shred state and config artifacts
    let ephemeral_targets = [
        "/var/run/wraith.state",
        "/run/wraith.state",
        "/etc/tor/wraithrc",
    ];

    for target in &ephemeral_targets {
        let p = Path::new(target);
        if p.exists() {
            let _ = secure_delete_file(p, 2);
            ops += 1;
        }
    }

    // Optional self-destruct (shreds current running binary from RAM/Disk)
    if self_destruct {
        if let Ok(current_exe) = std::env::current_exe() {
            info!("Self-destruct triggered: shredding {}", current_exe.display());
            let _ = secure_delete_file(&current_exe, 2);
            ops += 1;
        }
    }

    Ok(ops)
}
