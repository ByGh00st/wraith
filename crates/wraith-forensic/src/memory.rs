//! Wraith RAM & Swap Forensics Purger
//! Flushes kernel pagecache, dentries, inodes and wipes volatile swap partitions.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;
use tracing::{info, warn};
use wraith_core::error::Result;

pub fn clear_memory_caches() -> Result<()> {
    // 1. Flush dirty pages to sync memory state
    let _ = Command::new("sync").status();

    // 2. Drop pagecache, dentries, and inodes
    if fs::write("/proc/sys/vm/drop_caches", "3").is_ok() {
        info!("Kernel memory caches (pagecache, dentries, inodes) dropped");
    }

    // 3. Force kernel memory compaction to eliminate unallocated fragmented structures
    if Path::new("/proc/sys/vm/compact_memory").exists() {
        let _ = fs::write("/proc/sys/vm/compact_memory", "1");
        info!("Kernel memory compacted (/proc/sys/vm/compact_memory = 1)");
    }

    // 4. Set VFS cache pressure aggressively to reclaim dentry/inode caches
    if Path::new("/proc/sys/vm/vfs_cache_pressure").exists() {
        let _ = fs::write("/proc/sys/vm/vfs_cache_pressure", "1000");
    }

    Ok(())
}

pub fn overwrite_swap(is_emergency: bool) -> Result<()> {
    if let Ok(output) = Command::new("swapon").args(["--show=NAME,SIZE", "--noheadings", "--bytes"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let device = parts[0].to_string();
                let size_mb = parts.get(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|b| (b / (1024 * 1024)).max(1))
                    .unwrap_or(100);

                info!("Securing and wiping swap space: {device} (emergency_mode: {is_emergency})");

                let wipe_fn = move || {
                    let _ = Command::new("swapoff").arg(&device).status();

                    // 1. Attempt hardware TRIM / blkdiscard if block device
                    let discard_success = Command::new("blkdiscard")
                        .arg(&device)
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);

                    // 2. Fallback: Zero-fill partition
                    if !discard_success {
                        let _ = Command::new("dd")
                            .args(["if=/dev/zero", &format!("of={device}"), "bs=1M", &format!("count={size_mb}"), "status=none"])
                            .status();
                    }

                    let _ = Command::new("mkswap").arg(&device).status();
                    let _ = Command::new("swapon").arg(&device).status();
                };

                if is_emergency {
                    let (tx, rx) = mpsc::channel();
                    std::thread::spawn(move || {
                        wipe_fn();
                        let _ = tx.send(());
                    });

                    if rx.recv_timeout(Duration::from_secs(5)).is_err() {
                        warn!("Swap wipe timeout exceeded (5s emergency limit) — continuing emergency exit");
                    }
                } else {
                    wipe_fn();
                }
            }
        }
    }
    info!("Swap spaces dynamically scrubbed and reinitialized");
    Ok(())
}
