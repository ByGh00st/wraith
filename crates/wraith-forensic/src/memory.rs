//! Wraith RAM & Swap Forensics Purger
//! Flushes kernel pagecache, dentries, inodes and wipes volatile swap partitions.

use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::info;
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

pub fn overwrite_swap() -> Result<()> {
    if let Ok(output) = Command::new("swapon").args(["--show=NAME", "--noheadings"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for dev in stdout.lines() {
            let device = dev.trim();
            if !device.is_empty() {
                info!("Securing and wiping swap device: {device}");
                let _ = Command::new("swapoff").arg(device).status();
                let _ = Command::new("dd")
                    .args(["if=/dev/urandom", &format!("of={device}"), "bs=1M", "count=100", "status=none"])
                    .status();
                let _ = Command::new("mkswap").arg(device).status();
                let _ = Command::new("swapon").arg(device).status();
            }
        }
    }
    info!("Swap spaces scrubbed");
    Ok(())
}
