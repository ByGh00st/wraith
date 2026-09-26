//! Wraith RAM & Swap Forensics Purger
//! Flushes kernel pagecache, dentries, inodes and wipes volatile swap partitions.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::info;
use wraith_core::error::{Result, WraithError};

pub fn clear_memory_caches() -> Result<()> {
    if !Command::new("sync").status()?.success() {
        return Err(WraithError::Forensic("Filesystem sync failed; cache cleanup stopped".into()));
    }
    fs::write("/proc/sys/vm/drop_caches", "3")?;
    if Path::new("/proc/sys/vm/compact_memory").exists() {
        fs::write("/proc/sys/vm/compact_memory", "1")?;
    }
    info!("Kernel caches dropped; memory compaction requested where supported");
    Ok(())
}

pub fn overwrite_swap(is_emergency: bool) -> Result<()> {
    if is_emergency {
        return Err(WraithError::Forensic("Swap wiping is not safe during emergency shutdown; use explicit full cleanup".into()));
    }
    let output = Command::new("swapon")
        .args(["--show=NAME,SIZE,USED,PRIO", "--noheadings", "--bytes", "--raw"]).output()?;
    if !output.status.success() {
        return Err(WraithError::Forensic("Cannot enumerate active swap".into()));
    }
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 4
            || !fields[0].starts_with('/')
            || fields[0].contains('\\')
            || fields[0].contains("..")
            || fields[0].chars().any(|c| c.is_ascii_control() || c.is_ascii_whitespace())
        {
            return Err(WraithError::Forensic("Unsupported swap path; no destructive operation attempted".into()));
        }
        let device = fields[0];
        if !Path::new(device).exists() {
            return Err(WraithError::Forensic(format!("Swap target {device} does not exist")));
        }
        let size = fields[1].parse::<u64>().map_err(|e| WraithError::Forensic(e.to_string()))?;
        let uuid = Command::new("blkid").args(["-s", "UUID", "-o", "value", "--", device]).output()?;
        if !uuid.status.success() { return Err(WraithError::Forensic("Cannot read swap UUID".into())); }
        let priority = fields[3].parse::<i32>().map_err(|e| WraithError::Forensic(e.to_string()))?;
        let uuid = String::from_utf8(uuid.stdout).map_err(|e| WraithError::Forensic(e.to_string()))?;
        let uuid = uuid.trim();
        if uuid.is_empty() || !uuid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
            return Err(WraithError::Forensic(format!("Cannot preserve swap UUID for {device}")));
        }
        checked_swap_command("swapoff", &["--", device])?;
        let active = fs::read_to_string("/proc/swaps")?;
        if active.lines().skip(1).any(|line| line.split_whitespace().next() == Some(device)) {
            return Err(WraithError::Forensic(format!("{device} is still active; refusing swap wipe")));
        }
        // Wipe synchronously: no detached worker may continue writing after exit.
        // swapon SIZE excludes the swap header page. Include that page while
        // preserving the existing file length with conv=notrunc.
        #[cfg(unix)]
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        #[cfg(not(unix))]
        let page_size = 4096i64;
        if page_size <= 0 { return Err(WraithError::Forensic("Cannot determine swap page size".into())); }
        let bytes = size.checked_add(page_size as u64).ok_or_else(|| WraithError::Forensic("Invalid swap size".into()))?;
        checked_swap_command("dd", &["if=/dev/zero", &format!("of={device}"), "bs=1M",
            &format!("count={bytes}"), "iflag=count_bytes", "oflag=nofollow", "conv=notrunc,fsync", "status=none"])?;
        checked_swap_command("mkswap", &["-U", uuid, "--", device])?;
        if priority >= 0 {
            checked_swap_command("swapon", &["--priority", fields[3], "--", device])?;
        } else {
            checked_swap_command("swapon", &["--", device])?;
        }
    }
    info!("Inactive swap areas overwritten and reactivated; physical erasure depends on storage");
    Ok(())
}

fn checked_swap_command(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program).args(args).stdout(Stdio::null()).stderr(Stdio::null()).status()?;
    if !status.success() {
        return Err(WraithError::Forensic(format!("{program} failed; swap cleanup stopped, inspect swap status before retrying")));
    }
    Ok(())
}
