//! Wraith Cryptographic File Shredder
//! Multi-pass pseudo-random overwrite with fsync flush and zeroized RAM buffers.

use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use tracing::{debug, warn, info};
use wraith_core::error::Result;
use zeroize::Zeroize;

pub fn is_rotational_device(path: &Path) -> bool {
    if let Ok(out) = std::process::Command::new("df").arg("-P").arg(path).output() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(line) = stdout.lines().nth(1) {
            if let Some(dev) = line.split_whitespace().next() {
                let dev_name = dev.trim_start_matches("/dev/");
                let sys_path = format!("/sys/block/{}/queue/rotational", dev_name);
                if let Ok(val) = std::fs::read_to_string(&sys_path) {
                    return val.trim() == "1";
                }
                let base_dev = dev_name.trim_end_matches(|c: char| c.is_ascii_digit() || c == 'p');
                let sys_path_base = format!("/sys/block/{}/queue/rotational", base_dev);
                if let Ok(val) = std::fs::read_to_string(&sys_path_base) {
                    return val.trim() == "1";
                }
                return false; // Could not confirm rotational, assume SSD
            }
        }
    }
    true // default to rotational if unknown
}

fn open_no_follow_write(path: &Path) -> std::io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

pub fn secure_delete_file(path: &Path, passes: u8) -> Result<()> {
    // CRITICAL: Symlink defense — never follow symlinks into target files
    let sym_meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };

    if sym_meta.file_type().is_symlink() {
        warn!("Refusing to shred symlink target {:?} — removing link only", path);
        let _ = fs::remove_file(path);
        return Ok(());
    }

    let size = sym_meta.len() as usize;
    if size > 0 {
        let is_ssd = !is_rotational_device(path);
        
        if is_ssd {
            let discard_success = std::process::Command::new("fallocate")
                .args(["-p", "-n", "-o", "0", "-l", &size.to_string(), path.to_string_lossy().as_ref()])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

            if !discard_success {
                let mut file = open_no_follow_write(path)?;
                let buffer = vec![0u8; size.min(1024 * 1024)];
                let mut written = 0;
                while written < size {
                    let to_write = (size - written).min(buffer.len());
                    file.write_all(&buffer[..to_write])?;
                    written += to_write;
                }
                file.sync_all()?;
                warn!("SSD detected on {path:?}: fallocate punch-hole failed, fell back to single pass zero-fill. Note: In-place overwriting on SSD is not perfectly secure due to wear-leveling.");
            } else {
                info!("SSD detected: Successfully applied fallocate punch-hole (TRIM) on {path:?}");
            }
        } else {
            let mut rng = rand::thread_rng();
            let mut buffer = vec![0u8; size.min(1024 * 1024)]; // 1MB chunk

            for _ in 0..passes {
                let mut file = open_no_follow_write(path)?;
                let mut written = 0;
                while written < size {
                    let to_write = (size - written).min(buffer.len());
                    rng.fill_bytes(&mut buffer[..to_write]);
                    file.write_all(&buffer[..to_write])?;
                    written += to_write;
                }
                file.sync_all()?;
            }

            buffer.zeroize();
        }
    }

    fs::remove_file(path)?;

    // Force filesystem sync to mitigate cached write-back on journaling filesystems
    let _ = std::process::Command::new("sync").status();

    debug!("Cryptographically purged: {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_delete_file_basic() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let test_file = temp_dir.path().join("secure_delete_target.bin");
        fs::write(&test_file, b"CONFIDENTIAL OVERWRITE TEST").expect("write test file");
        assert!(test_file.exists());

        let res = secure_delete_file(&test_file, 2);
        assert!(res.is_ok());
        assert!(!test_file.exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_secure_delete_symlink_preserves_target() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let target_file = temp_dir.path().join("legit_target.txt");
        let symlink_file = temp_dir.path().join("malicious_symlink.lnk");

        fs::write(&target_file, b"SENSITIVE TARGET DATA").expect("write target");
        std::os::unix::fs::symlink(&target_file, &symlink_file).expect("create symlink");

        let res = secure_delete_file(&symlink_file, 2);
        assert!(res.is_ok());

        assert!(!symlink_file.exists());
        assert!(target_file.exists());
        let content = fs::read(&target_file).expect("read target");
        assert_eq!(content, b"SENSITIVE TARGET DATA");
    }
}
