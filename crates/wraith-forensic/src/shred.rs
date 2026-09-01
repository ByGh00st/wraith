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

pub fn secure_delete_file(path: &Path, passes: u8) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if let Ok(metadata) = fs::metadata(path) {
        let size = metadata.len() as usize;
        if size > 0 {
            let is_ssd = !is_rotational_device(path);
            
            if is_ssd {
                let discard_success = std::process::Command::new("fallocate")
                    .args(["-p", "-n", "-o", "0", "-l", &size.to_string(), path.to_string_lossy().as_ref()])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);

                if !discard_success {
                    let mut file = OpenOptions::new().write(true).open(path)?;
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
                    let mut file = OpenOptions::new().write(true).open(path)?;
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
    }

    fs::remove_file(path)?;

    // Force filesystem sync to mitigate cached write-back on journaling filesystems
    let _ = std::process::Command::new("sync").status();

    debug!("Cryptographically purged: {}", path.display());
    Ok(())
}
