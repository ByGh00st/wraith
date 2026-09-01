//! Wraith Cryptographic File Shredder
//! Multi-pass pseudo-random overwrite with fsync flush and zeroized RAM buffers.

use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use tracing::debug;
use wraith_core::error::Result;
use zeroize::Zeroize;

pub fn secure_delete_file(path: &Path, passes: u8) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if let Ok(metadata) = fs::metadata(path) {
        let size = metadata.len() as usize;
        if size > 0 {
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

    fs::remove_file(path)?;

    // Force filesystem sync to mitigate cached write-back on journaling filesystems
    let _ = std::process::Command::new("sync").status();

    debug!("Cryptographically purged: {}", path.display());
    Ok(())
}
