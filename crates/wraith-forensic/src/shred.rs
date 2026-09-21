//! Wraith Cryptographic File Shredder
//! Multi-pass pseudo-random overwrite with fsync flush and zeroized RAM buffers.

use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use tracing::debug;
use wraith_core::error::Result;

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
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

pub fn secure_delete_file(path: &Path, passes: u8) -> Result<()> {
    use wraith_core::error::WraithError;
    use std::io::{Seek, SeekFrom};
    if passes == 0 { return Err(WraithError::Forensic("Overwrite pass count must be nonzero".into())); }
    #[cfg(target_os = "linux")]
    let (_directory, anchored) = pin_parent(path)?;
    #[cfg(target_os = "linux")]
    let path = anchored.as_path();
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if metadata.file_type().is_symlink() {
        fs::remove_file(path)?;
        return Ok(());
    }
    if !metadata.is_file() { return Err(WraithError::Forensic("Only regular files can be overwritten".into())); }
    // All writes use this one no-follow descriptor, including on SSDs. Never
    // pass a previously checked pathname to fallocate or another writer.
    let mut file = open_no_follow_write(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() { return Err(WraithError::Forensic("Target changed to a non-regular file".into())); }
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        if opened.nlink() != 1 || opened.ino() != metadata.ino() || opened.dev() != metadata.dev() {
            return Err(WraithError::Forensic("Target changed or has additional hard links".into()));
        }
    }
    let size = opened.len();
    let mut buffer = zeroize::Zeroizing::new(vec![0u8; 1024 * 1024]);
    let mut rng = rand::thread_rng();
    for _ in 0..passes {
        file.seek(SeekFrom::Start(0))?;
        let mut remaining = size;
        while remaining > 0 {
            let count = remaining.min(buffer.len() as u64) as usize;
            rng.fill_bytes(&mut buffer[..count]);
            file.write_all(&buffer[..count])?;
            remaining -= count as u64;
        }
        file.sync_all()?;
    }
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        let current = fs::symlink_metadata(path)?;
        if current.ino() != opened.ino() || current.dev() != opened.dev() {
            return Err(WraithError::Forensic("Target name changed during overwrite; refusing unlink".into()));
        }
    }
    fs::remove_file(path)?;
    debug!("Overwritten and unlinked: {} (storage snapshots and SSD remapping are outside this guarantee)", path.display());
    Ok(())
}

/// Truncate an existing log only after verifying its opened inode. Never open
/// with O_TRUNC before rejecting symlinks, devices and additional hard links.
pub(crate) fn truncate_log_file(path: &Path) -> Result<()> {
    use wraith_core::error::WraithError;
    #[cfg(target_os = "linux")]
    let (_directory, anchored) = pin_parent(path)?;
    #[cfg(target_os = "linux")]
    let path = anchored.as_path();
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(WraithError::Forensic("Log is not a regular file".into()));
    }
    let file = open_no_follow_write(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() { return Err(WraithError::Forensic("Log changed type".into())); }
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        if opened.nlink() != 1 || opened.ino() != metadata.ino() || opened.dev() != metadata.dev() {
            return Err(WraithError::Forensic("Log changed or has extra hard links".into()));
        }
    }
    file.set_len(0)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn pin_parent(path: &Path) -> Result<(fs::File, std::path::PathBuf)> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    use std::path::{Component, PathBuf};
    use wraith_core::error::WraithError;
    let absolute = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) };
    let parent = absolute.parent().ok_or_else(|| WraithError::Forensic("Missing parent".into()))?;
    let mut directory = fs::File::open("/")?;
    for component in parent.components() {
        match component {
            Component::RootDir | Component::CurDir => {},
            Component::Normal(name) => {
                let next = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name);
                directory = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(next)?;
            }
            _ => return Err(WraithError::Forensic("Invalid parent component".into())),
        }
    }
    let name = absolute.file_name().ok_or_else(|| WraithError::Forensic("Missing filename".into()))?;
    let anchored = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name);
    Ok((directory, anchored))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn log_truncation_rejects_links_without_modifying_the_target() {
        let dir = tempfile::tempdir().unwrap(); let file = dir.path().join("log");
        fs::write(&file, b"keep").unwrap();
        std::os::unix::fs::symlink(&file, dir.path().join("symlink")).unwrap();
        assert!(truncate_log_file(&dir.path().join("symlink")).is_err());
        fs::hard_link(&file, dir.path().join("hardlink")).unwrap();
        assert!(truncate_log_file(&dir.path().join("hardlink")).is_err());
        assert_eq!(fs::read(file).unwrap(), b"keep");
    }
    #[test]
    fn zero_passes_cannot_delete_data() {
        let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("data");
        fs::write(&path, b"keep").unwrap();
        assert!(secure_delete_file(&path, 0).is_err());
        assert_eq!(fs::read(path).unwrap(), b"keep");
    }
    #[cfg(unix)]
    #[test]
    fn additional_hardlink_prevents_overwrite() {
        let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("data");
        fs::write(&path, b"keep").unwrap();
        fs::hard_link(&path, dir.path().join("alias")).unwrap();
        assert!(secure_delete_file(&path, 1).is_err());
        assert_eq!(fs::read(path).unwrap(), b"keep");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn symlinked_parent_prevents_overwrite() {
        let dir = tempfile::tempdir().unwrap(); let target = dir.path().join("real");
        fs::create_dir(&target).unwrap(); fs::write(target.join("data"), b"keep").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("alias")).unwrap();
        assert!(secure_delete_file(&dir.path().join("alias/data"), 1).is_err());
        assert_eq!(fs::read(target.join("data")).unwrap(), b"keep");
    }


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
