//! Retryable snapshots for root-managed session configuration files.
use crate::error::{Result, WraithError};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileSnapshot {
    Missing,
    File {
        bytes: Vec<u8>,
        mode: u32,
        uid: u32,
        gid: u32,
    },
    Symlink {
        target: PathBuf,
    },
}

impl FileSnapshot {
    pub fn capture(path: &Path) -> Result<Self> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::Missing),
            Err(e) => return Err(e.into()),
        };
        if metadata.file_type().is_symlink() {
            return Ok(Self::Symlink {
                target: fs::read_link(path)?,
            });
        }
        if !metadata.is_file() || metadata.len() > 1024 * 1024 {
            return Err(WraithError::Configuration(
                "Session configuration must be a regular file under 1 MiB".into(),
            ));
        }
        #[cfg(unix)]
        let (mode, uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            (metadata.mode(), metadata.uid(), metadata.gid())
        };
        #[cfg(not(unix))]
        let (mode, uid, gid) = (0, 0, 0);
        Ok(Self::File {
            bytes: fs::read(path)?,
            mode,
            uid,
            gid,
        })
    }

    pub fn restore(&self, path: &Path) -> Result<()> {
        if Self::capture(path)? == *self {
            return Ok(());
        }
        match self {
            Self::Missing => match fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            },
            Self::File {
                bytes,
                mode,
                uid,
                gid,
            } => {
                let parent = path
                    .parent()
                    .ok_or_else(|| WraithError::Configuration("Missing snapshot parent".into()))?;
                let mut temp = tempfile::NamedTempFile::new_in(parent)?;
                temp.write_all(bytes)?;
                #[cfg(unix)]
                {
                    use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
                    // SAFETY: fchown operates only on the freshly opened temporary file.
                    if unsafe { libc::fchown(temp.as_raw_fd(), *uid, *gid) } != 0 {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    temp.as_file()
                        .set_permissions(fs::Permissions::from_mode(*mode))?;
                }
                #[cfg(not(unix))]
                let _ = (mode, uid, gid);
                temp.as_file().sync_all()?;
                temp.persist(path).map_err(|e| e.error)?;
                Ok(())
            }
            Self::Symlink { target } => restore_symlink(path, target),
        }
    }
}

#[cfg(unix)]
fn restore_symlink(path: &Path, target: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| WraithError::Configuration("Missing symlink parent".into()))?;
    let temp = tempfile::tempdir_in(parent)?;
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(target, &link)?;
    fs::rename(link, path)?;
    Ok(())
}
#[cfg(not(unix))]
fn restore_symlink(_: &Path, _: &Path) -> Result<()> {
    Err(WraithError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_preserves_original_and_supports_retry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        fs::write(&path, b"original").unwrap();
        let snapshot = FileSnapshot::capture(&path).unwrap();
        fs::write(&path, b"session").unwrap();
        snapshot.restore(&path).unwrap();
        snapshot.restore(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"original");
        let absent = dir.path().join("absent");
        let snapshot = FileSnapshot::capture(&absent).unwrap();
        fs::write(&absent, b"created").unwrap();
        snapshot.restore(&absent).unwrap();
        assert!(!absent.exists());
    }
    #[cfg(unix)]
    #[test]
    fn resolver_symlink_restored_without_overwriting_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("resolv");
        fs::write(&target, b"resolver").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let snapshot = FileSnapshot::capture(&link).unwrap();
        fs::remove_file(&link).unwrap();
        fs::write(&link, b"local").unwrap();
        snapshot.restore(&link).unwrap();
        assert_eq!(fs::read_link(&link).unwrap(), target);
        assert_eq!(fs::read(&link).unwrap(), b"resolver");
    }
}
