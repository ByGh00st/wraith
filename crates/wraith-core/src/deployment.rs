//! Atomic binary replacement: leave the installed file intact on staging errors.
use crate::error::{Result, WraithError};
use std::{fs, io::Write, path::Path};

pub fn install_binary(bytes: &[u8], destination: &Path) -> Result<()> {
    if bytes.is_empty() { return Err(WraithError::Configuration("Empty binary artifact".into())); }
    let parent = destination.parent().ok_or_else(|| WraithError::Configuration("Missing install directory".into()))?;
    if let Ok(meta) = fs::symlink_metadata(destination) {
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err(WraithError::Configuration("Install target must be a regular file".into()));
        }
    }
    let mut staging = tempfile::NamedTempFile::new_in(parent)?;
    staging.write_all(bytes)?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        staging.as_file().set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    staging.as_file().sync_all()?;
    staging.persist(destination).map_err(|e| e.error)?;
    #[cfg(unix)] fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_artifact_preserves_installed_binary() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("wraith");
        fs::write(&target, b"old").unwrap();
        assert!(install_binary(b"", &target).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"old");
        install_binary(b"new", &target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
    }
}
