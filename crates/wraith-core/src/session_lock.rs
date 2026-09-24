//! Serialize preflight/claim and final cleanup without holding a lock while
//! asking a live worker to shut down (the worker must be able to clean itself).
use crate::error::{Result, WraithError};

pub struct SessionLock {
    #[cfg(target_os = "linux")]
    _file: nix::fcntl::Flock<std::fs::File>,
}

impl SessionLock {
    /// Release the lifecycle lock before starting the long-lived session.
    pub fn release(self) {}

    pub fn acquire() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/run/wraith.lifecycle.lock")?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
                return Err(WraithError::Configuration(
                    "Unsafe lifecycle lock ownership/mode".into(),
                ));
            }
            let file = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
                .map_err(|(_, e)| {
                WraithError::Configuration(format!(
                    "Another Wraith lifecycle operation is running: {e}"
                ))
            })?;
            Ok(Self { _file: file })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(WraithError::UnsupportedPlatform)
        }
    }
}
