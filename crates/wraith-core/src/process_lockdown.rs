#[cfg(unix)]
use tracing::info;
#[cfg(unix)]
use crate::error::WraithError;
use crate::error::Result;

pub fn enforce_process_lockdown() -> Result<()> {
    #[cfg(unix)]
    {
        // 1. Prevent core dumps and /proc/$PID/mem reading from other processes
        // PR_SET_DUMPABLE = 0
        // SAFETY: Invoking prctl with PR_SET_DUMPABLE and PR_SET_NO_NEW_PRIVS, and mlockall to lock pages in memory. All arguments are valid constants/primitives.
        unsafe {
            let res = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            if res != 0 {
                return Err(WraithError::Custom(format!(
                    "Failed to set PR_SET_DUMPABLE=0 (errno: {})",
                    std::io::Error::last_os_error()
                )));
            }

            // 2. Prevent gaining new privileges via setuid binaries (PR_SET_NO_NEW_PRIVS = 1)
            let res = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if res != 0 {
                return Err(WraithError::Custom(format!(
                    "Failed to set PR_SET_NO_NEW_PRIVS=1 (errno: {})",
                    std::io::Error::last_os_error()
                )));
            }

            // 3. Lock memory pages into RAM (MCL_CURRENT | MCL_FUTURE) so keys/buffers never hit swap
            let res = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
            if res != 0 {
                // Non-fatal if RLIMIT_MEMLOCK is exceeded, but log warning
                tracing::warn!(
                    "mlockall warning (non-fatal): {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        info!("Kernel process lockdown enforced: PR_SET_DUMPABLE=0, NO_NEW_PRIVS=1, mlockall active");
    }
    Ok(())
}
