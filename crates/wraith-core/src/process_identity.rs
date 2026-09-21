//! Process lifetime identity for session ownership, independent of process names.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub boot_id: String,
    pub start_ticks: u64,
    pub executable_device: u64,
    pub executable_inode: u64,
}

#[cfg(any(target_os = "linux", test))]
fn start_ticks(stat: &str) -> std::io::Result<u64> {
    // comm may itself contain spaces and parentheses. Field 3 starts after ') '.
    stat.rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid process stat"))
}

#[cfg(target_os = "linux")]
pub fn capture(pid: u32) -> std::io::Result<ProcessIdentity> {
    use std::os::unix::fs::MetadataExt;
    let directory = format!("/proc/{pid}");
    let before = start_ticks(&std::fs::read_to_string(format!("{directory}/stat"))?)?;
    let executable = std::fs::metadata(format!("{directory}/exe"))?;
    let after = start_ticks(&std::fs::read_to_string(format!("{directory}/stat"))?)?;
    if before != after {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Process lifetime changed"));
    }
    Ok(ProcessIdentity {
        boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim().into(),
        start_ticks: before,
        executable_device: executable.dev(),
        executable_inode: executable.ino(),
    })
}

#[cfg(target_os = "linux")]
pub struct SessionProcess(std::os::fd::OwnedFd);

#[cfg(target_os = "linux")]
impl SessionProcess {
    /// Open the lifetime first, then verify the journaled identity before signaling.
    /// Legacy live records fail closed: a process name is not ownership evidence.
    pub fn open(pid: u32, expected: Option<&ProcessIdentity>) -> std::io::Result<Option<Self>> {
        use std::os::fd::FromRawFd;
        if pid <= 1 || pid > i32::MAX as u32 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid session PID"));
        }
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as i32, 0) };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) { return Ok(None); }
            return Err(error);
        }
        let process = Self(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as i32) });
        if process.has_exited()? { return Ok(None); }
        let expected = expected.ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Live legacy session has no lifetime identity; stop its original worker before recovery",
        ))?;
        let observed = match capture(pid) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if &observed != expected || process.has_exited()? { return Ok(None); }
        Ok(Some(process))
    }

    pub fn terminate(&self) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let result = unsafe { libc::syscall(libc::SYS_pidfd_send_signal,
            self.0.as_raw_fd(), libc::SIGTERM, std::ptr::null::<libc::siginfo_t>(), 0) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) { return Err(error); }
        }
        Ok(())
    }

    pub fn has_exited(&self) -> std::io::Result<bool> {
        use std::os::fd::AsRawFd;
        let mut event = libc::pollfd { fd: self.0.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let result = unsafe { libc::poll(&mut event, 1, 0) };
        if result < 0 { return Err(std::io::Error::last_os_error()); }
        if event.revents & libc::POLLNVAL != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid session pidfd"));
        }
        Ok(event.revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parser_handles_masked_names_and_parentheses() {
        let fields = std::iter::once("S".to_string()).chain((4..=21).map(|n| n.to_string()))
            .chain(std::iter::once("987654".into())).collect::<Vec<_>>().join(" ");
        assert_eq!(start_ticks(&format!("123 (name with ) spaces) {fields}")).unwrap(), 987654);
        assert!(start_ticks("123 (truncated) S 1 2").is_err());
    }

    #[test]
    fn identity_distinguishes_boot_lifetime_and_executable() {
        let original = ProcessIdentity { boot_id: "boot-a".into(), start_ticks: 42,
            executable_device: 8, executable_inode: 123 };
        let mut other = original.clone(); other.start_ticks += 1;
        assert_ne!(original, other);
        let mut other = original.clone(); other.boot_id = "boot-b".into();
        assert_ne!(original, other);
        let mut other = original.clone(); other.executable_inode += 1;
        assert_ne!(original, other);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_rejects_wrong_and_missing_identity_without_signaling() {
        let pid = std::process::id();
        let mut identity = capture(pid).unwrap();
        assert!(SessionProcess::open(pid, Some(&identity)).unwrap().is_some());
        identity.start_ticks += 1;
        assert!(SessionProcess::open(pid, Some(&identity)).unwrap().is_none());
        assert!(SessionProcess::open(pid, None).is_err());
    }
}
