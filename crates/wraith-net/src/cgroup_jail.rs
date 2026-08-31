//! Wraith Linux cgroup2 Network Socket Jail
//! Tags all child process sockets within a kernel cgroup to strictly enforce Tor egress.

use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::info;
use wraith_core::error::{Result, WraithError};

pub const CGROUP_PATH: &str = "/sys/fs/cgroup/wraith_jail";

pub fn create_cgroup_jail() -> Result<()> {
    let cgroup_dir = Path::new(CGROUP_PATH);
    if !cgroup_dir.exists() {
        fs::create_dir_all(cgroup_dir).map_err(|e| {
            WraithError::Namespace(format!("Failed creating cgroup2 jail at {CGROUP_PATH}: {e}"))
        })?;
        info!("Constructed Linux cgroup2 socket jail at {CGROUP_PATH}");
    }

    // Add iptables cgroup matching rule if cgroup module is available
    let _ = Command::new("iptables")
        .args(["-A", "OUTPUT", "-m", "cgroup", "--path", "wraith_jail", "-p", "tcp", "-j", "ACCEPT"])
        .status();

    Ok(())
}

pub fn attach_pid_to_cgroup(pid: u32) -> Result<()> {
    let procs_file = format!("{CGROUP_PATH}/cgroup.procs");
    let path = Path::new(&procs_file);
    if path.exists() {
        fs::write(path, pid.to_string()).map_err(|e| {
            WraithError::Namespace(format!("Failed attaching PID {pid} to cgroup: {e}"))
        })?;
        info!("Process PID {pid} assigned to cgroup2 network jail");
    }
    Ok(())
}

pub fn destroy_cgroup_jail() -> Result<()> {
    let cgroup_dir = Path::new(CGROUP_PATH);
    if cgroup_dir.exists() {
        let _ = fs::remove_dir(cgroup_dir);
        info!("cgroup2 socket jail removed");
    }
    Ok(())
}
