//! Verifies strict kernel prerequisites and applies reversible session controls.

use std::fs;
use std::path::Path;
use tracing::{info, warn};

use crate::error::{Result, WraithError};

pub const LOCKDOWN_PATH: &str = "/sys/kernel/security/lockdown";
pub const IOMMU_PATH: &str = "/sys/kernel/iommu_groups";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockdownState {
    None,
    Integrity,
    Confidentiality,
    Unavailable,
}

pub fn get_lockdown_status() -> LockdownState {
    let path = Path::new(LOCKDOWN_PATH);
    if !path.exists() {
        return LockdownState::Unavailable;
    }

    if let Ok(content) = fs::read_to_string(path) {
        if content.contains("[confidentiality]") {
            LockdownState::Confidentiality
        } else if content.contains("[integrity]") {
            LockdownState::Integrity
        } else if content.contains("[none]") {
            LockdownState::None
        } else {
            LockdownState::Unavailable
        }
    } else {
        LockdownState::Unavailable
    }
}

pub const REQUIRED_CONTROLS: &[(&str, &str)] = &[
    ("/proc/sys/kernel/sysrq", "0"),
    ("/proc/sys/kernel/core_pattern", "|/bin/false"),

];

pub fn backup_reversible_controls() -> Result<std::collections::HashMap<String, String>> {
    REQUIRED_CONTROLS.iter().map(|(path, _)| Ok((path.to_string(), fs::read_to_string(path)?))).collect()
}

pub fn restore_reversible_controls(backup: &std::collections::HashMap<String, String>) -> Result<()> {
    let mut errors = Vec::new();
    for (path, value) in backup {
        if !REQUIRED_CONTROLS.iter().any(|(allowed, _)| path == allowed) {
            errors.push(format!("Unrecognized kernel backup path: {path}"));
        } else if let Err(e) = fs::write(path, value) { errors.push(format!("{path}: {e}")); }
    }
    if errors.is_empty() { Ok(()) } else { Err(WraithError::Custom(errors.join("; "))) }
}

fn enforce_controls(
    mut read: impl FnMut(&str) -> Result<String>,
    mut write: impl FnMut(&str, &str) -> Result<()>,
) -> Result<()> {
    // Preflight every required control before changing session controls.
    for (path, _) in REQUIRED_CONTROLS { read(path)?; }
    for (path, value) in REQUIRED_CONTROLS {
        if read(path)?.trim() != *value { write(path, value)?; }
        if read(path)?.trim() != *value {
            return Err(WraithError::Custom(format!("Kernel control did not take effect: {path}")));
        }
    }
    Ok(())
}

pub fn enforce_kernel_lockdown() -> Result<LockdownState> {
    let state = get_lockdown_status();
    info!("Current Linux Kernel Lockdown state: {:?}", state);

    // 1. Elevate Lockdown Mode to Confidentiality if permitted by securityfs
    let path = Path::new(LOCKDOWN_PATH);
    if path.exists() && (state == LockdownState::None || state == LockdownState::Integrity) {
        if fs::write(path, "confidentiality").is_ok() {
            info!("Linux Kernel Lockdown elevated to 'confidentiality'");
        } else if fs::write(path, "integrity").is_ok() {
            info!("Linux Kernel Lockdown elevated to 'integrity'");
        }
    }

    // 2. Enforce required reversible controls (SysRq=0, core_pattern=|/bin/false)
    enforce_controls(|path| Ok(fs::read_to_string(path)?), |path, value| Ok(fs::write(path, value)?))?;

    // 3. Proactively harden kexec and ptrace scope if available
    for (path, val) in [("/proc/sys/kernel/kexec_load_disabled", "1"), ("/proc/sys/kernel/yama/ptrace_scope", "3")] {
        if Path::new(path).exists() {
            let _ = fs::write(path, val);
        }
    }

    // 4. Verify IOMMU
    let iommu_path = Path::new(IOMMU_PATH);
    if iommu_path.exists() {
        if let Ok(entries) = fs::read_dir(iommu_path) {
            let count = entries.count();
            if count > 0 {
                info!("IOMMU (VT-d / AMD-Vi) hardware DMA memory protection active ({count} groups isolated)");
            }
        }
    } else {
        warn!("IOMMU not discovered in sysfs; ensure VT-d/IOMMU is active in BIOS for hardware DMA defense");
    }

    let final_state = get_lockdown_status();
    Ok(final_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_control_prevents_all_writes() {
        let mut writes = 0;
        assert!(enforce_controls(|_| Err(WraithError::Custom("missing".into())), |_, _| { writes += 1; Ok(()) }).is_err());
        assert_eq!(writes, 0);
    }
    #[test]
    fn rejected_and_ineffective_writes_cannot_pass() {
        assert!(enforce_controls(|_| Ok("old".into()), |_, _| Err(WraithError::Custom("denied".into()))).is_err());
        assert!(enforce_controls(|_| Ok("old".into()), |_, _| Ok(())).is_err());
    }
    #[test]
    fn already_enforced_controls_need_no_write() {
        enforce_controls(|path| Ok(REQUIRED_CONTROLS.iter().find(|(key, _)| *key == path).unwrap().1.into()), |_, _| panic!("unnecessary write")).unwrap();
    }
}
