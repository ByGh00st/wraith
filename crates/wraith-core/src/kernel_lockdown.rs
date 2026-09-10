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

    for (path, _) in REQUIRED_CONTROLS { fs::read_to_string(path)?; }

    if get_lockdown_status() != LockdownState::Confidentiality {
        return Err(WraithError::Custom("Strict mode requires pre-enabled confidentiality lockdown; Wraith will not make this irreversible change".into()));
    }
    for (path, required) in [("/proc/sys/kernel/kexec_load_disabled", "1"), ("/proc/sys/kernel/yama/ptrace_scope", "3")] {
        if fs::read_to_string(path)?.trim() != required {
            return Err(WraithError::Configuration(format!("Strict prerequisite {path}={required} is not enabled; refusing irreversible session changes")));
        }
    }
    enforce_controls(|path| Ok(fs::read_to_string(path)?), |path, value| Ok(fs::write(path, value)?))?;
    if fs::read_dir(IOMMU_PATH).map(|entries| entries.count()).unwrap_or(0) == 0 {
        warn!("IOMMU groups were not observed; hardware DMA protection is not verified");
    }
    info!("Required kernel controls were written and verified");
    Ok(LockdownState::Confidentiality)
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
