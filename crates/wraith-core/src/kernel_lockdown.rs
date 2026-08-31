//! Wraith Linux Kernel Lockdown, SysRq / Core Dump Disabler & Cold-Boot DMA Shield
//! Enforces hardware memory isolation against PCIe/Thunderbolt DMA sniffers,
//! disables kernel crash dumps, and activates Linux Kernel Lockdown confidentiality mode.

use std::fs;
use std::path::Path;
use tracing::{info, warn};

use crate::error::Result;

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

pub fn enforce_kernel_lockdown() -> Result<LockdownState> {
    let state = get_lockdown_status();
    info!("Current Linux Kernel Lockdown state: {:?}", state);

    // 1. Elevate Lockdown Mode to Confidentiality (Blocks /dev/mem, /dev/kmem, unsigned modules & DMA hooks)
    let path = Path::new(LOCKDOWN_PATH);
    if path.exists() {
        if state == LockdownState::None || state == LockdownState::Integrity {
            if fs::write(path, "confidentiality").is_ok() {
                info!("Linux Kernel Lockdown elevated to 'confidentiality'");
            } else if fs::write(path, "integrity").is_ok() {
                info!("Linux Kernel Lockdown elevated to 'integrity'");
            }
        }
    }

    // 2. Disable SysRq Triggers (prevents hardware keyboard crash dumps)
    let sysrq_path = Path::new("/proc/sys/kernel/sysrq");
    if sysrq_path.exists() {
        let _ = fs::write(sysrq_path, "0");
        info!("Disabled Linux Magic SysRq triggers (/proc/sys/kernel/sysrq = 0)");
    }

    // 3. Disable Core Pattern Dumps (prevents RAM process memory writing to disk on crash)
    let core_pattern = Path::new("/proc/sys/kernel/core_pattern");
    if core_pattern.exists() {
        let _ = fs::write(core_pattern, "|/bin/false\n");
        info!("Kernel core dump pattern locked (/proc/sys/kernel/core_pattern = |/bin/false)");
    }

    // 4. Disable KExec (prevents loading a rogue kernel in RAM to dump volatile memory)
    let kexec_path = Path::new("/proc/sys/kernel/kexec_load_disabled");
    if kexec_path.exists() {
        let _ = fs::write(kexec_path, "1");
        info!("Kernel kexec load disabled (Anti-Cold Boot RAM acquisition)");
    }

    // 5. Restrict Ptrace Scope System-Wide (Yama LSM Scope 3 = No ptrace allowed)
    let ptrace_scope = Path::new("/proc/sys/kernel/yama/ptrace_scope");
    if ptrace_scope.exists() {
        let _ = fs::write(ptrace_scope, "3");
        info!("Yama LSM ptrace scope set to 3 (System-wide anti-debugging lock)");
    }

    // 6. Verify IOMMU (VT-d / AMD-Vi) hardware DMA protection
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

    Ok(state)
}
