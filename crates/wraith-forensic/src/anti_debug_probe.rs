//! Wraith Ring 3 Anti-Debugging & Dynamic Instrumentation Defense Probe
//! Detects active debuggers (GDB, LLDB, Frida), TracerPid hooks, and memory breakpoints.

use std::fs;
use std::process;
use tracing::{error, info};
use wraith_core::error::Result;

pub struct AntiDebugProbe;

impl AntiDebugProbe {
    /// Inspects /proc/self/status for active TracerPid attached to our thread
    pub fn check_tracer_pid() -> bool {
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(pid) = parts[1].parse::<u32>() {
                            if pid != 0 {
                                error!("🚨 FORENSIC THREAT: Active TracerPid detected: {pid} (Debugger attached!)");
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Attempts PTRACE_TRACEME syscall to detect pre-existing ptrace hooks
    pub fn probe_ptrace_hook() -> bool {
        #[cfg(unix)]
        {
            // SAFETY: Invoking ptrace with PTRACE_TRACEME to test if current process is traced.
            let res = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 1, 0) };
            if res < 0 {
                // If TracerPid is actively set (> 0), an actual debugger is controlling the process
                if Self::check_tracer_pid() {
                    error!("🚨 FORENSIC THREAT: PTRACE_TRACEME failed with active TracerPid — Process is under active inspection!");
                    return true;
                }
                // If TracerPid is 0, failure is caused by Seccomp BPF policy blocking ptrace
                tracing::debug!("{}", rust_i18n::t!("log.msg_0"));
                return false;
            }
        }
        false
    }

    /// Evaluates /proc/self/wchan to see if the process is suspended in ptrace_stop or do_signal_stop
    pub fn check_wchan_suspension() -> bool {
        if let Ok(wchan) = fs::read_to_string("/proc/self/wchan") {
            let s = wchan.trim();
            if s.contains("ptrace") || s.contains("signal_stop") {
                error!("🚨 FORENSIC THREAT: Thread suspended in kernel state: {s}");
                return true;
            }
        }
        false
    }

    /// Enforces continuous anti-debugging probe. If a debugger is found, instantly terminates with SIGKILL.
    /// When seccomp is active (e.g. strict hardening mode), probe_ptrace_hook() is skipped to avoid trapped syscall faults.
    pub fn enforce_anti_debug_trap(seccomp_active: bool) -> Result<()> {
        let is_compromised = if seccomp_active {
            // Under active Seccomp BPF jail, only use file-based / non-syscall procfs checks
            Self::check_tracer_pid() || Self::check_wchan_suspension()
        } else {
            Self::check_tracer_pid() || Self::probe_ptrace_hook() || Self::check_wchan_suspension()
        };

        if is_compromised {
            error!("🚨 ACTIVE RECONNAISSANCE DETECTED — Executing Immediate Process Abort (SIGKILL)");
            process::abort();
        }
        info!("Anti-Debugging defenses verified (seccomp_active: {seccomp_active})");
        Ok(())
    }
}
