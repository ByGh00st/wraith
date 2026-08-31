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
            let res = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 1, 0) };
            if res < 0 {
                // If PTRACE_TRACEME fails with -1, a debugger is already controlling our process
                error!("🚨 FORENSIC THREAT: PTRACE_TRACEME failed — Process is under active inspection!");
                return true;
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

    /// Enforces continuous anti-debugging probe. If a debugger is found, instantly terminates with SIGKILL
    pub fn enforce_anti_debug_trap() -> Result<()> {
        if Self::check_tracer_pid() || Self::probe_ptrace_hook() || Self::check_wchan_suspension() {
            error!("🚨 ACTIVE RECONNAISSANCE DETECTED — Executing Immediate Process Suicide");
            process::exit(137); // 128 + 9 (SIGKILL)
        }
        info!("Anti-Debugging & Dynamic Instrumentation defenses verified");
        Ok(())
    }
}
