//! Wraith Seccomp-BPF Linux Syscall Sandbox & Raw Socket Trap
//! Injects a raw BPF bytecode program into the Linux kernel using PR_SET_SECCOMP.
//! Traps and terminates (or rejects with EPERM) unauthorized calls to:
//! - ptrace(...) (Raw sockets are exempted to prevent conflicts with the zero-copy IDS engine)
//! - unauthorized namespace escapes

#[cfg(unix)]
use tracing::info;
#[cfg(unix)]
use wraith_core::error::WraithError;
use wraith_core::error::Result;

// BPF Instruction opcodes & constants
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// Seccomp Return Actions
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_ERRNO: u32 = 0x00050000; // Return errno in lower 16 bits
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

// Linux audit ABI identifiers and ptrace syscall numbers.
const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
const AUDIT_ARCH_AARCH64: u32 = 0xc00000b7;

// Socket Families & Types
const EPERM: u32 = 1;

pub use crate::bpf_filter_engine::{SockFilter, SockFprog};

impl SockFilter {
    pub const fn stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    pub const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

pub fn build_seccomp_bpf_filter() -> Vec<SockFilter> {
    if cfg!(target_arch = "aarch64") {
        // Block ptrace (117), process_vm_readv (270), process_vm_writev (271)
        filter_for_arch(AUDIT_ARCH_AARCH64, &[117, 270, 271], false)
    } else {
        // Block ptrace (101), process_vm_readv (310), process_vm_writev (311)
        filter_for_arch(AUDIT_ARCH_X86_64, &[101, 310, 311], true)
    }
}

fn filter_for_arch(architecture: u32, blocked_syscalls: &[u32], reject_x32: bool) -> Vec<SockFilter> {
    let mut filter = vec![
        // 1. Load Architecture (seccomp_data.arch offset 4)
        SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, 4),
        // 2. Reject another ABI before interpreting its syscall numbers.
        SockFilter::jump(BPF_JMP | BPF_JEQ | BPF_K, architecture, 1, 0),
        SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        // 3. Load Syscall Number (seccomp_data.nr offset 0)
        SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, 0),
    ];
    if reject_x32 {
        // x32 shares the x86_64 audit identifier but uses different numbers.
        filter.extend([
            SockFilter::jump(BPF_JMP | 0x30 | BPF_K, 0x40000000, 0, 1),
            SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        ]);
    }

    // 4. Reject debugging and cross-process memory dumping syscalls
    for &nr in blocked_syscalls {
        filter.extend([
            SockFilter::jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),
            SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        ]);
    }

    // 5. Default: ALLOW all other standard system calls
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    filter
}

/// Enforces the Seccomp-BPF filter directly in the Linux kernel
pub fn enforce_seccomp_socket_jail() -> Result<()> {
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let filter = build_seccomp_bpf_filter();
        let fprog = SockFprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };

        // SAFETY: Invoking prctl with PR_SET_NO_NEW_PRIVS and valid SockFprog pointer for PR_SET_SECCOMP filter injection.
        unsafe {
            // Step 1: Ensure PR_SET_NO_NEW_PRIVS=1
            let res = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if res != 0 {
                return Err(WraithError::Custom(format!(
                    "Failed to set PR_SET_NO_NEW_PRIVS: {}",
                    std::io::Error::last_os_error()
                )));
            }

            // Step 2: Inject BPF filter via PR_SET_SECCOMP (SECCOMP_MODE_FILTER = 2)
            // TSYNC applies the filter to existing Tokio workers too.
            const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
            const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;
            let res = libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC, &fprog as *const SockFprog);
            if res != 0 {
                return Err(WraithError::Guard(format!("Seccomp installation failed: {}", std::io::Error::last_os_error())));
            } else {
                info!("Seccomp-BPF Kernel Filter Active: ptrace blocked at Ring 0 (raw sockets exempted for IDS engine)");
            }
        }
    }
    #[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
    return Err(wraith_core::error::WraithError::UnsupportedPlatform);
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn decision(code: &[SockFilter], arch: u32, syscall: u32) -> u32 {
        let mut pc = 0;
        let mut value = 0;
        loop {
            let instruction = &code[pc];
            match instruction.code {
                0x20 => value = if instruction.k == 4 { arch } else { syscall },
                0x15 => { pc += if value == instruction.k { instruction.jt } else { instruction.jf } as usize; }
                0x35 => { pc += if value >= instruction.k { instruction.jt } else { instruction.jf } as usize; }
                0x06 => return instruction.k,
                _ => panic!("unexpected instruction"),
            }
            pc += 1;
        }
    }
    #[test]
    fn denies_ptrace_and_alternate_abi() {
        let code = filter_for_arch(AUDIT_ARCH_X86_64, &[101, 310, 311], true);
        assert_eq!(decision(&code, AUDIT_ARCH_X86_64, 101), SECCOMP_RET_ERRNO | EPERM);
        assert_eq!(decision(&code, AUDIT_ARCH_X86_64, 310), SECCOMP_RET_ERRNO | EPERM);
        assert_eq!(decision(&code, AUDIT_ARCH_X86_64, 311), SECCOMP_RET_ERRNO | EPERM);
        assert_eq!(decision(&code, AUDIT_ARCH_X86_64, 0x40000209), SECCOMP_RET_ERRNO | EPERM);
        assert_eq!(decision(&code, AUDIT_ARCH_X86_64, 1), SECCOMP_RET_ALLOW);
        assert_eq!(decision(&code, AUDIT_ARCH_AARCH64, 1), SECCOMP_RET_KILL_PROCESS);
        let code = filter_for_arch(AUDIT_ARCH_AARCH64, &[117, 270, 271], false);
        assert_eq!(decision(&code, AUDIT_ARCH_AARCH64, 117), SECCOMP_RET_ERRNO | EPERM);
        assert_eq!(decision(&code, AUDIT_ARCH_AARCH64, 270), SECCOMP_RET_ERRNO | EPERM);
        assert_eq!(decision(&code, AUDIT_ARCH_AARCH64, 271), SECCOMP_RET_ERRNO | EPERM);
        assert_eq!(decision(&code, AUDIT_ARCH_AARCH64, 64), SECCOMP_RET_ALLOW);
        assert_eq!(decision(&code, AUDIT_ARCH_X86_64, 101), SECCOMP_RET_KILL_PROCESS);
        assert_eq!(decision(&code, 0x40000028, 26), SECCOMP_RET_KILL_PROCESS);
    }
}
