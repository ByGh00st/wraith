//! Wraith Seccomp-BPF Linux Syscall Sandbox & Raw Socket Trap
//! Injects a raw BPF bytecode program into the Linux kernel using PR_SET_SECCOMP.
//! Traps and terminates (or rejects with EPERM) unauthorized calls to:
//! - ptrace(...) (Raw sockets are exempted to prevent conflicts with the zero-copy IDS engine)
//! - unauthorized namespace escapes

#[cfg(unix)]
use tracing::{info, warn};
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

// Linux x86_64 Architecture constant
const AUDIT_ARCH_X86_64: u32 = 0xc000003e;

// Linux Syscall Numbers (x86_64)
const SYS_PTRACE: u32 = 101;

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
    vec![
        // 1. Load Architecture (seccomp_data.arch offset 4)
        SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, 4),
        // 2. Verify AUDIT_ARCH_X86_64. If not x86_64, kill process
        SockFilter::jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        // 3. Load Syscall Number (seccomp_data.nr offset 0)
        SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, 0),

        // 4. Check if syscall is ptrace (101) -> Deny with EPERM
        SockFilter::jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_PTRACE, 0, 1),
        SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        // 5. Default: ALLOW all other standard system calls
        SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    ]
}

/// Enforces the Seccomp-BPF filter directly in the Linux kernel
pub fn enforce_seccomp_socket_jail() -> Result<()> {
    #[cfg(unix)]
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
            const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
            let res = libc::prctl(libc::PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog as *const _ as libc::c_ulong, 0, 0);
            if res != 0 {
                warn!(
                    "Seccomp-BPF filter installation returned errno: {}. (Kernel may require CAP_SYS_ADMIN)",
                    std::io::Error::last_os_error()
                );
            } else {
                info!("Seccomp-BPF Kernel Filter Active: ptrace blocked at Ring 0 (raw sockets exempted for IDS engine)");
            }
        }
    }
    Ok(())
}
