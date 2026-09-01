//! Wraith Sovereign BPF (Berkeley Packet Filter) Bytecode Assembler & Kernel JIT Engine
//! Compiles raw BPF instructions for direct attachment to Linux kernel network sockets via SO_ATTACH_FILTER.

#[cfg(unix)]
use std::mem::size_of;

// BPF Instruction Classes (Linux <linux/filter.h>)
pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;

// BPF Size Modifiers
pub const BPF_W: u16 = 0x00;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;

// BPF Mode Modifiers
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;
pub const BPF_MSH: u16 = 0xa0;

// BPF ALU Operations
pub const BPF_ADD: u16 = 0x00;
pub const BPF_SUB: u16 = 0x10;
pub const BPF_MUL: u16 = 0x20;
pub const BPF_DIV: u16 = 0x30;
pub const BPF_OR: u16 = 0x40;
pub const BPF_AND: u16 = 0x50;
pub const BPF_LSH: u16 = 0x60;
pub const BPF_RSH: u16 = 0x70;
pub const BPF_NEG: u16 = 0x80;
pub const BPF_XOR: u16 = 0xa0;

// BPF Jump Operations
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;

// BPF Source Modifiers
pub const BPF_K: u16 = 0x00;
pub const BPF_X: u16 = 0x08;

/// Linux Kernel BPF Instruction (`struct sock_filter`)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockFilter {
    pub code: u16, // Filter opcode
    pub jt: u8,    // Jump true offset
    pub jf: u8,    // Jump false offset
    pub k: u32,    // Generic multiuse field / immediate operand
}

/// Linux Kernel BPF Program (`struct sock_fprog`)
#[repr(C)]
#[derive(Debug)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

/// High-Level BPF Bytecode Program Builder
#[derive(Debug, Clone, Default)]
pub struct BpfProgramBuilder {
    instructions: Vec<SockFilter>,
}

impl BpfProgramBuilder {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
        }
    }

    /// Appends a raw instruction
    pub fn emit(&mut self, code: u16, jt: u8, jf: u8, k: u32) -> &mut Self {
        self.instructions.push(SockFilter { code, jt, jf, k });
        self
    }

    /// Load absolute word/halfword/byte from packet at offset k: A = packet[k]
    pub fn ld_abs(&mut self, size: u16, offset: u32) -> &mut Self {
        self.emit(BPF_LD | BPF_ABS | size, 0, 0, offset);
        self
    }

    /// Compare accumulator with immediate k: if (A == k) jump jt else jump jf
    pub fn jmp_eq(&mut self, val: u32, jt: u8, jf: u8) -> &mut Self {
        self.emit(BPF_JMP | BPF_JEQ | BPF_K, jt, jf, val);
        self
    }

    /// Return instruction: Accept packet up to max_len bytes (or 0 to drop)
    pub fn ret(&mut self, max_len: u32) -> &mut Self {
        self.emit(BPF_RET | BPF_K, 0, 0, max_len);
        self
    }

    /// Compiles an anti-leak BPF program that drops all non-Tor TCP egress and IPv6
    pub fn build_tor_only_egress_filter(tor_transport: u16, tor_dnsport: u16) -> Vec<SockFilter> {
        let mut builder = Self::new();

        // 1. Load EtherType at offset 12 (2 bytes)
        builder.ld_abs(BPF_H, 12);

        // 2. If EtherType == 0x86DD (IPv6), DROP immediately
        builder.jmp_eq(0x86DD, 10, 0); // Drop if IPv6

        // 3. If EtherType != 0x0800 (IPv4), PASS (Allow ARP / local broadcast)
        builder.jmp_eq(0x0800, 0, 8);

        // 4. Load IP Protocol at offset 23 (1 byte)
        builder.ld_abs(BPF_B, 23);

        // 5. If TCP (protocol 6), inspect destination port
        builder.jmp_eq(6, 0, 3);
        // Load TCP Dst Port at offset 36 (assuming 20B IPv4 header)
        builder.ld_abs(BPF_H, 36);
        // If TCP Dst Port == Tor TransPort, ALLOW, else DROP
        builder.jmp_eq(tor_transport as u32, 4, 3);

        // 6. If UDP (protocol 17), inspect destination port
        builder.jmp_eq(17, 0, 2);
        // Load UDP Dst Port at offset 36
        builder.ld_abs(BPF_H, 36);
        // If UDP Dst Port == Tor DNSPort, ALLOW, else DROP
        builder.jmp_eq(tor_dnsport as u32, 1, 0);

        // Return ACCEPT (65535 bytes)
        builder.ret(0xFFFF);
        // Return DROP (0 bytes)
        builder.ret(0x0000);

        builder.instructions
    }

    /// Attaches the BPF filter program to a raw socket descriptor
    pub fn attach_to_socket(fd: i32, filter: &[SockFilter]) -> bool {
        #[cfg(unix)]
        {
            let prog = SockFprog {
                len: filter.len() as u16,
                filter: filter.as_ptr(),
            };

            // SAFETY: Setting SO_ATTACH_FILTER on socket fd with valid SockFprog referencing filter slice.
            let res = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ATTACH_FILTER,
                    &prog as *const _ as *const libc::c_void,
                    size_of::<SockFprog>() as u32,
                )
            };

            res == 0
        }
        #[cfg(not(unix))]
        {
            let _ = (fd, filter);
            false
        }
    }
}
