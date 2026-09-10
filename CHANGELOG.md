# Changelog

All notable changes to the **Wraith** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.3.0] - 2026-09-10

### Added
- **1,338+ Tool In-Flight DPI Signature Sanitization Matrix**:
  - Intercepts and rewrites Layer-4/Layer-7 HTTP and TLS signatures from 1,338+ security assessment, penetration testing, scanner, and exploitation tools across 10 major categories (Vulnerability Scanners, Web Discovery & Fuzzers, OSINT, C2 Frameworks, Active Directory, Network Scanners, Credential Testing, Interception Proxies, Reverse Engineering tools, and Scripting HTTP libraries).
  - Normalizes headers on the fly to authentic, randomized modern browser signatures (`Chrome 131`, `Firefox 132`, `Safari 18`).
- **Compile-Time XOR-0x7A EDR/AV Heuristic Avoidance**:
  - All 1,338+ signature strings in `.rodata` are encrypted at compile time using byte-wise XOR `0x7A`.
  - Blinds static antivirus scanners, YARA signatures, and EDR heuristics (preventing false-positive flags such as Windows Defender `OS Error 225`).
  - Single-phase on-demand decryption using thread-safe `std::sync::OnceLock<Vec<String>>` for zero-allocation runtime performance.
- **Automated Hardware Network Interface Selector (`wraith interfaces`)**:
  - Intelligent physical NIC enumeration via Linux `/sys/class/net` and Netlink.
  - Interactive full-screen terminal TUI (`wraith interfaces`) and automated fallback prioritizing active physical uplinks over loopback.
- **Systemd Early-Boot Fail-Closed Daemon (`install-daemon.sh`)**:
  - 6-step interactive deployment wizard and non-interactive command-line flags.
  - Hooks into systemd `network-pre.target` to establish fail-closed Netfilter isolation before user login or clearnet leaks can occur.
- **RFC 8484 DNS-over-HTTPS (DoH) Engine (`wraith doh`)**:
  - Native RFC 8484 DNS query synthesis with wire-format application/dns-message payloads.
  - Built-in privacy resolver presets (Quad9, Cloudflare, Mullvad, AdGuard) and custom endpoint support with interactive TUI.
- **Tor Moat Circumvention Bridge Engine (`wraith bridge`)**:
  - Automated BridgeDB discovery via domain-fronted Moat JSON API and CAPTCHA challenge resolver.
  - First-class support for `obfs4`, `snowflake`, and `webtunnel` pluggable transports.
- **Enterprise 75-Language Synchronization**:
  - 100% synchronized dictionaries across all 75 native locales with zero missing translation keys.

### Security & Hardening (Dual-Engine Audit Remediation)
- **VULN-01 (RamFS Vault Directory Permissions & Path Traversal)**:
  - Enforced `0o700` permissions on RAMFS vault directory creation.
  - Sanitized secret identifiers against path traversal (`..`, `/`, `\`) and null bytes (`\0`).
  - Added `libc::O_NOFOLLOW` flag to file descriptor creation on Unix.
- **VULN-02 (Cryptographic Shredder Symlink Hijacking)**:
  - Replaced `fs::metadata()` with `fs::symlink_metadata()` in `dod_7pass_shred` and `secure_delete_file`.
  - Symlinks are safely unlinked without following or overwriting target files; all write handles enforce `O_NOFOLLOW`.
- **VULN-03 (Netlink NlMsgErr Struct Offset Alignment)**:
  - Fixed Netlink error parsing offset in `send_and_recv_ack` and dump loops to read `NlMsgErr` immediately after outer 16-byte `NlMsgHdr`.
- **VULN-04 (Honeypot Loopback Isolation & Protected PID Immunity)**:
  - Restricted peer process resolution strictly to loopback IP addresses (`is_loopback()`), eliminating LAN ephemeral port collisions.
  - Added inviolable immunity guards preventing PID 0, PID 1 (`init`/`systemd`), and Wraith itself from being frozen or killed.
- **VULN-05 (State Persistence File Permission Lockdown)**:
  - Locked state files (`.wraith.state.*.tmp`, `/var/run/wraith.state`, custom paths) to Unix mode `0o600`.
- **VULN-06 (Network Namespace TCP TransPort Redirection)**:
  - Added `iptables -t nat -A PREROUTING -p tcp --syn -j REDIRECT --to-ports 9040` and `FORWARD` rules in `create_namespace`, with full teardown in `destroy_namespace`.
- **VULN-07 (CLI Argument Injection Defense)**:
  - Enforced HTTPS URL scheme validation and inserted POSIX `"--"` argument delimiter before URL parameters in `curl` invocations.

### Changed
- Total codebase scale expanded to **52,846 lines** (49,652 code lines, 13,493 pure Rust LOC across 61 files).
- Workspace test suite expanded to **44/44 passing tests** with 0 warnings in `cargo clippy --workspace`.

---

## [1.2.0] - 2026-09-01

### Added
- Multi-Hop Hybrid Tunneling: WireGuard-over-Tor encapsulation (`-W, --wireguard <CONF>`).
- Five Eyes Intelligence Exclusion Profile (`-p stealth`): Excludes US, UK, CA, AU, NZ, FR, DE exit relays.
- In-Flight Layer-4/Layer-7 DPI Sanitizer with initial 50+ tool signatures.
- RFC 8701 GREASE & JA3/JA4 TLS ClientHello fingerprint mimicry.
- Enterprise 75-language compile-time i18n architecture via `rust-i18n`.
- Dynamic Profile Switching (`wraith profile <NAME>`).

---

## [1.1.0] - 2026-08-31

### Added
- Kernel-level Netlink FIB Table 52 routing engine.
- WebRTC STUN request interceptor and public IP leak prevention.
- Volatile RAMFS secret vault with `mlockall` page locking and `PR_SET_DUMPABLE=0`.
- Automated Netfilter fail-closed recovery and Panic Sentry.

---

## [1.0.0] - 2026-08-31

### Added
- Initial release of Wraith kernel network privacy framework.
- Fail-Closed Netfilter KillSwitch watchdog.
- Tor TransProxy redirection on port 9040 with DNS sinkhole on port 5353.
- Hardware L2 MAC address randomization and hostname cloaking.
- DoD 5220.22-M 7-pass cryptographic file shredder.
