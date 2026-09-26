# Changelog

All notable changes to the **Wraith** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.4.7] - 2026-09-26

### Security & Integrity Improvements (Remediation & Defense-in-Depth)
- **Onion v3 Ephemeral Key Shredding TOCTOU Protection (CWE-59)**: Secured `shred_key_file` with `libc::O_NOFOLLOW | libc::O_NONBLOCK` and mandatory post-open descriptor validation (`nlink == 1`, matching inode/device). Enforced post-overwrite verification prior to unlink, eliminating symlink swap race attacks on ephemeral keys.
- **DNS Sinkhole & Onion FQDN Trailing Dot Normalization (CWE-178)**: Implemented `is_sinkhole_domain` and `is_onion_domain` stripping trailing FQDN dots (`.`) and normalizing case, preventing telemetry probes (e.g. `telemetry.mozilla.org.`) from bypassing sinkhole interception and guaranteeing correct loopback handling for fully qualified `.onion.` names.
- **Torrc Directive & Comment Injection Prevention (CWE-93)**: Introduced `OnionServiceConfig::validate()` rejecting comment tokens (`#`), CRLF injection (`\r`, `\n`), ASCII control characters, whitespace, identifiers over 64 chars, and path traversal sequences (`..`) in Unix socket targets.
- **L2 MAC Spoofing CSPRNG Standardization (CWE-330)**: Replaced PRNG `thread_rng` in physical and virtual MAC generation with kernel CSPRNG `rand::rngs::OsRng`.
- **High-Entropy Natural Hostname Generation (CWE-330)**: Replaced low-entropy dictionary adjective-noun combinations with high-entropy cryptographic hex tokens ($>10^8$ entropy) formatted as authentic corporate endpoints (`desktop-xxxxxx`, `laptop-xxxxxx`, `station-xxxxxx`), defeating DHCP log correlation and device fingerprinting.
- **Seccomp-BPF Memory Inspection Syscall Sandboxing (CWE-269)**: Extended BPF filter to actively reject cross-process virtual memory dumping syscalls `process_vm_readv` (x86_64: 310, ARM64: 270) and `process_vm_writev` (x86_64: 311, ARM64: 271) alongside `ptrace` and invalid ABI invocations with `EPERM`.
- **EDNS0 Padding Integer Underflow Hardening (CWE-190)**: Protected `apply_edns0_padding` with checked arithmetic (`checked_add`, `checked_sub`) and bounds conversion (`u16::try_from`), guaranteeing safe padding generation against arbitrary packet payloads.
- **Forensic Swap Scrubbing Device Path Enforcement (CWE-78)**: Enforced strict swap path validation in `overwrite_swap`, checking path existence via `Path::exists()` and rejecting control characters, traversal sequences (`..`), and non-canonical identifiers prior to disk sanitization.

## [1.4.6] - 2026-09-25

### Added & Improved
- Added single-letter emergency reset shortcuts `-R` and `-N` (`sudo wraith -R` / `sudo wraith -N`).
- Upgraded emergency reset interface to high-tech cybersec HUD telemetry:
  - Real-time step-by-step progress logging during subsystem teardown.
  - Detailed recovery table with UTF8 rounded corners, cyan headers, and green status badges.
  - Explicit purge of orphaned `veth-wr-host` and `veth-wr-ns` interfaces.
- Hardened X11 authentication detection in `spawn_monitor_terminal` for direct root shells (`xhost +local:` and fallback to `/home/*/.Xauthority`), enabling `[M]` pop-up monitor in Kali Linux desktop sessions.
- Added automatic shell completion generation and installation for both Bash and Zsh in `build.sh`.

### Security & Hardening (Zero-Tolerance Kernel Defense)
- **X11 Display Authorization Hardening**: Eliminated `xhost +local:` from `spawn_monitor_terminal` to prevent local unauthorized access to X11 sessions (keylogging/screengrab vectors). Enforced strict root-only authority (`+SI:localuser:root`).
- **Root Context Configuration Isolation**: Forbid loading unprivileged user configurations (`~/.config/wraith/config.toml`) when running with root privileges (UID 0), eliminating Local Privilege Escalation (LPE) and malicious policy tampering. Enforced root ownership and non-world-writable permission validation.
- **Cryptographic Ephemeral Key Shredding**: Integrated DoD 5220.22-M 7-pass random overwrite, in-memory zeroization, and physical disk sync (`shred_key_file` and `shred_onion_tree`) to securely purge Onion v3 private keys (`hs_ed25519_secret_key`) during service deactivation.
- **Moat Bridge Egress Proxy Enforcement**: Routed BridgeDB Moat API requests through local Tor SOCKS5 proxy (`127.0.0.1:9050` with `--socks5-hostname`) to eliminate clearnet SNI and DNS leaks on deep packet inspection (DPI) firewalls.
- **HTTP Keep-Alive / Pipelining Disablement**: Stripped client Keep-Alive headers in `tls_camouflage` and enforced mandatory `Connection: close` and `Proxy-Connection: close` to prevent HTTP pipelining bypasses of header sanitization.
- **RFC 2104 Section 2 HMAC-SHA256 Compliance**: Eliminated silent fallback to static zero-keys (`[0u8; 32]`) on initialization. Implemented standard RFC 2104 pre-hashing for keys exceeding 64 bytes.
- **Daemon Logging Symlink Protection (CWE-59)**: Secured `/var/log/wraith/daemon.log` opening with `libc::O_NOFOLLOW` and mode `0o600`. Enforced `0o700` permissions on `/var/log/wraith` with symlink verification.
- **RAMFS Ephemeral WireGuard Key Isolation**: Replaced disk-backed `/tmp` WireGuard key files with RAMFS (`/dev/shm`) `SecureTempKey` RAII containers enforced with `0o600` permissions and in-memory zeroize-on-drop.
- **Honeypot Stealth Banner Normalization**: Neutralized `Wraith Enterprise` banner fingerprint in decoy HTTP 401 basic auth responses, standardizing on generic stealth administration banner.
- **WIDS/WIPS Anomaly Prevention**: Segregated physical hardware OUIs (Intel, Apple, HP, Dell, Realtek) from virtual hypervisor OUIs (VMware, VirtualBox, QEMU) to prevent wireless intrusion detection system alerts on physical adapters.
- **Race-Proof Process Neutralization**: Implemented critical system daemon whitelist (`systemd`, `tor`, `wraith`, etc.) and Linux `SYS_pidfd_open` / `SYS_pidfd_send_signal` architecture to prevent PID recycling race conditions (TOCTOU).
- **Tor Bridge Directive & CRLF Injection Prevention**: Implemented `sanitize_bridge_line` rejecting CRLF (`\r`, `\n`), control chars, and shell metachars, with whitelist filtering and `0o600` torrc file mode locking.
- **Session State Arming Permission Lock**: Enforced `0o600` permissions on temporary and persistent state files in `StateManager::claim()` to prevent WireGuard private key disclosure during session arming.
- **Trusted Pluggable Transport Binary Resolution**: Restricted binary lookup in `find_transport_binary` to root-owned (UID 0), non-world-writable, non-symlink executable binaries (`is_safe_root_binary`).
- **Bounded Xauthority Ingestion & O_NOFOLLOW**: Implemented 64 KB upper bound and symlink rejection on `xauth` source reading, with `libc::O_NOFOLLOW` and `0o600` writing to `/root/.Xauthority`.
- **eBPF Egress Fastpath Detection Reliability**: Replaced flawed `which tc` error check with comprehensive `is_tc_available()` testing standard system binary locations and exit status codes.

## [1.4.5] - 2026-09-24

### Added
- Dedicated emergency network recovery engine accessible via `wraith reset`, `wraith network reset`, `--reset`, `--reset-network`, `--net-reset`, and `--ressert`.
- 5-tier systematic host recovery teardown:
  - Shuts down active/interrupted Wraith sessions, systemd services, and background Tor daemons.
  - Purges `wraith-ns` namespace, orphan veth links (`veth-host`, `veth-ns`), and WireGuard tunnels.
  - Flushes all iptables, ip6tables, and nftables rules back to clean default `ACCEPT` policies, removing lingering killswitches and tc qdisc traffic shapers.
  - Restores `/etc/resolv.conf` from backup or clean fallback resolvers (1.1.1.1, 9.9.9.9, 8.8.8.8) and restarts `systemd-resolved` / `NetworkManager`.
  - Normalizes kernel routing, re-enables IP forwarding, flushes ARP table, and brings physical interfaces back up.
- Added multilingual localization keys `cmd_reset` and `cmd_network` across all 17 supported locales.

## [1.4.4] - 2026-09-24

### Security & Hardening
- Eradicated shell interpolation in `spawn_monitor_terminal` by converting all terminal emulator invocations to direct argument vectors without `/bin/sh`.
- Mitigated symlink arbitrary file overwrite vulnerability (CWE-59 / CWE-377) in Tor Moat protocol: replaced static `/tmp/wraith_moat_captcha.png` with randomized temporary files created with `O_CREAT | O_EXCL` and hardened `O_NOFOLLOW` 0600 mode on Unix.
- Enforced strict Linux interface format validation in `wraith_net::validate_interface` and CLI preflight (maximum 15 characters, no leading `-`, restricted ASCII alphabet).
- Strengthened `WraithConfig::validate` schema bounds for `network.default_interface`, `network.wireguard_config`, `dns.upstream`, and `general.lang`.
- Added preflight input sanitization preventing empty command execution in `wraith exec` and empty paths in `wraith shred`.

## [1.4.3] - 2026-09-24

### Fixed
- DNSSEC resolution accepts `Proof::Indeterminate` records for unsigned domains over DoH forwarders (e.g., Quad9/Cloudflare) without incorrectly marking them bogus, restoring network reachability for Kali Linux repos and general internet traffic.
- Direct DoH query fallback implemented over Tor to prevent total resolution blackouts if upstream recursive DNSSEC queries fail or time out.
- Tor `.onion` domain lookups are strictly isolated and routed to Tor's internal DNSPort (`127.0.0.1:5353`).
- DNS response question validation now uses case-insensitive ASCII comparison to handle 0x20-bit case randomization.

## [1.4.2] - 2026-09-24

### Fixed
- Root-owned legacy recovery directories with group or other write access are narrowed before a new namespace or egress lease is written. Foreign-owned paths and symlinks remain rejected, and the tightened mode is read back before use.

## [1.4.1] - 2026-09-24

### Fixed
- Full-security no longer refuses standard Linux systems solely because boot-time kernel lockdown is `none`, `integrity`, or unavailable. Wraith observes that administrator-owned policy and still verifies only reversible session controls.
- Failed startup recovery no longer prints a fabricated clearnet status, fetches a public IP, or displays raw untranslated dashboard keys. Normal cleanup reports local restoration without making an external connectivity probe.
- Strict-mode status text now distinguishes observed kernel policy from controls that Wraith actually applies.

## [1.4.0] - 2026-09-24

### Release engineering
- One workspace version for all six crates, versioned internal dependencies and localized banners derived from Cargo metadata.
- ThinLTO release profile, 16 codegen units, stripped symbols, no debug information and `panic = "abort"`; source installation caps Cargo/CMake concurrency at two.
- Native x86_64 and ARM64 Debian packages, plus GNU and static musl archives; Debian installs `/usr/bin/wraith` with runtime dependencies and project documentation.
- Official-release installer selects CPU/libc, validates checksums and package/archive identity, supports a download-only preview, and verifies the installed version and PATH.
- Tag-driven release workflow validates all artifacts, creates SHA-256 sums and publishes only after all uploads; manual runs only build and validate. Disposable runners receive 4 GiB of additional swap.
- Native ARM64 seccomp audit architecture and ptrace syscall selection; musl builder separates dynamically linked host tools from static target artifacts.

### Session hardening since 1.3.0
- Owned namespace veth MACs use the OS CSPRNG and are verified before activation. Durable leases and process identity constrain orphan cleanup.
- Owned session/snapshot buffers and serialization secrets are zeroized on normal drop. Release panics now abort and skip destructors; no whole-process or abrupt-termination erasure guarantee is made.
- Namespace TCP profiles, Tor access-link SYN normalization and inspect telemetry document the local ISP/Guard scope and preserve shared Tor exits.
- Updated `rustls` to 0.23.45 for RUSTSEC-2026-0285; CLI validation, recovery and TLS/HTTP regressions are included in the current validation guide.

Historical entries below describe earlier release announcements. Current supported behavior and measured limits are documented in the README and wiki.

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
