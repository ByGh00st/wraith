# Wraith v1.4.6 — Warfare-Grade Security & Kernel Defense Remediation

**Production-grade kernel security hardening, zero-tolerance cryptographic protections, and operational reliability across all six workspace crates.**

## Security & Architectural Hardening

- **X11 Display Authorization Hardening**: Eliminated `xhost +local:` from `spawn_monitor_terminal` to eliminate local unauthorized display access, preventing keylogging and screengrab attack vectors. Enforced strict root-only authority (`+SI:localuser:root`).
- **Root Context Configuration Isolation**: Forbid loading unprivileged user configurations (`~/.config/wraith/config.toml`) when running with root privileges (UID 0), eliminating Local Privilege Escalation (LPE) and malicious overriding of security controls. Enforced root ownership and non-world-writable permission validation.
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

## Added & Improved

- Added single-letter emergency reset shortcuts `-R` and `-N` (`sudo wraith -R` / `sudo wraith -N`).
- Upgraded emergency reset interface to high-tech cybersec HUD telemetry with step-by-step progress logging.
- Added automatic shell completion generation and installation for both Bash and Zsh in `build.sh`.

## Upgrade

```bash
sudo apt update
sudo apt install --only-upgrade wraith
wraith --version
```
