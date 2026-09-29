# Wraith v1.5.0 — Enterprise Stabilization & Formal Verification Release

**A formal stability, reliability, and security verification release across all workspace components, validated against live Linux kernel network namespaces, automated libFuzzer instrumentation, multi-distribution matrices, and Debian packaging policy standards.**

---

## 1. Executive Summary

Wraith version **1.5.0** marks the formal completion of the **Stabilization and Quality Assurance Gate**. Following a strict feature freeze enacted upon the v1.4.7 release, the scope of this milestone was dedicated entirely to system resilience, formal validation, low-level error recovery, parser security, and multi-platform distribution integrity.

All automated continuous integration pipelines have achieved **100% green verification (0 failures, 0 regressions)**:

1. **Kernel-Level End-to-End Integration:** Seven (7) automated network namespace scenarios and live AF_PACKET raw wire SYN audits executed in cryptographically isolated Linux network namespaces, confirming zero interference with host networking infrastructure.
2. **Continuous Parser Fuzzing:** Five (5) dedicated LLVM libFuzzer targets instrumented with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan), completing automated continuous fuzzing cycles with zero memory leaks, zero crashes, and zero panics.
3. **Multi-Distribution Compatibility Matrix:** Verified deployment and operational health across five (5) enterprise and operational Linux environments: Kali Linux (Rolling), Debian 12 (Bookworm), Ubuntu 24.04 LTS, Arch Linux, and Alpine Linux 3.20 (musl static binary).
4. **Debian Packaging Compliance & Zero-Orphan Purge:** Complete compliance with Debian Policy standards, passing `lintian --fail-on error` with zero errors, validated groff manpage integration (`wraith.1`), and deterministic removal of all runtime artifacts upon package purge (`postrm`).

---

## 2. Formal Technical Specifications & Remediation

### Phase 1: Live Linux Kernel Integration (Network Namespace Sandboxing)
- **Namespace Sandbox Harness (`tests/e2e/harness.sh`):** Concludes formal verification of routing policies within isolated network namespaces (`ip netns` / `unshare -n`). This design guarantees total host isolation, ensuring the execution environment's network connectivity and management plane remain untouched while testing privileged netfilter policies.
- **Automated Verification Scenarios:**
  - *Netfilter Policy Integrity:* Verified exact binding of Tor TransPort (`:9040`) redirection rules and enforced IPv6 blackout (`DROP`) policies.
  - *DNS & Cryptographic DNSSEC:* Validated local port-5354 query interception, Tor DoH upstream forwarding, and recursive DNSSEC proof chain validation against root trust anchors.
  - *Tor Bootstrap Synchronization:* Implemented non-blocking polling confirming 100% Tor circuit readiness prior to egress validation via verified public Tor endpoints.
  - *Egress Leak Prevention:* Raw frame monitoring via packet capture on UDP port 53 confirming zero unencrypted DNS queries escape the routing boundary.
  - *Fail-Closed Kill Switch Verification:* Enforced emergency network containment upon simulated daemon termination (`kill -9`), confirming that no clearnet traffic egresses following process interruption.
  - *Deterministic System Restoration:* Validated complete rollback of netfilter chains, restoration of `/etc/resolv.conf`, removal of filesystem immutability flags, and deletion of ephemeral state journals.
  - *Emergency Recovery Audit:* Executed emergency reset routines (`wraith reset`), certifying zero orphan virtual interfaces (`veth-wr-host`, `veth-wr-ns`) or residual routing table entries.
- **Wire-Level SYN Fingerprint Audit (`live_wire_syn_audit.rs`):** Validated raw TCP SYN packet structure inside isolated Linux network namespaces using AF_PACKET sockets, confirming expected TTL (128), MSS (1460), selective timestamp suppression (`TS=0`), initial receive window parameters, and OS-CSPRNG MAC generation.

### Phase 2: Memory Safety & Parser Fuzzing Infrastructure
- **LLVM libFuzzer Integration:** Integrated formal `cargo-fuzz` test targets targeting all exterior byte-parsing boundaries:
  - `fuzz_tcp_wire` (`wraith-net`): Packet parsing and SYN option modification.
  - `fuzz_dns_engine` (`wraith-guard`): RFC 1035 wire-format DNS parsing and normalization.
  - `fuzz_proxy_request` (`wraith-tor`): HTTP/1.1 and CONNECT proxy framing parser.
  - `fuzz_netlink` (`wraith-net`): Unaligned-safe Netlink frame parser (`parse_netlink_frames`).
  - `fuzz_tls_camouflage` (`wraith-tor`): HTTP header sanitization and tunnel parsing.
- **Verification Guarantee:** Instrumented with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan). All targets executed without memory corruption, buffer overflows, memory leaks, or unaligned memory access.

### Phase 3: Platform & Distribution Matrix
- **Operating Environment Compatibility:**
  - **Kali Linux (Rolling):** Validated native `.deb` installation, runtime security policies, and environment diagnostics (`wraith doctor`).
  - **Debian 12 (Bookworm):** Verified on baseline Debian GNU/Linux systemd infrastructure.
  - **Ubuntu 24.04 LTS:** Validated compliance with restricted unprivileged user namespace policies (`kernel.apparmor_restrict_unprivileged_userns`).
  - **Arch Linux:** Verified standalone binary deployment from compressed GNU archives.
  - **Alpine Linux 3.20 (musl-libc):** Verified static compilation without dynamic runtime dependencies; validated that binary contains zero ELF program interpreter entries (`INTERP`).
- **Static Toolchain Wrapper (`.github/musl-rustc-wrapper.sh`):** Solved host-target linking constraints in musl environments by ensuring host procedural macros load system libraries dynamically while compiling the final binary with static CRT linkage.

### Phase 4: Packaging Standard & Zero-Orphan Purge Policy
- **Debian Quality Audit:** Verified zero packaging defects under strict Debian Lintian inspection (`lintian --fail-on error`). Package metadata and capability requirements comply with distribution standards.
- **Clean Purge Lifecycle (`packaging/debian/postrm`):** Added automated maintainer script ensuring that execution of `apt purge wraith` unconditionally purges all created runtime directories (`/var/lib/wraith`, `/run/wraith-tor`, `/var/run/wraith.state`, and configuration backups), leaving zero orphan files on the host.
- **Unix Manual Documentation (`docs/wraith.1`):** Integrated standard groff format manual page installed to `/usr/share/man/man1/wraith.1.gz`, verified clean by `man-db` validation tooling.

### Low-Level Kernel & Syscall Remediations
- **Linux Kernel Network Interface Alias Preservation:** Resolved kernel-level interface alias wiping in `net/core/dev.c` during network namespace migration by re-registering interface aliases post-move.
- **Process Identity & Zombie Termination Handling:** Handled `EINVAL` (error code 22) during `SYS_pidfd_send_signal` invocations to accommodate processes already reaped into the zombie state, ensuring resilient and error-free session termination.
- **Service Discovery Resiliency:** Handled systemd D-Bus communication failures gracefully when running within containerized environments.

---

## 3. Compliance & Quality Assurance Verification Matrix

| Verification Scope | Testing Methodology | Compliance Status |
| :--- | :--- | :--- |
| **Continuous Parser Hardening** | 5 libFuzzer targets + ASan / UBSan | **COMPLIANT** (0 crashes, 0 memory leaks) |
| **Kernel Network Integration** | 7 NetNS scenarios + AF_PACKET audit | **COMPLIANT** (100% Green, zero host disruption) |
| **Multi-Distribution Matrix** | 5 environments (Kali, Debian, Ubuntu, Arch, Alpine) | **COMPLIANT** (Verified deployment & teardown) |
| **Debian Packaging Standards** | Lintian strict `--fail-on error` & `postrm purge` | **COMPLIANT** (0 errors, zero orphan files) |
| **Unit & Regression Suites** | Multi-crate workspace unit tests | **COMPLIANT** (271 passed on Linux / 269 on Windows, 0 failures) |

---

## 4. Installation and Upgrade Procedures

### APT Package Manager (Debian / Ubuntu / Kali Linux)

```bash
sudo apt update
sudo apt install --only-upgrade wraith
wraith --version
```

### Direct Release Binary Installation

```bash
# Architecture: amd64 (x86_64)
wget https://github.com/ByGh00st/wraith/releases/download/v1.5.0/wraith_1.5.0_amd64.deb
wget https://github.com/ByGh00st/wraith/releases/download/v1.5.0/SHA256SUMS.txt
sha256sum --ignore-missing --check SHA256SUMS.txt
sudo apt install ./wraith_1.5.0_amd64.deb
```

### Static musl Archive (Alpine / Standalone Linux)

```bash
wget https://github.com/ByGh00st/wraith/releases/download/v1.5.0/wraith-v1.5.0-x86_64-unknown-linux-musl.tar.gz
tar -xzf wraith-v1.5.0-x86_64-unknown-linux-musl.tar.gz
sudo install -m 0755 wraith /usr/local/bin/wraith
```

---

## 5. Security & Responsible Use Notice

Wraith is provided as an administrative, diagnostic, and network privacy tool for authorized research, system administration, and network engineering. Usage must comply with all applicable local, national, and international laws and regulations. Refer to the project [LICENSE](../../LICENSE) (GNU General Public License v3.0) and [THREAT_MODEL.md](../THREAT_MODEL.md) for terms of use, operational boundaries, and warranty disclaimers.
