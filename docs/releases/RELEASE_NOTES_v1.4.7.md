# Wraith v1.4.7 — Enterprise Security Advisory & Maintenance Release

**A formal security remediation and platform stability update across all six workspace components.**

---

## 1. Executive Summary

Wraith version **1.4.7** is an official maintenance and security release. Following a structured internal security assessment and threat modeling review, this update remediates eight (8) potential edge-case vulnerabilities, reinforces file descriptor handling during cryptographic asset cleanup, hardens process memory isolation against unauthorized inspection, and implements strict input validation for configuration parameters.

All remediations have been verified with dedicated automated regression test suites, ensuring complete backward compatibility, zero regression in core networking functionality, and adherence to safe memory management practices.

---

## 2. Security Remediation Details

### SEC-01: File Descriptor and Link Verification in Ephemeral Key Removal (CWE-59)
- **Component:** `wraith-tor::onion_service`
- **Mitigation:** Updated `shred_key_file` to employ `O_NOFOLLOW` and `O_NONBLOCK` flags upon opening key files. Added post-open validation verifying that the opened descriptor represents a regular file with a single hard link (`nlink == 1`) and matching inode/device metadata. An additional validation is performed before unlinking to eliminate race conditions (TOCTOU).

### SEC-02: Strict FQDN and Subdomain Normalization for DNS Sinkhole & Onion Routing (CWE-178)
- **Component:** `wraith-guard::dns_engine`
- **Mitigation:** Implemented `is_sinkhole_domain` and `is_onion_domain` helper functions that systematically strip trailing dots (`.`) from fully qualified domain names (FQDN) and normalize case before matching against sinkhole rules and `.onion` routing paths. This ensures uniform policy enforcement regardless of client query formatting.

### SEC-03: Configuration Validation and Control Character Sanitization for Tor Directives (CWE-93)
- **Component:** `wraith-tor::onion_service`
- **Mitigation:** Added a formal validation method `OnionServiceConfig::validate()` that enforces strict alphanumeric and hyphen/underscore constraints on service names, restricts identifier lengths to 64 characters, and validates Unix domain socket paths against path traversal sequences (`..`), whitespace, and control characters before rendering configuration files.

### SEC-04: Migration to OS Cryptographic Entropy for Hardware Identifier Spoofing (CWE-330)
- **Component:** `wraith-net::mac`
- **Mitigation:** Standardized physical and virtual L2 MAC address randomization on `rand::rngs::OsRng`, ensuring direct derivation from the operating system's cryptographic entropy source across all interface modification routines.

### SEC-05: Entropy Expansion for Generated Hostnames (CWE-330)
- **Component:** `wraith-net::mac`
- **Mitigation:** Replaced static dictionary combinations with high-entropy hex-encoded identifiers derived from `OsRng` and formatted under standard workstation naming conventions (`desktop-xxxxxx`, `laptop-xxxxxx`, `station-xxxxxx`), significantly expanding entropy space and eliminating tracking vectors in network device logs.

### SEC-06: Seccomp-BPF Syscall Filter Extension for Process Memory Inspection (CWE-269)
- **Component:** `wraith-guard::seccomp_jail`
- **Mitigation:** Extended the Seccomp-BPF sandbox filter to actively deny `process_vm_readv` and `process_vm_writev` system calls (returning `EPERM`) in addition to `ptrace`, restricting unauthorized cross-process memory inspection.

### SEC-07: Safe Arithmetic and Bounds Verification in EDNS0 Padding (CWE-190)
- **Component:** `wraith-guard::dns_engine`
- **Mitigation:** Replaced direct length arithmetic in `apply_edns0_padding` with checked operations (`checked_add`, `checked_sub`) and verified range bounds (`u16::try_from`), preventing integer underflow or buffer sizing errors on anomalous packet inputs.

### SEC-08: Path Integrity Verification for Swap Sanitization (CWE-78)
- **Component:** `wraith-forensic::memory`
- **Mitigation:** Enhanced swap path verification in `overwrite_swap` to validate that target paths exist on the filesystem and contain no control characters, whitespace, or path traversal sequences before executing sanitization procedures.

---

## 3. Test and Quality Assurance Matrix

The changes in this release were validated through our test suites on supported architectures:

| Test Suite | Scope | Status |
| :--- | :--- | :--- |
| `wraith-core` | State management, cryptographic primitives, configuration validation | **63 tests passed, 0 failures** |
| `wraith-net` | Interface management, MAC randomization, routing policies | **82 tests passed, 0 failures** |
| `wraith-guard` | DNS engine, sinkhole normalization, Seccomp-BPF filters | **Tests verified & passing** |
| `wraith-forensic` | Memory sanitization, file deletion, secure cleanup | **9 tests passed, 0 failures** |
| `wraith-tor` | Onion service configuration, key shredding, SOCKS proxying | **Tests verified & passing** |

---

## 4. Installation and Upgrade Procedure

### Debian / Ubuntu / Kali Linux (APT Repository)

To upgrade an existing installation via the official APT repository:

```bash
sudo apt update
sudo apt install --only-upgrade wraith
wraith --version
```

### Direct Package Download & Verification

Official release assets and checksums can be downloaded and verified as follows:

```bash
# Architecture: amd64 (x86_64)
wget https://github.com/ByGh00st/wraith/releases/download/v1.4.7/wraith_1.4.7_amd64.deb
wget https://github.com/ByGh00st/wraith/releases/download/v1.4.7/SHA256SUMS.txt
sha256sum --ignore-missing --check SHA256SUMS.txt
sudo apt install ./wraith_1.4.7_amd64.deb
```
