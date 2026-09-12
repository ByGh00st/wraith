# 🛡️ THREAT MODEL & OPERATIONAL BOUNDARIES

This document formalizes the defensive scope, operational guarantees, and explicit non-goals of the Wraith system.

---

## 🎯 Assets & Security Objectives

1. **Tor Egress Enforcement:** Guarantee zero clearnet packet leakage across all local applications using kernel-level fail-closed netfilter hooks.
2. **DNS Integrity & Confidentiality:** Eliminate DNS leaks and poisoning attacks through local DNSSEC validation over Tor DoH (`127.0.0.1:5354`).
3. **Hardware & Ephemeral Anonymity:** Randomize MAC addresses, hostname, machine-id, and volatile runtime memory traces.
4. **Anti-Fingerprinting:** Neutralize TCP/IP OS stack fingerprinting (TTL=128, TS=0, MSS=1460) and cleartext HTTP tool signatures.

---

## 🔒 Threat Matrix & Mitigations

| Threat Vector | Mitigation Strategy | Failure Mode / Boundary |
| :--- | :--- | :--- |
| **Unintended TCP Leaks** | Fail-Closed Netfilter `OUTPUT DROP` default policy | Root account can alter rules; concurrent firewall writers uncoordinated |
| **DNS Leaks / Spoofing** | Hickory DNSSEC engine over Tor DoH (RFC 8484) | Insecure delegations remain unsigned |
| **WebRTC STUN Leaks** | Netfilter drop on ports 19302/3478 + RFC 5389 UDP verification | Browser plugins directly talking to raw interfaces |
| **DPI Cleartext Observation** | In-flight HTTP proxy rewriting on port 9055 | Does not inspect encrypted HTTPS traffic without MITM CA |
| **Memory Extraction / Forensics**| DoD 5220.22-M 7-pass shredder + `/dev/shm` RAMFS vault | Cold-boot attacks or compromised kernel Ring-0 rootkits |
| **Kernel Process Inspection** | `prctl(PR_SET_NAME)` masquerade as `[kworker/u16:0]` | `/proc/{pid}/exe` is immutable in Linux kernel space |

---

## ⛔ Explicit Non-Goals

- **Absolute Immunity:** No software can guarantee 100% immunity against targeted nation-state physical compromise or zero-day kernel exploits.
- **Arbitrary UDP/ICMP Routing:** Tor does not natively transport arbitrary UDP or ICMP ping traffic; non-DNS UDP is safely dropped by netfilter to prevent deanonymization.
- **Hardware/Firmware Compromise:** System firmware (BIOS/UEFI) or hardware-level keyloggers remain outside the software boundary.
