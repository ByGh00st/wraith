# 🏗️ WRAITH ARCHITECTURE & INTERNALS

This document provides a low-level architectural breakdown of the Wraith codebase, detailing the 6-crate topology, netfilter packet traversal, unforgeable process tracking, and leak prevention mechanisms.

---

## 📂 Modular Six-Crate Topology

Wraith is engineered as a modular, separation-of-concerns Cargo workspace:

```
crates/
├── wraith-core/       # Shared primitives, atomic state manager, config, zeroizing buffers
├── wraith-net/        # Netfilter/iptables rules, IPv6 drop, MAC spoofing, traffic shaper
├── wraith-guard/      # DNS engine (DoH/DNSSEC), leak tests, honey ports, killswitch
├── wraith-tor/        # Tor daemon lifecycle, ControlPort client, TLS proxy, Moat bridges
├── wraith-forensic/   # DoD 7-pass shredder, log scrubbing, memory locking, process masquerading
└── wraith-cli/        # Unified CLI command dispatcher, ANSI display tables, 17-language i18n
```

---

## 🛡️ Netfilter Fail-Closed Routing Pipeline

When Wraith arms (`wraith -s`), the firewall table configuration executes transactionally:

```
[OUTBOUND PACKET FROM LOCAL APPLICATION]
                    │
                    ▼
     Is Destination Loopback or Tor UID?
                    │
           ┌────────┴────────┐
          YES                NO
           │                 │
           ▼                 ▼
     [ALLOW LOCAL]    Is Port 53 (DNS)?
                             │
                    ┌────────┴────────┐
                   YES                NO
                    │                 │
                    ▼                 ▼
          REDIRECT to Port 5354   Is Port 80 (Cleartext HTTP)?
          (Local Tor DoH Relay)       │
                                     ┌┴┐
                                   YES  NO
                                    │    │
                                    ▼    ▼
                       REDIRECT to 9055   REDIRECT to 9040
                       (DPI Sanitizer)    (Tor TransPort)
```

### Table Rule Specifications:
1. **Default Drop:** `iptables -P OUTPUT DROP`, `INPUT DROP`, `FORWARD DROP`.
2. **DNS Egress Interception:** Port 53 (UDP/TCP) is unconditionally caught and redirected to `127.0.0.1:5354` (Hickory DNSSEC DoH server).
3. **HTTP Cleartext Wire Scrubbing:** Port 80 SYN packets are redirected to `127.0.0.1:9055` for in-flight header rewriting.
4. **All Remaining TCP:** Redirected to `127.0.0.1:9040` (Tor transparent proxy).
5. **Fail-Closed Guarantee:** Any packet that fails to match the proxy redirection rules hits the default DROP policy.

---

## 🕵️ Kernel Worker Masquerading & `/proc/{pid}/exe` Tracking

When started with `--aggressive-masquerade` (`-K`), Wraith invokes:
```c
prctl(PR_SET_NAME, "[kworker/u16:0]");
```
This rewrites `/proc/self/comm` in the Linux kernel scheduler.

### StateManager Inode Verification:
Standard process inspectors fail when a process changes its name. `StateManager::is_running()` in `wraith-core` uses a multi-tier verification algorithm:
1. **Signal 0 Check:** `libc::kill(pid, 0)` verifies PID existence and access rights.
2. **Canonical Binary Inode:** Reads `/proc/{pid}/exe` (`std::fs::read_link`), which the Linux kernel guarantees always points to the true executable path on disk, unforgeable by userspace.
3. **Cloaked Comm Prefix:** Accepts `[kworker` signatures as valid active sessions.

---

## 🔍 RFC 5389 WebRTC STUN Leak Detection

WebRTC browsers gather interactive connectivity candidates using STUN datagrams. Wraith implements an RFC 5389 compliant probe:
- **Header Structure:** 20 bytes containing Message Type `0x0001` (Binding Request), Magic Cookie `0x2112A442`, and a 12-byte cryptographically random Transaction ID.
- **Dual-Stack Inspection:** Probes ports 19302 and 3478 over both **UDP** (`tokio::net::UdpSocket`) and **TCP** (`TcpStream`).
- **Fail-Closed Audit:** If any outbound STUN response packet is received, Wraith immediately flags a high-priority leak alert.
