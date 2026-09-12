# 🛡️ WRAITH WIKI // SOVEREIGN PRIVACY & KERNEL GATEWAY

Welcome to the official technical documentation and wiki for **Wraith** — the warfare-grade Linux privacy suite and sovereign network anonymization gateway.

---

## 🌌 Overview

Wraith is an autonomous, fail-closed Linux privacy session manager and transparent Tor gateway written in modern Rust. It unifies low-level netfilter isolation, hardware identity spoofing, DNSSEC over encrypted DoH, in-flight cleartext DPI sanitization, browser TLS profile spoofing (JA3/JA4), and anti-forensic memory sanitization into a single high-performance binary.

```
+-------------------------------------------------------------------------+
|                       RING 3: USER APPLICATION SPACE                    |
|       Browsers, CLI Pentest Tools (Nmap/Sqlmap/Ffuf), Curl, Python      |
+-------------------------------------------------------------------------+
                                     │
           ┌─────────────────────────┴─────────────────────────┐
           ▼                                                   ▼
Cleartext HTTP (Port 80)                              All TCP Traffic
           │                                                   │
           ▼                                                   ▼
+-----------------------+                            +--------------------+
|  IN-FLIGHT DPI PROXY  |                            |   NETFILTER HOOKS  |
|  127.0.0.1:9055       | ──[Sanitized Headers]──►  |  OUTPUT DROP Trap  |
|  UA/Header Masking    |                            +--------------------+
+-----------------------+                                      │
           │                                                   ▼
           └──────────────────────────────────────────► +--------------------+
                                                        |   TOR TRANSPROXY   |
                                                        |   127.0.0.1:9040   |
                                                        +--------------------+
                                                               │
                                                               ▼
                                                        +--------------------+
                                                        |  TOR CIRCS / HOPS  |
                                                        |  Guard -> Middle   |
                                                        |      -> Exit       |
                                                        +--------------------+
```

---

## 📚 Documentation Index

1. **[Getting Started](Getting-Started)**  
   System prerequisites, automated deployment via `build.sh`, manual cargo compilation, and running your first session.
2. **[Daily Workflow](Daily-Workflow)**  
   Session controls, status dashboard HUD, Tor identity rotation (`-r`), anti-forensic residue purging (`-c`), and pentesting workflows.
3. **[Architecture & Internals](Architecture)**  
   The six-crate workspace breakdown (`wraith-core`, `wraith-net`, `wraith-guard`, `wraith-tor`, `wraith-forensic`, `wraith-cli`), netfilter fail-closed mechanics, and kernel worker masquerading.
4. **[TLS, DPI & HTTP Camouflage](TLS-and-HTTP)**  
   JA3/JA4 fingerprint emulation, RFC 8701 GREASE, cleartext header rewriting on port 9055, and offensive security tool sanitization.
5. **[Troubleshooting & Recovery](Troubleshooting)**  
   Diagnostic checklists, Tor bootstrap stall recovery, systemd conflict resolution, and atomic emergency network reset.
6. **[Threat Model & Scope](Threat-Model)**  
   Detailed defense boundaries, threat vectors, explicit non-goals, and security verification guarantees.

---

## ⚡ Quick Reference

```bash
# Start a detached background session with fail-closed netfilter protection
sudo wraith -s

# Display real-time telemetry dashboard & active circuit hops
sudo wraith -i

# Rotate Tor exit node identity (SIGNAL NEWNYM)
sudo wraith -r

# Execute deep leak test (IPv4/IPv6, DNS, WebRTC UDP RFC 5389)
sudo wraith -t

# Disarm gateway and restore system networking cleanly
sudo wraith -x
```
