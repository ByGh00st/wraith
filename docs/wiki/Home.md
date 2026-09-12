# WRAITH DOCUMENTATION // LINUX PRIVACY & NETWORK ISOLATION GATEWAY

Technical documentation and formal specifications for **Wraith** — an open-source, fail-closed Linux network privacy and transparent Tor routing framework.

---

## 1. System Overview

Wraith is an autonomous, fail-closed network routing and privacy management framework engineered in Rust for Linux operating systems. The system integrates host-level netfilter packet interception, dedicated Tor daemon supervision, cryptographic DNSSEC verification over DNS-over-HTTPS (RFC 8484), cleartext HTTP header normalization (port 9055), and verified browser TLS ClientHello handshakes (BoringSSL).

All configuration changes—including routing rules, sysctl parameters, nameserver configurations, and interface states—are journaled to non-volatile state prior to mutation, ensuring deterministic restoration upon session termination.

```
+-------------------------------------------------------------------------+
|                       RING 3: USER APPLICATION SPACE                    |
|           Browsers, CLI Utilities, Network Tools, Background Tasks      |
+-------------------------------------------------------------------------+
                                     │
           ┌─────────────────────────┴─────────────────────────┐
           ▼                                                   ▼
Cleartext HTTP (Port 80)                                All TCP Traffic
           │                                                   │
           ▼                                                   ▼
+-----------------------+                             +--------------------+
|  IN-FLIGHT DPI RELAY  |                             |   NETFILTER HOOKS  |
|  127.0.0.1:9055       | ──[Normalized Headers]──►   |  OUTPUT DROP Trap  |
|  Header Sanitization  |                             +--------------------+
+-----------------------+                                       │
           │                                                    ▼
           └──────────────────────────────────────────►  +--------------------+
                                                         |   TOR TRANSPROXY   |
                                                         |   127.0.0.1:9040   |
                                                         +--------------------+
                                                                │
                                                                ▼
                                                         +--------------------+
                                                         |  TOR RELAY CIRCUIT |
                                                         |  Guard -> Middle   |
                                                         |      -> Exit       |
                                                         +--------------------+
```

---

## 2. Technical Documentation Index

| Section | Scope & Functional Description |
| :--- | :--- |
| **[Getting Started](Getting-Started)** | System prerequisites, compiler dependencies, automated installation, and initial session execution. |
| **[Daily Workflow](Daily-Workflow)** | Operational command reference, status telemetry, circuit rotation (`-r`), and data sanitization protocols. |
| **[Architecture & Internals](Architecture)** | Modular 6-crate architecture, netfilter packet routing pipeline, process tracking (`/proc/{pid}/exe`), and STUN audit mechanics. |
| **[TLS & HTTP Camouflage](TLS-and-HTTP)** | Cleartext HTTP header filtering (port 9055), BoringSSL browser TLS profiles (Chrome 131, Firefox 133, Safari 18), and RFC 8701 GREASE. |
| **[Troubleshooting & Recovery](Troubleshooting)** | Diagnostic resolution procedures, Tor bootstrap handling, port conflict remediation, and atomic network restoration. |
| **[Threat Model & Scope](Threat-Model)** | Security boundaries, threat matrix, cryptographic guarantees, and explicit system non-goals. |

---

## 3. Operational Reference

```bash
# Initialize fail-closed transparent proxy session
sudo wraith -s

# Query live session telemetry, exit node IP, and circuit topology
sudo wraith -i

# Request new Tor circuit identity (SIGNAL NEWNYM)
sudo wraith -r

# Execute multi-vector leak audit (IPv4/IPv6, DNSSEC, WebRTC STUN RFC 5389)
sudo wraith -t

# Terminate session and restore original network configuration
sudo wraith -x
```
