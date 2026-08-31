<p align="center">
  <img src="https://img.shields.io/badge/WRAITH--PRIME-v8.0_GEN--4-8855ff?style=for-the-badge&logo=ghostery&logoColor=white" alt="Version">
  <img src="https://img.shields.io/badge/LANGUAGE-PURE_RUST_2021-00d4ff?style=for-the-badge&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/TARGET-x86__64--unknown--linux--gnu-ff3366?style=for-the-badge&logo=linux&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/SECURITY-ENTERPRISE_PRIVACY_STANDARD-00ff88?style=for-the-badge&logo=matrix&logoColor=white" alt="Standard">
  <img src="https://img.shields.io/badge/TEST_SUITE-26%2F26_PASS-3399ff?style=for-the-badge&logo=checkmarx&logoColor=white" alt="Tests">
</p>

```ascii
 ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗   ██████╗ ██████╗ ██╗███╗   ███╗███████╗
 ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║   ██╔══██╗██╔══██╗██║████╗ ████║██╔════╝
 ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║   ██████╔╝██████╔╝██║██╔████╔██║█████╗  
 ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║   ██╔═══╝ ██╔══██╗██║██║╚██╔╝██║██╔══╝  
 ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║   ██║     ██║  ██║██║██║ ╚═╝ ██║███████╗
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝
```

<h3 align="center">High-Assurance Kernel-Level Network Privacy & Anti-Fingerprinting Engine</h3>
<p align="center">
  <b>Engineered in Pure Rust (12,484 Lines) for Linux Systems & Security Engineering</b><br>
  <i>Ring 0/3 Hardened • Netlink FIB Engine • Zero-Copy IDS • 50+ Tool DPI Sanitizer • JA3/JA4 GREASE TLS • Encrypted RAMFS Vault</i>
</p>

---

## 🌌 System Overview

**Wraith-Prime** is a high-assurance, kernel-level network privacy, protocol normalization, and anti-fingerprinting framework designed for security researchers, privacy engineering professionals, and authorized auditing operations.

Built completely from scratch in pure Rust across **6 modular crates**, Wraith operates directly at the kernel and network boundary using **raw `AF_NETLINK` sockets, Seccomp-BPF syscall filters, `AF_PACKET` zero-copy dissectors, and wire-level protocol synthesizers**. It enforces zero-trust fail-closed network routing, active WebRTC STUN leak protection, in-flight auditing tool signature sanitization, and locked in-memory RAMFS vaults.

---

## ⚡ Core Architectural Pillars

```mermaid
graph LR
    classDef kBox fill:#0f172a,stroke:#38bdf8,stroke-width:1.5px,color:#f8fafc;
    classDef gBox fill:#0f172a,stroke:#4ade80,stroke-width:1.5px,color:#f8fafc;
    classDef tBox fill:#0f172a,stroke:#c084fc,stroke-width:1.5px,color:#f8fafc;

    subgraph G1["1. Wire & Hardware Gate"]
        L0["🔒 RAMFS Vault & Shredder<br/><sub>ChaCha20 • mlockall • DMI Cloak</sub>"]:::kBox
        L1["⚡ Netlink FIB & Seccomp<br/><sub>AF_NETLINK • Fail-Closed Gate</sub>"]:::kBox
    end

    subgraph G2["2. Zero-Copy IDS & DPI"]
        L2["🛡️ 50+ Tool DPI Sanitizer<br/><sub>In-Flight UA Rewrite • STUN Trap</sub>"]:::gBox
        L3["🎭 TLS GREASE & p0f Mask<br/><sub>JA3/JA4 Mimicry • TTL=128</sub>"]:::gBox
    end

    subgraph G3["3. Anonymous Egress Mesh"]
        L4["🌐 Multi-Hop Tor & DNSSEC<br/><sub>RFC 1035 UDP • Five-Eyes Shield</sub>"]:::tBox
    end

    G1 ==>|Zero-Copy Stream| G2
    G2 ==>|Camouflaged Tunnel| G3
```

---

## 🛡️ Privacy & Security Comparison Matrix

| Security Feature / Vector | Anonsurf (Bash) | TorGhost (Python) | Proxychains-NG (C) | Tails OS (Debian) | Wraith-Prime GEN-4 (Rust) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Execution Architecture** | Unsafe Shell Scripts | GC Python Wrapper | `LD_PRELOAD` Hook | Full OS Environment | **Pure-Rust Sovereign Crates (Zero GC)** |
| **Routing Mechanism** | Spawns `ip` / `route` CLI | Spawns `iptables` CLI | Hijacks `connect()` | Kernel Netfilter | **Direct `AF_NETLINK` FIB Socket API** |
| **Fail-Closed KillSwitch** | ❌ Prone to Script Hang | ❌ Fragile Subprocess | ❌ Leaks on Non-TCP | ⚠️ Static Firewall | **✔ Async Watchdog (<1ms Kernel Drop)** |
| **50+ Tool DPI Sanitizer** | ❌ None | ❌ None | ❌ None | ❌ None | **✔ In-Flight Header Normalization** |
| **Diversified UA Pool** | ❌ None | ❌ None | ❌ None | ❌ Standard Tor UA | **✔ Dynamic Multi-Browser Rotation** |
| **DNS Leak Mitigation** | `/etc/resolv.conf` rewrite | `/etc/resolv.conf` rewrite | `proxyresolv` script | Loopback Resolver | **✔ RFC 1035 + EDNS0 468B Padding** |
| **WebRTC STUN Trapping** | ❌ Vulnerable | ❌ Vulnerable | ❌ Vulnerable | ⚠️ Browser Config Only | **✔ Hardware `AF_PACKET` STUN Trap** |
| **IPv6 Leak Blackout** | Partial Disable | ❌ Unmanaged | ❌ Bypassed | Kernel Drop | **✔ Dual sysctl & ip6tables Blackout** |
| **TLS JA3/JA4 Mimicry** | ❌ None | ❌ None | ❌ None | ❌ Standard Tor Client | **✔ RFC 8701 GREASE TLS Synthesizer** |
| **TCP/IP p0f Stack Mask** | ❌ Linux Default (TTL 64)| ❌ Linux Default (TTL 64)| ❌ Linux Default (TTL 64)| ❌ Linux Default (TTL 64)| **✔ Windows 11 Profile (TTL 128, TS 0)** |
| **In-Memory RAMFS Vault** | ❌ Plaintext Temp Files | ❌ Plaintext Memory | ❌ None | ⚠️ Tmpfs (Unencrypted) | **✔ ChaCha20-Poly1305 `mlock` Vault** |
| **Anti-Forensics Wipe** | `shred` binary call | Basic `os.remove` | ❌ None | RAM wipe on shutdown | **✔ DoD 5220.22-M 7-Pass Zeroizer** |
| **Memory Footprint** | External Utilities | ~45 MB (Python VM) | ~2 MB (Hook Only) | Entire OS | **< 3.2 MB Locked Physical Memory** |

---

## 📂 Modular Crate Topology

Wraith is cleanly architected into 6 highly decoupled, zero-warning pure-Rust crates:

```
wraith/
├── Cargo.toml                              # Sovereign Workspace Root Manifest
├── LICENSE                                 # GNU General Public License v3.0 (GPLv3)
├── README.md                               # Operational Architecture & Documentation
├── build.sh                                # Production Linux Build & Installation Script
└── crates/
    ├── wraith-core/                        # [Core & Memory Security Layer]
    │   ├── src/crypto.rs                   # Constant-Time Cryptography (ChaCha20, Poly1305, SHA-256)
    │   ├── src/vault.rs                    # Encrypted RAMFS Vault (mlockall, MADV_DONTDUMP, XOR Scrambler)
    │   ├── src/kernel_lockdown.rs          # Kernel Hardening (kexec disable, ptrace scope, sysctl lockdown)
    │   ├── src/process_lockdown.rs         # Process Capability Stripping (PR_SET_NO_NEW_PRIVS)
    │   └── src/state.rs                    # Atomic State Lifecycle & Safe Persistence
    │
    ├── wraith-net/                         # [Kernel Networking & DPI Layer]
    │   ├── src/netlink.rs                  # Direct AF_NETLINK Route, Link, Address & FIB Rule Engine
    │   ├── src/ids.rs                      # Zero-Copy AF_PACKET Dissector, 50+ Tool DPI Sanitizer & STUN Trap
    │   ├── src/tcp_stack.rs                # TCP/IP Stack Normalizer & p0f Evasion (TTL=128, TS=0)
    │   ├── src/ipv6.rs                     # IPv6 Dual-Stack Blackout & Leak Guard
    │   ├── src/mac.rs                      # IEEE 802.3 Hardware MAC Address Randomizer
    │   ├── src/namespace.rs                # Isolated Kernel Network Namespace (veth jail)
    │   ├── src/nftables.rs                 # Transactional Netfilter & iptables Fail-Closed Rule Manager
    │   └── src/traffic_shaper.rs           # Kernel TC/Netem Traffic Shaping (Jitter & Latency Obfuscation)
    │
    ├── wraith-guard/                       # [Sovereign Defense & DNS Engine]
    │   ├── src/dns_engine.rs               # RFC 1035 UDP DNS Server + EDNS0 (468B) Padding + Sinkhole
    │   ├── src/killswitch.rs               # Fail-Closed Async Watchdog Engine (<1ms Panic Drop)
    │   ├── src/bpf_filter_engine.rs        # Classic BPF / eBPF Raw Packet Assembly & Filtering
    │   ├── src/seccomp_jail.rs             # Strict Seccomp-BPF Syscall Allowlist Filter
    │   └── src/leak.rs                     # Multi-Vector Egress Leak Auditor
    │
    ├── wraith-tor/                         # [Tor Transport & TLS Camouflage Layer]
    │   ├── src/grease.rs                   # RFC 8701 GREASE JA3/JA4 TLS 1.3 ClientHello Synthesizer
    │   ├── src/circuit.rs                  # Multi-Hop Circuit Topology & Geographic Profiler
    │   ├── src/control.rs                  # Tor Control Protocol Interface (SIGNAL NEWNYM, Telemetry)
    │   ├── src/onion_service.rs            # Ephemeral v3 Onion Hidden Service Controller
    │   └── src/bridge.rs                   # obfs4 / Snowflake Pluggable Transport Manager
    │
    ├── wraith-forensic/                    # [Anti-Forensics & Hardware Cloaking Layer]
    │   ├── src/shred.rs                    # DoD 5220.22-M 7-Pass Magnetic Zeroizer
    │   ├── src/anti_debug_probe.rs         # Dynamic RE Detection (PTRACE_TRACEME, TracerPid Probe)
    │   ├── src/hardware_cloaker.rs         # Hardware Serial & /etc/machine-id Mutator
    │   ├── src/browser.rs                  # Browser Profile Hardener (Canvas, WebGL, Audio Shield)
    │   └── src/logs.rs                     # System Journal, Bash History & Memory Dump Sanitizer
    │
    └── wraith-cli/                         # [Command Interface & TUI Dashboard]
        ├── src/display.rs                  # Cyberpunk Terminal Presentation Engine & Telemetry Cards
        ├── src/commands.rs                 # Subcommand Handlers (start, stop, doctor, bench, pentest)
        ├── src/tui.rs                      # Interactive Real-Time Circuit & Threat Telemetry TUI
        └── src/benchmark.rs                # Sovereign Cryptographic Throughput Benchmark
```

---

## 🚀 Quickstart & Installation

### 1. Automated Installation
Execute the automated installer on any modern Linux / Debian / Kali environment:

```bash
chmod +x build.sh
sudo ./build.sh
```

### 2. Manual Compilation
```bash
cargo build --release
sudo cp target/release/wraith /usr/local/bin/wraith
```

---

## 💻 Operational Command Reference

```bash
sudo wraith [COMMAND] [OPTIONS]
```

### ⚡ Operational Modes

| Command | Operational Action |
| :--- | :--- |
| `sudo wraith --gen4` | **Apex GEN-4 Mode**: Deploys all 21 privacy layers simultaneously (Netlink, DNS Proxy, Zero-Copy IDS, DPI Sanitizer, GREASE, Seccomp, RAMFS Vault, Browser Shield). |
| `sudo wraith --black-level` | **Maximum Hardening**: Full-spectrum network anonymization, hardware signature cloaking, and TCP stack normalization. |
| `sudo wraith --gen4 -d` | **Ephemeral Execution**: Auto-shreds session artifacts, temporary logs, and state files via DoD 7-Pass on termination. |
| `sudo wraith doctor` | **Kernel & System Integrity Auditor**: Verifies IPv4/IPv6 sysctls, Tor daemon state, Netlink connectivity, and seccomp features. |
| `sudo wraith bench` | **Cryptographic Benchmark**: Evaluates ChaCha20 and SHA-256 throughput in GB/s. |
| `sudo wraith pentest` | **Security Research Guide**: Displays guidance for running network assessment tools over anonymized circuits. |

### 🛠️ Granular Control Flags

```bash
# Maximum Stealth: MAC Randomize + NetNS Jail + Five Eyes Excluded Exits + Full GPU/Font/Resolution Shield
sudo wraith -s -m -n -p stealth --shield --font-jail

# Hardware Cloaking & TCP/IP p0f Masking + Network Jitter
sudo wraith -s --cloaking --tcp-mask --jitter

# Standard Start (Fail-Closed KillSwitch ON)
sudo wraith -s

# Censorship Bypass with obfs4 Pluggable Transports
sudo wraith -s -b

# Multi-Vector Leak Verification Probe
sudo wraith -t

# Live Circuit Telemetry & Active IP Check
sudo wraith -i

# Forensic Eradication (Wipe RAM caches, Swap partition, and session logs)
sudo wraith -c --cleanup-full

# Clean Stop & Restore Original Network Interface State
sudo wraith -x
```

---

## ⚔️ In-Flight DPI Tool Signature Sanitization (50+ Matrix)

When authorized security auditing tools or custom scripts send HTTP requests through Wraith, their default headers expose identifiable signatures (`User-Agent: sqlmap/1.8`, `User-Agent: Nmap Scripting Engine`, etc.) to target systems and network monitors.

Wraith's **Zero-Copy `AF_PACKET` Deep Packet Inspection (DPI) Engine** scans Layer-4 streams on the fly and **automatically rewrites auditing signatures into legitimate, randomized browser headers** before packets leave the local gateway.

```
[Tool Egress: "User-Agent: sqlmap/1.8"] ➔ [Wraith In-Flight DPI] ➔ [Wire: "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0"]
```

### 🎯 Supported Tool Matrix (50+ Pre-Configured Signatures)

| Category | Targeted & Normalized Signatures |
| :--- | :--- |
| **🌐 Network & Port Scanners** | `Nmap (NSE)`, `masscan`, `RustScan`, `OWASP ZAP`, `Metasploit (msf)`, `BurpSuite`, `BurpCollaborator` |
| **🔍 Web Content & Fuzzers** | `ffuf`, `gobuster`, `dirsearch`, `feroxbuster`, `Kiterunner`, `Wfuzz`, `Katana`, `Arjun` |
| **💥 Vulnerability Scanners** | `sqlmap`, `Nikto`, `nuclei`, `httpx`, `wpscan`, `Commix`, `dalfox`, `Ghauri`, `Droopescan` |
| **📡 OSINT & Subdomain Recon** | `Amass`, `Subfinder`, `Sublist3r`, `theHarvester`, `DNSRecon`, `WhatWeb`, `wafw00f`, `EyeWitness` |
| **⚙️ HTTP & Code Libraries** | `python-requests`, `python-urllib`, `curl/`, `Wget/`, `aiohttp`, `httplib2`, `axios/`, `node-fetch`, `Go-http-client`, `Java/`, `libwww-perl`, `Scrapy` |
| **🔐 Credential & Auditing** | `Hydra`, `Medusa`, `CrackMapExec`, `NetExec`, `Impacket`, `PostmanRuntime`, `Insomnia`, `testssl`, `sslscan` |

---

### 🎭 Diversified Multi-Browser User-Agent Pool

To prevent static User-Agent correlation and client profiling across consecutive sessions, **Wraith avoids single static headers**. 

Headers are dynamically assigned from a **stream-seeded pool of authentic modern browsers**:

```rust
pub const BROWSER_USER_AGENT_POOL: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
];
```

* **Session Consistency**: Rewriting maintains deterministic consistency for streams within the same TCP session to avoid mid-session header flapping.
* **RFC 7230 Byte-Safe Alignment**: In-flight byte replacements preserve HTTP payload framing and pad length variations with standard trailing header whitespace.

---

### 🚨 Unrecognized & Custom Tool Detection (Heuristic Normalization)

What happens if an auditor uses a custom Python script, proprietary Go client, or an unlisted tool (`User-Agent: my-custom-recon-bot-v3.0`)?

1. **Heuristic Detection**: Wraith inspects HTTP `User-Agent` headers on the wire. If the header does not match standard browser syntax (`Mozilla/5.0`), it is flagged as an **identifiable tracking vector**.
2. **Automatic Normalization**: To prevent unique client profiling, Wraith's DPI engine intercepts and rewrites the header to a randomized authentic browser signature in-flight.
3. **Live Operator Alert**: An interactive alert is printed to the terminal with telemetry details:

```text
  ╔════════════════════════════════════════════════════════════════════════════════════════════════╗
  ║  ⚠️ WRAITH-DPI // UNRECOGNIZED CUSTOM USER-AGENT INTERCEPTED                                    ║
  ╠════════════════════════════════════════════════════════════════════════════════════════════════╣
  ║  • Detected Raw Header: User-Agent: my-custom-recon-bot-v3.0                                   ║
  ║  • Intercept Decision : Auto-sanitized to randomized authentic Browser User-Agent Pool         ║
  ║  • Operational Rationale : Non-browser / bespoke User-Agents expose unique tracking markers!     ║
  ║  • Operator Control   : To pass verbatim headers, configure dedicated transparent proxy rule.  ║
  ╚════════════════════════════════════════════════════════════════════════════════════════════════╝
```

---

## ⚖️ Legal & Operational Disclaimer

> [!IMPORTANT]
> **LEGAL NOTICE & TERMS OF ENGAGEMENT**
>
> 1. **Authorized Security Research & Privacy Protection**: **Wraith-Prime** is designed and distributed strictly for authorized security assessments, professional penetration testing, authorized red-team auditing, and privacy defense research.
> 2. **Compliance with Laws**: Users are solely responsible for complying with all applicable local, state, national, and international laws, including computer fraud and abuse legislation (e.g., US CFAA, EU NIS2, UK Computer Misuse Act).
> 3. **Disclaimer of Liability**: The developers and contributors assume **zero liability** and are not responsible for any misuse, damage, unauthorized access, or legal consequences resulting from the operation of this software.
> 4. **Explicit Authorization Required**: Never execute network assessment or scanning tools against infrastructure or networks without prior written authorization from the system owners.

---

## 📜 License

Distributed under the **GNU General Public License v3.0 (GPLv3)**. See [LICENSE](file:///LICENSE) for the full copyleft license terms.
