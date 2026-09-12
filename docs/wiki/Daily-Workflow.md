# ⚡ DAILY OPERATIONAL WORKFLOW

This document outlines everyday usage patterns, command options, interactive monitors, identity rotation, and authorized security auditing procedures.

---

## 📋 Core Command Matrix

| Shortcut | Long Form | Operational Action |
| :---: | :--- | :--- |
| **`-s`** | `wraith start` | **Arm Gateway**: Starts fail-closed transparent proxy and local DoH engine. |
| **`-x`** | `wraith stop` | **Disarm Gateway**: Restores original clearnet routing and nameservers. |
| **`-r`** | `wraith switch` | **Rotate Identity**: Requests a new Tor cryptographic circuit (`SIGNAL NEWNYM`). |
| **`-c`** | `wraith cleanup` | **Anti-Forensic Purge**: Clears volatile RAM buffers, DNS cache, and temp state. |
| **`-t`** | `wraith test` | **Leak Audit**: Executes automated IPv4, IPv6, DNS, and RFC 5389 UDP STUN tests. |
| **`-i`** | `wraith info` | **HUD Matrix**: Renders real-time telemetry dashboard, circuits, and posture. |
| **`-m`** | `wraith tui` | **Live TUI Monitor**: Launches full-screen terminal monitor with live packet stats. |
| **`-M`** | `wraith monitor`| **In-Flight IDS Monitor**: Streams real-time DPI packet inspections and signatures. |
| **`-K`** | `wraith --kworker`| **Process Masquerade**: Cloaks Wraith in kernel scheduler as `[kworker/u16:0]`. |
| **`-F`** | `wraith -s -F` | **Strict Hardening**: Enforces Seccomp, Kernel Lockdown, and RAMFS crypto vault. |
| **`-u`** | `wraith update`| **In-Place Update**: Clones, compiles as ordinary user, and hot-swaps binary. |

---

## 🔄 Identity Rotation & Circuit Management

When operating through Tor, websites or rate-limiters may temporarily restrict your exit node. To obtain a completely fresh circuit without interrupting your session:

```bash
sudo wraith -r
```

Wraith sends `SIGNAL NEWNYM` to Tor ControlPort (`127.0.0.1:9051`), flushes local DNS caches, and re-queries public IP endpoints. The newly acquired IP, ISO country code, and verification tag are immediately displayed in a dedicated HUD box.

---

## 🧹 Anti-Forensic Purging & Residue Scrubbing

### 1. Quick Residue Flush (`wraith -c`)
Flushes system disk caches, syncs filesystems, and purges Tor ephemeral circuit traces:
```bash
sudo wraith -c
```

### 2. Deep Memory & Swap Shredding (`wraith --cleanup-full`)
Thoroughly unmounts and wipes swap space, scrubs systemd journal buffers, and shreds all user shell history (`.bash_history`, `.zsh_history`, etc.):
```bash
sudo wraith --cleanup-full
```

### 3. DoD 5220.22-M Cryptographic File Shredder
To permanently destroy sensitive artifacts using a 7-pass random-pattern overwrite:
```bash
sudo wraith shred /path/to/sensitive-target.dump
```

---

## 🛡️ Authorized Pentest & Security Auditing Guide

Wraith includes built-in guides and proxy configurations for popular offensive security tools to prevent accidental clearnet leaks:

```bash
sudo wraith pentest
```

### Recommended Tool Tunneling Configurations:
```bash
# Nmap TCP Connect scan through Tor SOCKS5
nmap -sT -Pn -n --proxy socks5://127.0.0.1:9050 <target_ip>

# Curl via In-Flight DPI Sanitizer (Port 9055)
curl -x http://127.0.0.1:9055 https://target.com/login

# Sqlmap vulnerability auditing over SOCKS5
sqlmap -u "http://<target>/id=1" --proxy="socks5://127.0.0.1:9050" --random-agent

# Metasploit Framework SOCKS5 proxy setup
msfconsole -x "setg Proxies socks5:127.0.0.1:9050; setg HTTP_USER_AGENT Mozilla/5.0"
```
