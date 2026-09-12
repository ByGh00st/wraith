# DAILY WORKFLOW // OPERATIONAL PROTOCOLS & INTEGRATION

Operational reference for everyday session management, telemetry monitoring, circuit rotation, forensic data sanitization, and security auditing workflows.

---

## 1. Primary Command Reference

| Flag / Shortcut | Command Syntax | Operational Function |
| :---: | :--- | :--- |
| **`-s`** | `sudo wraith -s [OPTIONS]` | **Initialize Session:** Activates fail-closed transparent proxying and local DoH relay. |
| **`-x`** | `sudo wraith -x [-d]` | **Terminate Session:** Restores pre-session netfilter rules, routing tables, and nameservers. |
| **`-r`** | `sudo wraith -r` | **Circuit Rotation:** Issues `SIGNAL NEWNYM` to Tor ControlPort to acquire a new exit identity. |
| **`-c`** | `sudo wraith -c` | **Volatile State Purge:** Clears kernel page caches, ARP cache, and ephemeral session buffers. |
| — | `sudo wraith --cleanup-full` | **Deep Storage Purge:** Deactivates swap, overwrites swap space, and scrubs session authentication records. |
| **`-t`** | `sudo wraith -t` | **Multi-Vector Leak Audit:** Performs RFC 5389 UDP STUN tests, DNS validation, and IPv4/IPv6 egress verification. |
| **`-i`** | `sudo wraith -i` | **Telemetry Dashboard:** Queries active connection metrics, public exit node IP, and circuit relay nodes. |
| **`-M`** | `sudo wraith -M` | **Real-Time DPI Monitor:** Streams packet inspections and signature classifications from port 9055. |
| **`-K`** | `sudo wraith -s -K` | **Process Masquerade:** Replaces scheduler process name (`PR_SET_NAME`) with `[kworker/u16:0]`. |
| **`-F`** | `sudo wraith -Fs` | **Strict Preset:** Demands kernel lockdown, `kexec_load_disabled`, and memory vault locks. |
| **`-u`** | `sudo wraith -u` | **Official In-Place Update:** Fetches source from GitHub, builds non-root, and atomically replaces binary. |

---

## 2. Circuit Rotation & Identity Lifecycle

When operating across rate-limited or congested endpoints, operators can cycle Tor exit nodes without terminating the active session:

```bash
sudo wraith -r
```

### Operational Mechanics:
1. Wraith connects to Tor ControlPort (`127.0.0.1:9051`) using cookie or password authentication.
2. Sends the `SIGNAL NEWNYM` directive.
3. Tor marks current circuits as dirty, ensuring subsequent TCP connection requests negotiate a new three-hop path (Guard -> Middle -> Exit).
4. Clears local DNS cache entries.
5. Re-queries public verification endpoints to confirm the new exit IP address and jurisdiction.

> [!IMPORTANT]
> **Stream Boundary Notice:** In accordance with Tor specification, `SIGNAL NEWNYM` does not migrate or terminate currently established, active TCP streams. New circuits apply exclusively to subsequent connections opened after the signal.

---

## 3. Data Sanitization & Memory Protocols

### 3.1 Ephemeral State Cleansing (`wraith -c`)
Flushes volatile kernel memory caches and file buffers to ensure clean baseline states:
```bash
sudo wraith -c
```
- Executes `sync` to flush unwritten filesystem buffers to storage.
- Writes to `/proc/sys/vm/drop_caches` to free clean pagecache, dentries, and inodes.
- Flushes ARP neighbor tables.

### 3.2 Deep Swap & Session Cleansing (`wraith --cleanup-full`)
Recommended prior to host decommissioning or after intensive auditing sessions:
```bash
sudo wraith --cleanup-full
```
- Disables active swap partitions (`swapoff -a`).
- Performs overwrite patterns across raw swap devices to sanitize unencrypted memory dumps.
- Truncates transient session logs in `/var/log/` and shell history files.

### 3.3 DoD 5220.22-M Cryptographic File Sanitization
To sanitize target files with multi-pass random data overwrites:
```bash
sudo wraith shred /path/to/target.dump
```
- Executes 7 sequential overwrite passes following Department of Defense 5220.22-M specifications.
- Issues `fsync` after each pass to force physical write execution.
- Truncates file length to zero before unlinking from directory structure.

> [!NOTE]
> **Solid-State Drive (SSD) Caveat:** Flash translation layers (FTL), wear-leveling algorithms, and over-provisioned blocks on modern NVMe/SATA SSDs can prevent in-place overwriting of physical flash cells. Complete sanitization on flash media requires full-disk encryption (FDE) or hardware cryptographic erase.

---

## 4. Authorized Network Auditing Protocols

For authorized security evaluations, penetration testing, and vulnerability research, client tools should be configured to use local SOCKS5 or HTTP proxies to ensure complete network isolation:

```bash
# Built-in configuration guide:
sudo wraith pentest
```

### Recommended Proxy Client Configurations:

#### 1. Network Discovery (Nmap)
Tor carries TCP exclusively. Scans must utilize TCP connect (`-sT`) without ICMP ping discovery (`-Pn`):
```bash
nmap -sT -Pn -n --proxy socks5://127.0.0.1:9050 <target_host>
```

#### 2. HTTP Inspection (Curl via Port 9055 Relay)
Routing cleartext HTTP requests through the in-flight DPI sanitizer automatically removes identifying tool signatures:
```bash
curl -x http://127.0.0.1:9055 http://example.org/api
```

#### 3. Web Application Auditing (Sqlmap)
Enforces SOCKS5 routing and randomized User-Agent headers:
```bash
sqlmap -u "http://target.example/query?id=1" --proxy="socks5://127.0.0.1:9050" --random-agent
```

#### 4. Post-Exploitation Frameworks (Metasploit)
Configures global proxy settings to avoid accidental egress over raw interfaces:
```bash
msfconsole -x "setg Proxies socks5:127.0.0.1:9050; setg HTTP_USER_AGENT Mozilla/5.0"
```
