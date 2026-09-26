# Wraith v1.3.0 — 1,338+ Tool In-Flight DPI Matrix, Compile-Time XOR-0x7A EDR Evasion & Dual-Engine Kernel Hardening

We are proud to release **Wraith v1.3.0**, a monumental leap in sovereign kernel-level network privacy, anti-fingerprinting, and protocol sanitization for Linux systems.

This release expands the in-flight Deep Packet Inspection (DPI) engine from 50 to **1,338+ security tool signatures** with **compile-time XOR-0x7A obfuscation**, resolves all 7 dual-engine audited kernel vulnerabilities, introduces an automated physical network interface selector (`wraith interfaces`), embeds an early-boot systemd fail-closed installer (`install-daemon.sh`), and expands the test suite to **44/44 passing tests** across **52,846 total lines** with **zero compiler or clippy warnings**.

---

## 🛡️ 1. In-Flight L4/L7 DPI Sanitization Matrix (1,338+ Tools)
* **1,338+ Security & Pentest Tool Signatures**: Intercepts Layer-4/Layer-7 HTTP and TLS traffic in real time and automatically rewrites conspicuous tool user-agents, headers, and metadata across 10 major offensive categories:
  * **Vulnerability Scanners (230+)**: `sqlmap`, `nuclei`, `httpx`, `Ghauri`, `Commix`, `dalfox`, `Nikto`, `OpenVAS`, `Nessus`, `Acunetix`, etc.
  * **Web Fuzzers & Crawlers (210+)**: `ffuf`, `gobuster`, `dirsearch`, `feroxbuster`, `Wfuzz`, `Kiterunner`, `Katana`, `Arjun`, etc.
  * **OSINT & Subdomain Recon (180+)**: `theHarvester`, `Amass`, `Subfinder`, `Assetfinder`, `Recon-ng`, `DNSRecon`, `Spiderfoot`, etc.
  * **Security Frameworks & Post-Exploitation (150+)**: `Metasploit`, `Cobalt Strike`, `Sliver C2`, `Havoc C2`, `Mythic`, `Empire`, `Brute Ratel C4`, etc.
  * **Active Directory & Identity Auditing (170+)**: `BloodHound`, `SharpHound`, `CrackMapExec`, `NetExec`, `Impacket`, `Responder`, `Evil-WinRM`, `Mimikatz`, `Certipy`, etc.
  * **Network & Port Scanners (130+)**: `Nmap (NSE)`, `masscan`, `RustScan`, `ZMap`, `Naabu`, `Hping3`, etc.
  * **Credential Testing (110+)**: `Hydra`, `Medusa`, `Ncrack`, `Patator`, `Hashcat`, `John The Ripper`, etc.
  * **Interception Proxies (95+)**: `BurpSuite`, `OWASP ZAP`, `Caido`, `mitmproxy`, `Bettercap`, `Wireshark`, etc.
  * **Reverse Engineering Tools (85+)**: `Ghidra`, `IDA Pro`, `Radare2`, `Cutter`, `Angr`, `Binary Ninja`, `Frida`, etc.
  * **HTTP Scripting Libraries (120+)**: `python-requests`, `urllib3`, `aiohttp`, `Go-http-client`, `curl`, `Wget`, `axios`, `Apache-HttpClient`, etc.
* **Authentic Modern Browser Pool**: Signatures are deterministically rewritten into modern desktop browser pools (`Chrome 131`, `Firefox 132`, `Safari 18`) without mid-session header flapping.

---

## 🔒 2. Compile-Time XOR-0x7A EDR & Antivirus Heuristic Avoidance
* **Zero Plaintext Signatures in `.rodata`**: All 1,338+ tool identifiers are stored as compile-time byte arrays encrypted with key `0x7A`.
* **Elimination of False-Positive Detections**: Completely prevents antivirus engines (Windows Defender `OS Error 225`, ClamAV, CrowdStrike, SentinelOne) from flagging the binary as a HackTool or Riskware simply due to literal tool names in `.rodata`.
* **Lock-Free Thread-Safe Decryption**: Initialized once on demand via `std::sync::OnceLock<Vec<String>>` for zero heap fragmentation and sub-microsecond in-flight packet lookup.

---

## 🖧 3. Hardware Network Interface Selector (`wraith interfaces`)
* **Physical NIC Auto-Discovery**: Automatically enumerates physical Ethernet and Wi-Fi adapters via Linux `/sys/class/net`, discarding virtual tunnels, loopback, and inactive links.
* **Automatic Fallback Routing**: If the primary interface drops, Wraith autonomously rebinds routing to secondary active physical uplinks without exposing clearnet leaks.
* **Interactive Terminal TUI**: Run `sudo wraith interfaces` to launch a full-screen interactive selector with real-time MAC, IP, state, and carrier speed display.

---

## ⚙️ 4. Systemd Early-Boot Fail-Closed Daemon (`install-daemon.sh`)
* **Zero Clearnet Leak at Boot**: Hooks into systemd `network-pre.target` to establish Netfilter routing and KillSwitch barriers before root login, NetworkManager, or background daemons initialize.
* **Interactive 6-Step Wizard**: Easily configure operational profiles (`stealth`, `speed`, `research`), DoH resolver, Tor bridges, and early-boot preferences.
* **Full CLI Non-Interactive Automation**: Deploy in CI/CD or headless environments with `sudo ./install-daemon.sh --non-interactive --boot-mode early --profile stealth`.

---

## 🛡️ 5. Dual-Engine Security Hardening (Audited & Remediated)
* **VULN-01 (RamFS Vault Directory Permissions & Path Traversal)**: `0o700` mode lock on vault path, strict traversal sanitization (`..`, `/`, `\`, `\0`), and `libc::O_NOFOLLOW` open flags.
* **VULN-02 (Cryptographic Shredder Symlink Hijacking)**: `fs::symlink_metadata()` check safely unlinks symlinks without overwriting or following into target files; all write handles enforce `O_NOFOLLOW`.
* **VULN-03 (Netlink NlMsgErr Struct Offset Alignment)**: Recalibrated Netlink error payload offset to 16 bytes (past outer `NlMsgHdr`) in both ACK and dump request loops.
* **VULN-04 (Honeypot Loopback Isolation & Protected PID Immunity)**: Restricted peer process inspection strictly to loopback IP addresses (`is_loopback()`); added inviolable immunity for PID 0, PID 1, and the Wraith process.
* **VULN-05 (State Persistence File Permission Lockdown)**: Enforced Unix `0o600` permissions on temporary and permanent state files.
* **VULN-06 (Network Namespace TCP TransPort Redirection)**: Added `iptables -t nat -A PREROUTING -p tcp --syn -j REDIRECT --to-ports 9040` and `FORWARD` rules in `create_namespace()`, with clean teardown in `destroy_namespace()`.
* **VULN-07 (CLI Argument Injection in Wire Transports)**: Validated HTTPS URL schemes and injected POSIX `"--"` argument delimiters before URLs in `curl` execution paths.

---

## 🌐 6. RFC 8484 DoH & Tor Moat Protocol
* **Sovereign DNS-over-HTTPS (`wraith doh`)**: Native RFC 8484 wire-format query generation with Quad9, Cloudflare, Mullvad, and AdGuard presets, plus interactive TUI.
* **Tor Moat Bridge Discovery (`wraith bridge`)**: Automated BridgeDB retrieval via domain-fronted Moat JSON API and built-in CAPTCHA solving protocol.

---

## 📊 Codebase Metrics & Test Verification
* **Total Lines:** **52,846 lines** (49,652 lines of code across 473 files).
* **Pure Rust LOC:** **13,493 lines of pure safe Rust** across 61 files.
* **Test Suite:** **44/44 unit & integration tests passing (%100 PASS)**.
* **Linter & Static Analysis:** **0 errors, 0 warnings** in `cargo clippy --workspace`.
* **Internationalization:** **75 native locales** synchronized with zero missing keys.

---

## 📦 Production Installation

```bash
# Clone the repository
git clone https://github.com/ByGh00st/wraith.git
cd wraith

# Run the automated build & installation engine
chmod +x build.sh
sudo ./build.sh

# Deploy systemd early-boot daemon (Optional)
chmod +x install-daemon.sh
sudo ./install-daemon.sh

# Launch Wraith with Full 16-Layer Security & Stealth Profile
sudo wraith -s -Fs -p stealth
```
