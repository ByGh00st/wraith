# Wraith v1.3.0 — Network Interface Selection & Kernel Hardening

Wraith v1.3.0 introduced network interface selection, kernel hardening, and Tor connectivity features for Linux systems.

This release introduced an automated physical network interface selector (`wraith interfaces`), an early-boot systemd installer (`install-daemon.sh`), and kernel hardening updates. The notes below have been revised to describe supported behavior without implying browser impersonation or endpoint concealment.

---

## 1. Historical HTTP request handling

The historical implementation normalized selected cleartext HTTP request headers. It did not inspect or rewrite encrypted HTTPS payloads.

## 2. Hardware Network Interface Selector (`wraith interfaces`)
* **Physical NIC Auto-Discovery**: Automatically enumerates physical Ethernet and Wi-Fi adapters via Linux `/sys/class/net`, discarding virtual tunnels, loopback, and inactive links.
* **Automatic Fallback Routing**: If the primary interface drops, Wraith autonomously rebinds routing to secondary active physical uplinks without exposing clearnet leaks.
* **Interactive Terminal TUI**: Run `sudo wraith interfaces` to launch a full-screen interactive selector with real-time MAC, IP, state, and carrier speed display.

---

## 3. Systemd Early-Boot Fail-Closed Daemon (`install-daemon.sh`)
* **Zero Clearnet Leak at Boot**: Hooks into systemd `network-pre.target` to establish Netfilter routing and KillSwitch barriers before root login, NetworkManager, or background daemons initialize.
* **Interactive 6-Step Wizard**: Configure routing profiles, DoH resolver, Tor bridges, and early-boot preferences.
* **Full CLI Non-Interactive Automation**: Deploy in CI/CD or headless environments with `sudo ./install-daemon.sh --non-interactive --boot-mode early --profile stealth`.

---

## 4. Kernel and application hardening (Audited & Remediated)
* **VULN-01 (RamFS Vault Directory Permissions & Path Traversal)**: `0o700` mode lock on vault path, strict traversal sanitization (`..`, `/`, `\`, `\0`), and `libc::O_NOFOLLOW` open flags.
* **VULN-02 (Cryptographic Shredder Symlink Hijacking)**: `fs::symlink_metadata()` check safely unlinks symlinks without overwriting or following into target files; all write handles enforce `O_NOFOLLOW`.
* **VULN-03 (Netlink NlMsgErr Struct Offset Alignment)**: Recalibrated Netlink error payload offset to 16 bytes (past outer `NlMsgHdr`) in both ACK and dump request loops.
* **VULN-04 (Honeypot Loopback Isolation & Protected PID Immunity)**: Restricted peer process inspection strictly to loopback IP addresses (`is_loopback()`); added inviolable immunity for PID 0, PID 1, and the Wraith process.
* **VULN-05 (State Persistence File Permission Lockdown)**: Enforced Unix `0o600` permissions on temporary and permanent state files.
* **VULN-06 (Network Namespace TCP TransPort Redirection)**: Added `iptables -t nat -A PREROUTING -p tcp --syn -j REDIRECT --to-ports 9040` and `FORWARD` rules in `create_namespace()`, with clean teardown in `destroy_namespace()`.
* **VULN-07 (CLI Argument Injection in Wire Transports)**: Validated HTTPS URL schemes and injected POSIX `"--"` argument delimiters before URLs in `curl` execution paths.

---

## 5. RFC 8484 DoH and Tor bridge support
* **Sovereign DNS-over-HTTPS (`wraith doh`)**: Native RFC 8484 wire-format query generation with Quad9, Cloudflare, Mullvad, and AdGuard presets, plus interactive TUI.
* **Tor Moat Bridge Discovery (`wraith bridge`)**: Automated BridgeDB retrieval via domain-fronted Moat JSON API and built-in CAPTCHA solving protocol.

---

## 6. Historical validation metrics
* **Total Lines:** **52,846 lines** (49,652 lines of code across 473 files).
* **Pure Rust LOC:** **13,493 lines of pure safe Rust** across 61 files.
* **Test Suite:** **44/44 unit & integration tests passing (%100 PASS)**.
* **Linter & Static Analysis:** **0 errors, 0 warnings** in `cargo clippy --workspace`.
* **Internationalization:** **17 native locales** synchronized with zero missing keys.

---

## 7. Installation

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

# Launch Wraith with the strict network profile
sudo wraith -s -Fs -p stealth
```
