# TROUBLESHOOTING & RECOVERY PROCEDURES

Operational remediation guide for initialization failures, port collisions, Tor bootstrap delays, and emergency network state restoration.

---

## 1. Emergency Host Network Restoration

If an unexpected system crash, power loss, or forced reboot occurs while Wraith is active, netfilter rules may remain in a fail-closed state (`OUTPUT DROP`).

### Primary Recovery: Native Command
```bash
sudo wraith -x
```
*Parses existing state journals in `/var/run/wraith/` and executes clean deconfiguration of firewall rules, sysctl flags, and DNS settings.*

### Secondary Recovery: Standalone Reset Scripts
If the Wraith binary was deleted or cannot execute, execute the standalone POSIX recovery scripts:
```bash
sudo ./reset.sh
# or
sudo ./reset_network.sh
```

**Actions Executed by Recovery Scripts:**
1. **Firewall Reset:** Flushes all custom and standard rules across `filter`, `nat`, and `mangle` tables in both `iptables` and `ip6tables`.
2. **Policy Reset:** Restores default policies to `ACCEPT` on `INPUT`, `FORWARD`, and `OUTPUT` chains.
3. **DNS Restoration:** Clears the immutable flag (`chattr -i /etc/resolv.conf`), restores nameservers from backup (`/etc/resolv.conf.wraith.bak`), or populates trusted fallbacks (`9.9.9.9`, `1.1.1.1`).
4. **Process Cleanup:** Terminates orphaned Tor or Wraith worker processes bound to ports 9040, 9050, 9051, 5354, or 9055.
5. **Interface State:** Verifies that physical network interfaces remain in an `UP` operational state.

---

## 2. Common Diagnostic Conditions & Solutions

### Condition A: "Wraith daemon is currently running via systemd"
* **Diagnosis:** The background systemd service (`wraith.service`) was enabled and currently holds the exclusive process lock.
* **Remediation:** Stop the service before invoking the interactive CLI:
  ```bash
  sudo systemctl stop wraith
  # or terminate session via CLI:
  sudo wraith -x
  ```

### Condition B: "Address already in use: Port 9050 / 9051 / 5354 / 9055"
* **Diagnosis:** An external Tor instance, local DNS cache (such as `systemd-resolved` or `dnsmasq`), or leftover process is bound to one of Wraith's designated service ports.
* **Remediation:** Inspect and terminate the competing process:
  ```bash
  # Check active port bindings:
  sudo ss -tulpn | grep -E ':(9040|9050|9051|5354|9055)'

  # Stop standard distribution Tor daemons:
  sudo systemctl stop tor
  sudo systemctl stop tor@default
  ```

### Condition C: "Tor bootstrap stalled at 5% / 10% / 85%"
* **Diagnosis:** Direct access to Tor Directory Authorities is intercepted, filtered, or blocked by upstream network intermediaries (ISP / Deep Packet Inspection).
* **Remediation:** Configure censorship-resistant Pluggable Transports using the Bridge engine:
  ```bash
  # Query bridges via Moat API:
  wraith bridge moat --transport obfs4

  # Start session utilizing obfs4 bridges:
  sudo wraith -s --bridge --bridge-type obfs4
  ```

### Condition D: "ip6tables: Table does not exist" on Minimal Kernels
* **Diagnosis:** The operating system kernel is compiled without the optional `ip6table_nat` kernel module (common in lightweight virtualization containers or minimal cloud kernels).
* **Remediation:** In current versions of Wraith, `ip6tables -t nat` errors are classified as non-fatal warnings; the engine enforces IPv6 containment by setting default `DROP` policies in the `filter` table, maintaining complete leak prevention without requiring the NAT module.

### Condition E: "Operation not permitted on /etc/resolv.conf"
* **Diagnosis:** Another security utility has applied the immutable ext4/xfs file attribute (`chattr +i`).
* **Remediation:** Remove the immutable attribute and re-run session startup:
  ```bash
  sudo chattr -i /etc/resolv.conf
  sudo wraith -s
  ```
