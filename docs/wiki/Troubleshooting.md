# 🩺 TROUBLESHOOTING & RECOVERY GUIDE

This guide provides operational solutions for startup failures, port collisions, Tor bootstrap delays, and catastrophic network recovery.

---

## 🛠️ Emergency Network Restoration

If your network is unresponsive after an unexpected reboot, power outage, or hard freeze while Wraith was armed:

### Option 1: Native Stop Command
```bash
sudo wraith -x
```

### Option 2: Standalone Emergency Reset Script
If the binary was deleted or cannot execute:
```bash
sudo ./reset.sh
# or
sudo ./reset_network.sh
```

The reset scripts unconditionally:
1. Flush `iptables` and `ip6tables` (`filter`, `nat`, `mangle` tables).
2. Set default policies to `ACCEPT` (`INPUT`, `OUTPUT`, `FORWARD`).
3. Unlock `/etc/resolv.conf` (`chattr -i`), restore nameservers from backup (`.wraith.bak`), or inject public fallbacks (`9.9.9.9`, `1.1.1.1`).
4. Force-kill any lingering background Tor or Wraith worker processes.
5. Re-enable network interfaces.

---

## ⚠️ Common Issues & Solutions

### 1. "Wraith is already running as a systemd service"
**Cause:** The background daemon service was installed and is currently running via systemd.  
**Fix:**
```bash
sudo systemctl stop wraith
# or disarm via CLI:
sudo wraith -x
```

### 2. "Port 9050 / 9051 / 5353 already in use"
**Cause:** An existing system Tor daemon is binding to default ports.  
**Fix:**
```bash
sudo systemctl stop tor
sudo systemctl stop tor@default
sudo pkill -9 -f tor
sudo wraith -s
```

### 3. "Tor bootstrap stalled at 5% / 10% / 85%"
**Cause:** Upstream censorship or severe ISP packet inspection blocking direct Tor directory authority access.  
**Fix:** Use Tor Moat to discover unblocked Pluggable Transport bridges:
```bash
sudo wraith bridge --transport obfs4
# or with Snowflake:
sudo wraith bridge --transport snowflake
```

### 4. "IPv6 protection failed" on minimal VPS or container
**Cause:** Kernel lacks `ip6table_nat` module.  
**Fix:** Ensure you are running latest Wraith (`v1.3.0+`), which automatically treats `ip6tables -t nat` as non-fatal while preserving fail-closed `DROP` filter policies.
