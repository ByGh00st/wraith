#!/usr/bin/env bash
# ==============================================================================
# SCENARIO 1: Session Initiation & Netfilter Routing Audit
# ==============================================================================
set -euo pipefail

echo "[*] [Scenario 1] Launching Wraith session on veth-ns..."
wraith --start -I veth-ns

echo "[*] [Scenario 1] Inspecting IPv4 Netfilter NAT table..."
NAT_RULES=$(iptables -t nat -L -n)
if ! echo "$NAT_RULES" | grep -q "9040"; then
    echo "[!] FAILED: Tor TransPort redirect (9040) not present in iptables NAT table." >&2
    echo "$NAT_RULES" >&2
    exit 1
fi
echo "[+] Tor TransPort redirect verified."

if ! echo "$NAT_RULES" | grep -q "5354"; then
    echo "[!] FAILED: DNS redirect (5354) not present in iptables NAT table." >&2
    echo "$NAT_RULES" >&2
    exit 1
fi
echo "[+] DNS redirect verified."

echo "[*] [Scenario 1] Inspecting IPv6 Netfilter filtering policy..."
IP6_RULES=$(ip6tables -L -n)
if ! echo "$IP6_RULES" | grep -q "DROP"; then
    echo "[!] FAILED: IPv6 DROP policy not enforced." >&2
    echo "$IP6_RULES" >&2
    exit 1
fi
echo "[+] IPv6 leak prevention verified."

# --------------------------------------------------------------------------
# Wait for Tor daemon bootstrap & circuit readiness before subsequent tests.
# wraith --start returns before bootstrap completes in daemon mode — DNS
# proxy and SOCKS only become available after Tor has a working circuit.
# --------------------------------------------------------------------------
MAX_BOOT=180
echo "[*] [Scenario 1] Waiting for Tor bootstrap & circuit readiness (max ${MAX_BOOT}s)..."
READY=false
for i in $(seq 1 "$MAX_BOOT"); do
    RESP=$(curl --socks5-hostname 127.0.0.1:9050 --max-time 8 --silent \
           https://check.torproject.org/api/ip 2>/dev/null || true)
    if echo "$RESP" | grep -q '"IsTor"'; then
        READY=true
        echo "[+] Tor circuit established at ${i}s. Daemon fully operational."
        break
    fi
    if (( i % 15 == 0 )); then
        TOR_PID=$(pgrep -x tor 2>/dev/null || echo "none")
        echo "[-] Bootstrap poll: ${i}s elapsed (tor pid: $TOR_PID)"
    fi
    sleep 1
done

if [[ "$READY" != "true" ]]; then
    echo "[!] FAILED: Tor daemon did not establish a circuit within ${MAX_BOOT}s." >&2
    TOR_PID=$(pgrep -x tor 2>/dev/null || true)
    if [[ -z "$TOR_PID" ]]; then
        echo "[!] Tor daemon is not running." >&2
    else
        echo "[*] Tor PID: $TOR_PID (still bootstrapping)" >&2
        cat /var/log/wraith/daemon.log 2>/dev/null | tail -30 >&2 || true
    fi
    exit 1
fi

echo "[+] [Scenario 1] Netfilter table routing audit PASSED."
