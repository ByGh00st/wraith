#!/usr/bin/env bash
# ==============================================================================
# SCENARIO 3: Tor Circuit Readiness & TCP Egress Anonymity Audit
# ==============================================================================
set -euo pipefail

MAX_BOOTSTRAP_WAIT=120
MAX_CIRCUIT_WAIT=60

# --------------------------------------------------------------------------
# Phase 1: Wait for Tor bootstrap to complete (control port / log polling)
# --------------------------------------------------------------------------
echo "[*] [Scenario 3] Waiting for Tor daemon bootstrap (max ${MAX_BOOTSTRAP_WAIT}s)..."
BOOTSTRAPPED=false

for i in $(seq 1 "$MAX_BOOTSTRAP_WAIT"); do
    # Method 1: Check Tor control port for bootstrap status
    AUTH_COOKIE=""
    if [[ -f /run/wraith-tor/control.authcookie ]]; then
        AUTH_COOKIE=$(xxd -p -c 64 /run/wraith-tor/control.authcookie 2>/dev/null || true)
    fi
    if [[ -n "$AUTH_COOKIE" ]]; then
        BOOTSTRAP_STATUS=$(printf 'AUTHENTICATE %s\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n' "$AUTH_COOKIE" | nc -w 2 127.0.0.1 9051 2>/dev/null || true)
    else
        BOOTSTRAP_STATUS=$(printf 'AUTHENTICATE ""\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n' | nc -w 2 127.0.0.1 9051 2>/dev/null || true)
    fi

    if echo "$BOOTSTRAP_STATUS" | grep -q "PROGRESS=100"; then
        BOOTSTRAPPED=true
        echo "[+] Tor bootstrap reached 100% at attempt $i (control port)."
        break
    fi

    # Method 2: Check if Tor SOCKS port is accepting connections
    if [[ "$i" -gt 30 ]]; then
        SOCKS_CHECK=$(curl --socks5-hostname 127.0.0.1:9050 --max-time 5 --silent https://check.torproject.org/api/ip 2>/dev/null || true)
        if echo "$SOCKS_CHECK" | grep -q '"IsTor"'; then
            BOOTSTRAPPED=true
            echo "[+] Tor SOCKS proxy responsive at attempt $i."
            TOR_RESPONSE="$SOCKS_CHECK"
            break
        fi
    fi

    # Method 3: Check Tor log for bootstrap completion
    for log_path in /var/log/tor/log /var/log/tor/notices.log /var/log/wraith/tor.log; do
        if [[ -f "$log_path" ]] && grep -q "Bootstrapped 100%" "$log_path" 2>/dev/null; then
            BOOTSTRAPPED=true
            echo "[+] Tor bootstrap reached 100% at attempt $i (log: $log_path)."
            break 2
        fi
    done

    # Progress indicator every 15 seconds
    if (( i % 15 == 0 )); then
        PROGRESS=$(echo "$BOOTSTRAP_STATUS" | grep -oP 'PROGRESS=\K[0-9]+' 2>/dev/null || echo "?")
        echo "[-] Bootstrap progress: ${PROGRESS}% (${i}s elapsed)..."
    fi

    sleep 1
done

if [[ "$BOOTSTRAPPED" != "true" ]]; then
    echo "[!] Tor bootstrap did not reach 100% within ${MAX_BOOTSTRAP_WAIT}s." >&2
    echo "[*] Checking if Tor daemon is running..."
    TOR_PID=$(pgrep -x tor || true)
    if [[ -z "$TOR_PID" ]]; then
        echo "[!] FAILED: Tor daemon not running at all." >&2
    else
        echo "[*] Tor PID: $TOR_PID (still bootstrapping)"
    fi
    exit 1
fi

# --------------------------------------------------------------------------
# Phase 2: Verify Tor circuit establishment & egress anonymity
# --------------------------------------------------------------------------
echo "[*] [Scenario 3] Polling Tor egress verification (max ${MAX_CIRCUIT_WAIT}s)..."

if [[ -z "${TOR_RESPONSE:-}" ]]; then
    TOR_RESPONSE=""
    for j in $(seq 1 "$MAX_CIRCUIT_WAIT"); do
        # Try SOCKS proxy first (most reliable — proves traffic actually routes through Tor)
        TOR_RESPONSE=$(curl --socks5-hostname 127.0.0.1:9050 --max-time 10 --silent https://check.torproject.org/api/ip 2>/dev/null || true)
        if echo "$TOR_RESPONSE" | grep -q '"IsTor"'; then
            echo "[+] Tor circuit verified at attempt $j (SOCKS)."
            break
        fi

        # Fallback: direct curl (traffic should be transparently redirected via TransPort)
        TOR_RESPONSE=$(curl --max-time 10 --silent https://check.torproject.org/api/ip 2>/dev/null || true)
        if echo "$TOR_RESPONSE" | grep -q '"IsTor"'; then
            echo "[+] Tor circuit verified at attempt $j (TransPort)."
            break
        fi

        if (( j % 10 == 0 )); then
            echo "[-] Circuit readiness poll: ${j}s elapsed..."
        fi
        sleep 1
    done
fi

echo "[*] [Scenario 3] Parsing Tor verification payload..."
echo "Payload: $TOR_RESPONSE"

IS_TOR=$(echo "$TOR_RESPONSE" | jq -r '.IsTor' 2>/dev/null || true)
EGRESS_IP=$(echo "$TOR_RESPONSE" | jq -r '.IP' 2>/dev/null || true)

if [[ "$IS_TOR" != "true" ]]; then
    echo "[!] FAILED: Egress traffic was not recognized by Tor Project API as Tor exit." >&2
    echo "Raw response: $TOR_RESPONSE" >&2
    exit 1
fi

echo "[+] Verified: IsTor = true. Egress Node IP: $EGRESS_IP"
if [[ "$EGRESS_IP" == "10.200.1."* || "$EGRESS_IP" == "127.0.0.1" ]]; then
    echo "[!] FAILED: Egress IP leaked local address: $EGRESS_IP" >&2
    exit 1
fi

echo "[+] [Scenario 3] Tor TCP egress anonymity audit PASSED."
