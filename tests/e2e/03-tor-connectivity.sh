#!/usr/bin/env bash
# ==============================================================================
# SCENARIO 3: Tor Circuit Readiness & TCP Egress Anonymity Audit
# ==============================================================================
set -euo pipefail

echo "[*] [Scenario 3] Polling Tor bootstrap readiness (max 45s)..."
BOOTSTRAPPED=false
for i in {1..45}; do
    # Check if Tor circuit is ready by querying check.torproject.org
    TOR_RESPONSE=$(curl --max-time 5 --silent https://check.torproject.org/api/ip 2>/dev/null || true)
    if echo "$TOR_RESPONSE" | grep -q '"IsTor"'; then
        BOOTSTRAPPED=true
        echo "[+] Tor circuit established at attempt $i."
        break
    fi
    sleep 1
done

if [[ "$BOOTSTRAPPED" != "true" ]]; then
    # Fallback to HTTP endpoint if TLS had transient handshake delay
    TOR_RESPONSE=$(curl --max-time 10 --silent http://check.torproject.org/api/ip 2>/dev/null || true)
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
