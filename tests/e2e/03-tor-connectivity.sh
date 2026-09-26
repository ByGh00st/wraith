#!/usr/bin/env bash
# ==============================================================================
# SCENARIO 3: Tor Circuit Readiness & TCP Egress Anonymity Audit
# Tor bootstrap already verified by Scenario 1 — this validates anonymity.
# ==============================================================================
set -euo pipefail

echo "[*] [Scenario 3] Verifying TCP egress anonymity via Tor..."

# Tor circuit is already established (Scenario 1 confirmed via SOCKS probe).
# Now verify the egress IP is a real Tor exit node, not a local address.
TOR_RESPONSE=""
for attempt in $(seq 1 30); do
    TOR_RESPONSE=$(curl --socks5-hostname 127.0.0.1:9050 \
                        --max-time 10 --silent \
                        https://check.torproject.org/api/ip 2>/dev/null || true)
    if echo "$TOR_RESPONSE" | grep -q '"IsTor"'; then
        break
    fi

    # Fallback: TransPort (iptables transparent redirect)
    TOR_RESPONSE=$(curl --max-time 10 --silent \
                        https://check.torproject.org/api/ip 2>/dev/null || true)
    if echo "$TOR_RESPONSE" | grep -q '"IsTor"'; then
        break
    fi
    sleep 1
done

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
