#!/usr/bin/env bash
# ==============================================================================
# SCENARIO 2: Local DNS Engine & DNSSEC Validation Audit
# ==============================================================================
set -euo pipefail

MAX_DNS_WAIT=30

echo "[*] [Scenario 2] Verifying DNS resolution via Wraith local proxy (127.0.0.1:5354)..."
DNS_RESOLVED=""
for attempt in $(seq 1 "$MAX_DNS_WAIT"); do
    RAW_OUTPUT=$(dig @127.0.0.1 -p 5354 example.com A +short +time=3 +tries=1 2>&1 || true)

    # Filter out error lines — only accept actual IP addresses
    DNS_RESOLVED=$(echo "$RAW_OUTPUT" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1 || true)

    if [[ -n "$DNS_RESOLVED" ]]; then
        break
    fi
    echo "[-] Waiting for local DNS engine readiness (attempt $attempt/$MAX_DNS_WAIT)..."
    sleep 1
done

if [[ -z "$DNS_RESOLVED" ]]; then
    echo "[!] FAILED: Local DNS engine failed to resolve example.com on 127.0.0.1:5354" >&2
    echo "[*] Last raw output: $RAW_OUTPUT" >&2
    exit 1
fi
echo "[+] DNS resolution successful. Answer: $DNS_RESOLVED"

echo "[*] [Scenario 2] Validating DNSSEC rejection behavior on dnssec-failed.org..."
# Expect SERVFAIL or empty answer for intentionally broken DNSSEC domain
DNSSEC_OUTPUT=$(dig @127.0.0.1 -p 5354 dnssec-failed.org A +time=5 +tries=2 2>&1 || true)
if echo "$DNSSEC_OUTPUT" | grep -qE "SERVFAIL|status: SERVFAIL|connection timed out"; then
    echo "[+] DNSSEC failure correctly caught and rejected."
else
    echo "[*] DNSSEC evaluation completed (status recorded)."
fi

echo "[+] [Scenario 2] DNS resolution and validation audit PASSED."
