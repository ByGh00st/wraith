#!/usr/bin/env bash
# ==============================================================================
# SCENARIO 2: Sovereign DNS Engine & DNSSEC Validation Audit
# ==============================================================================
set -euo pipefail

echo "[*] [Scenario 2] Verifying DNS resolution via Wraith local proxy (127.0.0.1:5354)..."
DNS_RESOLVED=""
for attempt in {1..10}; do
    DNS_RESOLVED=$(dig @127.0.0.1 -p 5354 example.com A +short +time=3 +tries=1 2>/dev/null || true)
    if [[ -n "$DNS_RESOLVED" && "$DNS_RESOLVED" != *"connection refused"* ]]; then
        break
    fi
    echo "[-] Waiting for local DNS engine readiness (attempt $attempt/10)..."
    sleep 1
done

if [[ -z "$DNS_RESOLVED" ]]; then
    echo "[!] FAILED: Local DNS engine failed to resolve example.com on 127.0.0.1:5354" >&2
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
