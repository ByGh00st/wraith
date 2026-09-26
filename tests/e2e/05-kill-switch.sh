#!/usr/bin/env bash
# ==============================================================================
# SCENARIO 5: Tor Daemon Catastrophic Failure & Fail-Closed Kill-Switch Audit
# ==============================================================================
set -euo pipefail

echo "[*] [Scenario 5] Locating active Tor daemon process in namespace..."
TOR_PID=$(pgrep -x tor || true)
if [[ -z "$TOR_PID" ]]; then
    echo "[!] Tor daemon not found running prior to kill-switch test." >&2
    exit 1
fi

echo "[*] [Scenario 5] Injecting SIGKILL (kill -9) into Tor daemon (PID: $TOR_PID)..."
kill -9 "$TOR_PID"
sleep 2

echo "[*] [Scenario 5] Verifying fail-closed firewall state (attempting clearnet HTTP request)..."
# Request MUST fail. If it succeeds, traffic leaked onto clearnet without Tor!
LEAKED=false
if curl --max-time 5 --silent http://example.com >/dev/null 2>&1; then
    LEAKED=true
fi

if [[ "$LEAKED" == "true" ]]; then
    echo "[!] CRITICAL FAILURE: Fail-closed kill switch breached! Clearnet traffic allowed after Tor death!" >&2
    exit 1
fi
echo "[+] Clearnet traffic successfully blocked after daemon termination."

echo "[*] [Scenario 5] Confirming Netfilter rules remained locked..."
if ! iptables -L -n | grep -qE "DROP|REJECT"; then
    echo "[!] FAILED: Firewall rules were flushed unexpectedly upon Tor crash." >&2
    exit 1
fi

echo "[+] [Scenario 5] Fail-closed kill-switch audit PASSED."
