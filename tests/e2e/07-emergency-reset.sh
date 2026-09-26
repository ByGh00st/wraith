#!/usr/bin/env bash
# ==============================================================================
# SCENARIO 7: Emergency Recovery Script (reset.sh) Verification
# ==============================================================================
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

echo "[*] [Scenario 7] Launching fresh session for emergency recovery test..."
wraith --start -I veth-ns
sleep 2

echo "[*] [Scenario 7] Invoking emergency reset.sh directly..."
bash "$SCRIPT_DIR/reset.sh"

echo "[*] [Scenario 7] Verifying firewall and state rollback via emergency reset..."
if iptables -t nat -L -n | grep -q "9040"; then
    echo "[!] FAILED: NAT 9040 persists after emergency reset." >&2
    exit 1
fi

if [[ -f /run/wraith.state || -f /var/run/wraith.state ]]; then
    echo "[!] FAILED: State file remains after emergency reset." >&2
    exit 1
fi

echo "[+] [Scenario 7] Emergency recovery script successfully reset environment. PASSED."
