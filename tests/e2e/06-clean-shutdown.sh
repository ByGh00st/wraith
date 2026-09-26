#!/usr/bin/env bash
# ==============================================================================
# SCENARIO 6: Graceful Teardown & Netfilter State Rollback Audit
# ==============================================================================
set -euo pipefail

echo "[*] [Scenario 6] Issuing graceful teardown (wraith --stop)..."
wraith --stop

echo "[*] [Scenario 6] Verifying netfilter rollback (checking for lingering TransPort 9040 rules)..."
if iptables -t nat -L -n | grep -q "9040"; then
    echo "[!] FAILED: TransPort 9040 rule lingers in NAT table after --stop." >&2
    exit 1
fi
echo "[+] TransPort NAT redirect cleanly removed."

echo "[*] [Scenario 6] Verifying IPv6 filter policy restoration..."
IP6_POLICY=$(ip6tables -L INPUT -n | head -n 1)
if ! echo "$IP6_POLICY" | grep -q "ACCEPT"; then
    echo "[!] WARNING / FAILED: IPv6 INPUT policy not restored to ACCEPT: $IP6_POLICY" >&2
    exit 1
fi
echo "[+] IPv6 policy successfully restored to ACCEPT."

echo "[*] [Scenario 6] Verifying /etc/resolv.conf state and attributes..."
if command -v lsattr >/dev/null 2>&1; then
    if lsattr /etc/resolv.conf 2>/dev/null | grep -q "i"; then
        echo "[!] FAILED: /etc/resolv.conf remains immutably locked (+i) after shutdown." >&2
        exit 1
    fi
    echo "[+] Immutable attribute successfully removed from /etc/resolv.conf."
fi

echo "[*] [Scenario 6] Verifying session state file destruction..."
if [[ -f /run/wraith.state || -f /var/run/wraith.state ]]; then
    echo "[!] FAILED: Session state file not deleted after --stop." >&2
    exit 1
fi
echo "[+] Session state file cleanly wiped."

echo "[+] [Scenario 6] Clean shutdown and state rollback audit PASSED."
