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

echo "[+] [Scenario 1] Netfilter table routing audit PASSED."
