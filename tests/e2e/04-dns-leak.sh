#!/usr/bin/env bash
# ==============================================================================
# SCENARIO 4: Wire-Level DNS Leak Audit (Zero Clearnet UDP/53 Egress)
# ==============================================================================
set -euo pipefail

PCAP_FILE="/tmp/dns_leak_audit.pcap"
rm -f "$PCAP_FILE"

echo "[*] [Scenario 4] Starting packet capture on veth-ns for external UDP 53 egress..."
# Listen on interface for any UDP 53 not directed to loopback
tcpdump -i veth-ns -nn -s 0 -w "$PCAP_FILE" 'udp port 53 and not dst host 127.0.0.1' 2>/dev/null &
TCPDUMP_PID=$!
sleep 1

echo "[*] [Scenario 4] Triggering intensive DNS lookups across distinct domains..."
for domain in duckduckgo.com eff.org torproject.org wikipedia.org github.com; do
    dig +time=2 +tries=1 "$domain" A >/dev/null 2>&1 || true
done

sleep 2
# Terminate packet capture
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

# Analyze captured packets
PACKET_COUNT=$(tcpdump -r "$PCAP_FILE" 2>/dev/null | wc -l || true)
rm -f "$PCAP_FILE"

echo "[*] Clearnet DNS packets intercepted: $PACKET_COUNT"
if [[ "$PACKET_COUNT" -gt 0 ]]; then
    echo "[!] FAILED: Critical DNS leak detected! $PACKET_COUNT packet(s) escaped via clearnet." >&2
    exit 1
fi

echo "[+] [Scenario 4] Zero clearnet DNS leak confirmed. Audit PASSED."
