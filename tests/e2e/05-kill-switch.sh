#!/usr/bin/env bash
# Tor failure must block numeric-IP TCP/UDP, with a live external fixture.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${WRAITH_EGRESS_ADDRESS:?Run through harness.sh}"
: "${WRAITH_EGRESS_PORT:?Run through harness.sh}"
: "${WRAITH_EGRESS_PID:?Run through harness.sh}"
AUDIT_DIR=$(mktemp -d /tmp/wraith-killswitch-XXXXXX)
CAPTURE_PID=""
cleanup() {
    if [[ -n "$CAPTURE_PID" ]]; then
        kill -INT "$CAPTURE_PID" 2>/dev/null || true
        wait "$CAPTURE_PID" 2>/dev/null || true
    fi
    rm -rf "$AUDIT_DIR"
}
trap cleanup EXIT

# Confirm both services are still responding from the fixture's network namespace.
# This cannot pass merely because DNS, Tor or the external Internet is unavailable.
check_fixture() {
    kill -0 "$WRAITH_EGRESS_PID"
    nsenter --net="/proc/$WRAITH_EGRESS_PID/ns/net" \
        python3 "$SCRIPT_DIR/egress-probe.py" reachable \
        --address "$WRAITH_EGRESS_ADDRESS" --port "$WRAITH_EGRESS_PORT"
}
check_fixture

TOR_PIDS=$(pgrep -x tor)
[[ -n "$TOR_PIDS" ]] || { echo "Tor missing before failure injection" >&2; exit 1; }
echo "[*] [Scenario 5] Killing Tor and checking numeric-IP egress..."
kill -KILL $TOR_PIDS
sleep 2

tcpdump -i veth-ns -nn -U -w "$AUDIT_DIR/egress.pcap" \
    "dst host $WRAITH_EGRESS_ADDRESS and dst port $WRAITH_EGRESS_PORT and (tcp or udp)" \
    2>"$AUDIT_DIR/capture.log" &
CAPTURE_PID=$!
for _ in $(seq 1 50); do
    grep -q 'listening on' "$AUDIT_DIR/capture.log" && break
    kill -0 "$CAPTURE_PID"
    sleep 0.1
done
grep -q 'listening on' "$AUDIT_DIR/capture.log"
python3 "$SCRIPT_DIR/egress-probe.py" blocked \
    --address "$WRAITH_EGRESS_ADDRESS" --port "$WRAITH_EGRESS_PORT"
sleep 1
kill -0 "$CAPTURE_PID"
kill -INT "$CAPTURE_PID"
wait "$CAPTURE_PID"
CAPTURE_PID=""
# Parsing errors must fail the test rather than becoming an empty packet count.
tcpdump -nn -r "$AUDIT_DIR/egress.pcap" >"$AUDIT_DIR/packets.txt"
if [[ -s "$AUDIT_DIR/packets.txt" ]]; then
    cat "$AUDIT_DIR/packets.txt" >&2
    echo "FAIL: direct TCP/UDP packets escaped after Tor failure" >&2
    exit 1
fi
check_fixture

echo "[+] [Scenario 5] Numeric-IP TCP/UDP blocked; zero matching egress packets."
