#!/usr/bin/env bash
# Exercise the actual CLI reset, including no-state, failure and retry paths.
set -euo pipefail
AUDIT_DIR=$(mktemp -d /tmp/wraith-reset-XXXXXX)
trap 'rm -rf "$AUDIT_DIR"' EXIT
STATE=/run/wraith.state
[[ ! -e "$STATE" ]] || { echo "Previous scenario left a session" >&2; exit 1; }

# These belong to the test's administrator, never to Wraith. Their names would
# have been deleted by the old reset implementation without ownership checks.
ip link add wg0 type dummy
ip link add veth-host type dummy
ip link set wg0 up
ip link set veth-host up
ip route add blackhole 192.0.2.0/24 table 100
iptables -N USER_RESET_SENTINEL
iptables -A USER_RESET_SENTINEL -j RETURN
iptables -A OUTPUT -m comment --comment user-reset-sentinel -j USER_RESET_SENTINEL
ip6tables -N USER_RESET_SENTINEL
ip6tables -A USER_RESET_SENTINEL -j RETURN
ip6tables -A OUTPUT -m comment --comment user-reset-sentinel -j USER_RESET_SENTINEL
iptables -P FORWARD DROP
ip6tables -P FORWARD DROP

snapshot() {
    iptables-save | sed -E '/^#/d; s/\[[0-9]+:[0-9]+\]/[0:0]/g' >"$AUDIT_DIR/$1.v4"
    ip6tables-save | sed -E '/^#/d; s/\[[0-9]+:[0-9]+\]/[0:0]/g' >"$AUDIT_DIR/$1.v6"
    ip -j link show wg0 >"$AUDIT_DIR/$1.wg0"
    ip -j link show veth-host >"$AUDIT_DIR/$1.veth"
    ip route show table 100 >"$AUDIT_DIR/$1.routes"
    cat /etc/resolv.conf >"$AUDIT_DIR/$1.dns"
    readlink /etc/resolv.conf >"$AUDIT_DIR/$1.dns-link" || [[ ! -L /etc/resolv.conf ]]
}
assert_preserved() {
    snapshot actual
    for item in v4 v6 wg0 veth routes dns dns-link; do
        diff -u "$AUDIT_DIR/before.$item" "$AUDIT_DIR/actual.$item"
    done
}
snapshot before

# Every compatibility target must be a no-op with no journal/owned leases.
echo "[*] [Scenario 7] Checking reset aliases without a session..."
wraith -rN
wraith --reset
wraith network reset
for target in network net all dns firewall; do
    wraith reset "$target"
    assert_preserved
done

# Invalid recovery data must not trigger a best-effort global network reset.
printf 'invalid-recovery-json\n' >"$STATE"
cp "$STATE" "$AUDIT_DIR/corrupt-state"
if wraith reset >"$AUDIT_DIR/corrupt.log" 2>&1; then
    echo "FAIL: corrupt recovery record was accepted" >&2
    exit 1
fi
cmp "$STATE" "$AUDIT_DIR/corrupt-state"
assert_preserved
rm "$STATE" # Only the deliberately malformed test record created above.

echo "[*] [Scenario 7] Recovering an active session with the CLI..."
wraith --start -I veth-ns
wraith reset
[[ ! -e "$STATE" ]]
assert_preserved

echo "[*] [Scenario 7] Injecting a firewall restore failure after worker death..."
wraith --start -I veth-ns
WORKER_PID=$(jq -er '.pid | select(. > 1)' "$STATE")
kill -KILL "$WORKER_PID"
sleep 1
mkdir "$AUDIT_DIR/bin"
printf '#!/bin/sh\necho injected-restore-failure >&2\nexit 42\n' >"$AUDIT_DIR/bin/iptables-restore"
chmod 755 "$AUDIT_DIR/bin/iptables-restore"
if PATH="$AUDIT_DIR/bin:$PATH" wraith reset >"$AUDIT_DIR/failure.log" 2>&1; then
    cat "$AUDIT_DIR/failure.log" >&2
    echo "FAIL: reset reported success after a failed firewall restore" >&2
    exit 1
fi
grep -q 'injected-restore-failure' "$AUDIT_DIR/failure.log"
grep -q 'Cleanup incomplete' "$AUDIT_DIR/failure.log"
[[ -s "$STATE" ]]
# Errors must leave enough state to retry the exact saved firewall policy.
jq -e '.saved_rules != null and .state == "Cleanup"' "$STATE" >/dev/null
wraith reset firewall
[[ ! -e "$STATE" ]]
assert_preserved

# Repeated reset stays harmless after successful recovery.
wraith reset dns
assert_preserved
iptables -D OUTPUT -m comment --comment user-reset-sentinel -j USER_RESET_SENTINEL
iptables -F USER_RESET_SENTINEL
iptables -X USER_RESET_SENTINEL
ip6tables -D OUTPUT -m comment --comment user-reset-sentinel -j USER_RESET_SENTINEL
ip6tables -F USER_RESET_SENTINEL
ip6tables -X USER_RESET_SENTINEL
ip link del wg0
ip link del veth-host
ip route del blackhole 192.0.2.0/24 table 100
echo "[+] [Scenario 7] CLI reset preserves unrelated settings and propagates cleanup failures."
