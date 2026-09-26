#!/usr/bin/env bash
# ==============================================================================
# NYX-PRIME // WRAITH E2E KERNEL SANDBOX HARNESS
# Isolated Linux Network Namespace (NetNS) Execution Engine
# Prevents CI Runner Severing by isolating iptables/Tor from host interface.
# ==============================================================================
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "[!] Root privilege required for network namespace harness." >&2; exit 1; }

NS_NAME="wraith-e2e"
VETH_HOST="veth-h"
VETH_NS="veth-ns"
HOST_IP="10.200.1.1"
NS_IP="10.200.1.2"
SUBNET="10.200.1.0/24"

cleanup() {
    echo "[*] Cleaning up network namespace harness ($NS_NAME)..."
    # Kill any processes remaining in namespace
    if ip netns list | grep -qw "$NS_NAME"; then
        ip netns pids "$NS_NAME" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    fi

    # Host NAT cleanup
    HOST_EGRESS=$(ip route show default 2>/dev/null | awk '/dev/ {print $5; exit}' || true)
    if [[ -n "$HOST_EGRESS" ]]; then
        iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$HOST_EGRESS" -j MASQUERADE 2>/dev/null || true
        iptables -D FORWARD -i "$VETH_HOST" -o "$HOST_EGRESS" -j ACCEPT 2>/dev/null || true
        iptables -D FORWARD -i "$HOST_EGRESS" -o "$VETH_HOST" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    fi

    # Interface & namespace teardown
    ip link delete "$VETH_HOST" 2>/dev/null || true
    ip netns delete "$NS_NAME" 2>/dev/null || true
    echo "[+] Harness cleanup complete."
}
trap cleanup EXIT

echo "[*] Initializing isolated Network Namespace ($NS_NAME)..."
ip netns add "$NS_NAME"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NS_NAME"

# Host-side configuration
ip addr add "$HOST_IP/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up

# Namespace-side configuration
ip netns exec "$NS_NAME" ip addr add "$NS_IP/24" dev "$VETH_NS"
ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
ip netns exec "$NS_NAME" ip link set lo up
ip netns exec "$NS_NAME" ip route add default via "$HOST_IP" dev "$VETH_NS"

# Enable IP forwarding and NAT on host
sysctl -w net.ipv4.ip_forward=1 >/dev/null
HOST_EGRESS=$(ip route show default | awk '/dev/ {print $5; exit}')
if [[ -z "$HOST_EGRESS" ]]; then
    echo "[!] Failed to detect default host egress interface." >&2
    exit 1
fi

iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$HOST_EGRESS" -j MASQUERADE
iptables -A FORWARD -i "$VETH_HOST" -o "$HOST_EGRESS" -j ACCEPT
iptables -A FORWARD -i "$HOST_EGRESS" -o "$VETH_HOST" -m state --state RELATED,ESTABLISHED -j ACCEPT

# Verify outbound ping from namespace to host gateway
if ! ip netns exec "$NS_NAME" ping -c 1 -W 2 "$HOST_IP" >/dev/null; then
    echo "[!] Namespace connectivity check failed (gateway unreachable)." >&2
    exit 1
fi
echo "[+] Network Namespace ($NS_NAME) online with verified gateway ($HOST_IP)."

# Execute targeted test scenario or all scenarios
if [[ $# -eq 0 ]]; then
    echo "[*] No scenario specified. Running full E2E test suite inside $NS_NAME..."
    ip netns exec "$NS_NAME" bash "$(dirname "$0")/run-all.sh"
else
    echo "[*] Executing: $* inside $NS_NAME..."
    ip netns exec "$NS_NAME" "$@"
fi
