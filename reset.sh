#!/usr/bin/env bash
# Recover only the recorded session; never erase unrelated firewall policy.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run this recovery script with sudo." >&2; exit 1; }
if [[ ! -e /run/wraith.state && ! -e /var/run/wraith.state ]]; then
    echo "No session record found. System configuration was left unchanged."
    exit 0
fi
for binary in /usr/local/bin/wraith /usr/bin/wraith; do
    if [[ -x $binary ]]; then
        exec "$binary" stop
    fi
done
echo "Wraith binary unavailable. Keep the session record and reinstall before recovery." >&2
exit 1
