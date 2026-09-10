#!/usr/bin/env bash
# Remove the managed installation only after recorded session cleanup succeeds.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo." >&2
    exit 1
fi
if systemctl is-active --quiet wraith.service; then
    systemctl stop wraith.service
fi
if [[ -e /var/run/wraith.state ]]; then
    if [[ ! -x /usr/local/bin/wraith ]]; then
        echo "Session state exists but the managed binary is missing. Recover networking before uninstalling." >&2
        exit 1
    fi
    /usr/local/bin/wraith -x
fi
systemctl disable wraith.service 2>/dev/null || true
rm -f -- /etc/systemd/system/wraith.service /etc/systemd/system/wraith-early.service
systemctl daemon-reload
rm -f -- /usr/local/bin/wraith /etc/bash_completion.d/wraith /usr/share/bash-completion/completions/wraith /usr/share/zsh/vendor-completions/_wraith /usr/share/zsh/site-functions/_wraith
echo "Managed installation removed. Configuration and logs retained; unrelated firewall and DNS settings were not reset."
