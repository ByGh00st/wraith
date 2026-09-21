#!/usr/bin/env bash
# Recover the recorded session before removing the installed executable.
set -euo pipefail
[[ "$EUID" -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
if [[ -e /run/wraith.state || -e /var/run/wraith.state ]]; then
    binary=""
    for candidate in /usr/local/bin/wraith /usr/bin/wraith; do
        if [[ -x "$candidate" ]]; then binary="$candidate"; break; fi
    done
    [[ -n "$binary" ]] || { echo "Restore the Wraith binary and run wraith stop first. Recovery state retained." >&2; exit 1; }
    "$binary" stop
    [[ ! -e /run/wraith.state && ! -e /var/run/wraith.state ]] || { echo "Recovery is incomplete; uninstall stopped." >&2; exit 1; }
fi
for unit in wraith.service wraith-early.service; do
    if systemctl cat "$unit" >/dev/null 2>&1; then systemctl disable --now "$unit"; fi
done
rm -f -- /etc/systemd/system/wraith.service /etc/systemd/system/wraith-early.service
systemctl daemon-reload
rm -f -- /usr/local/bin/wraith /usr/bin/wraith \
    /etc/bash_completion.d/wraith /usr/share/bash-completion/completions/wraith \
    /usr/share/zsh/vendor-completions/_wraith /usr/share/fish/vendor_completions.d/wraith.fish \
    /usr/share/applications/wraith.desktop /usr/share/pixmaps/wraith.png /usr/share/pixmaps/wraith.svg
printf '%s\n' 'Wraith uninstalled. Configuration and logs retained for your review.'
