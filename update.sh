#!/usr/bin/env bash
# Synchronize official source without discarding local changes.
set -euo pipefail
if [[ $EUID -eq 0 ]]; then
    [[ ${SUDO_UID:-0} -ne 0 ]] || { echo "Run ./update.sh as a non-root user." >&2; exit 1; }
    update_user=$(getent passwd "$SUDO_UID" | cut -d: -f1)
    [[ -n $update_user ]] || exit 1
    exec sudo -H -u "$update_user" -- bash "$(realpath -- "${BASH_SOURCE[0]}")"
fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
# Ignore environment overrides and global helpers. Repository helpers run only
# as the invoking user; hooks and filesystem monitors are disabled explicitly.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_CONFIG GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0
update_git() {
    /usr/bin/git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
        -c protocol.allow=never -c protocol.https.allow=always -c http.sslVerify=true "$@"
}
update_git rev-parse --show-toplevel >/dev/null
origin=$(update_git config --get remote.origin.url)
case "$origin" in
    https://github.com/ByGh00st/wraith.git|https://github.com/ByGh00st/wraith) ;;
    *) echo "Refusing to update a repository with a different origin." >&2; exit 1 ;;
esac
[[ $(update_git symbolic-ref --short HEAD) == main ]] || { echo "Switch to main before updating." >&2; exit 1; }
[[ -z $(update_git status --porcelain --untracked-files=normal) ]] || { echo "Commit or stash local changes before updating." >&2; exit 1; }
config=$(update_git config --list)
if printf '%s\n' "$config" | grep -qiE '^url\..*\.insteadof='; then
    echo "Remove Git URL rewrite rules before updating." >&2; exit 1
fi
update_git fetch --no-tags --no-recurse-submodules https://github.com/ByGh00st/wraith.git main
update_git merge --ff-only --no-edit FETCH_HEAD
echo "Source synchronized. Run sudo ./build.sh to build and install the updated binary."
