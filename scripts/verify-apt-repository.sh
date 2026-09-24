#!/usr/bin/env bash
# Verify the signed repository through an isolated local APT configuration.
set -euo pipefail

usage() {
    echo 'Usage: verify-apt-repository.sh --repository DIR --keyring FILE --version VERSION' >&2
    exit 2
}

repository=''
keyring=''
version=''
while (($#)); do
    case "$1" in
        --repository) repository=${2:-}; shift 2 ;;
        --keyring) keyring=${2:-}; shift 2 ;;
        --version) version=${2:-}; shift 2 ;;
        *) usage ;;
    esac
done

[[ -n $repository && -n $keyring && -n $version ]] || usage
[[ -d $repository && -f $keyring ]] || { echo 'Repository or public key is missing.' >&2; exit 1; }
cmp -- "$keyring" "$repository/wraith-archive-keyring.asc"
for command in apt-get dpkg-deb gpg gpgv python3; do
    command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 1; }
done

temporary=$(mktemp -d)
server_pid=''
cleanup() {
    if [[ -n $server_pid ]]; then kill "$server_pid" 2>/dev/null || true; fi
    rm -rf -- "$temporary"
}
trap cleanup EXIT

verify_home="$temporary/gnupg"
mkdir -m 700 "$verify_home"
gpg --batch --homedir "$verify_home" --import "$keyring" >/dev/null
gpgv --keyring "$verify_home/pubring.kbx" "$repository/dists/stable/InRelease" >/dev/null

port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$repository" >"$temporary/http.log" 2>&1 &
server_pid=$!
for _ in {1..20}; do
    if python3 - "$port" <<'PY'
import sys
from urllib.request import urlopen
with urlopen(f"http://127.0.0.1:{sys.argv[1]}/dists/stable/InRelease", timeout=1) as response:
    assert response.status == 200
PY
    then
        break
    fi
    sleep 0.1
done

apt_root="$temporary/apt"
mkdir -p "$apt_root/lists/partial" "$apt_root/archives/partial" "$apt_root/keyrings" "$temporary/download"
install -m 0644 "$keyring" "$apt_root/keyrings/wraith.asc"
printf 'deb [signed-by=%s] http://127.0.0.1:%s stable main\n' "$apt_root/keyrings/wraith.asc" "$port" > "$apt_root/sources.list"
apt_options=(
    -o "Dir::Etc::sourcelist=$apt_root/sources.list"
    -o 'Dir::Etc::sourceparts=-'
    -o "Dir::State::Lists=$apt_root/lists"
    -o "Dir::Cache::archives=$apt_root/archives"
    -o 'APT::Get::List-Cleanup=0'
)
apt-get "${apt_options[@]}" update >/dev/null
(
    cd "$temporary/download"
    apt-get "${apt_options[@]}" download "wraith=$version" >/dev/null
)
package="$temporary/download/wraith_${version}_amd64.deb"
[[ -f $package ]]
[[ $(dpkg-deb -f "$package" Package) == wraith ]]
[[ $(dpkg-deb -f "$package" Version) == "$version" ]]
[[ $(dpkg-deb -f "$package" Architecture) == amd64 ]]
