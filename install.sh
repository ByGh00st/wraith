#!/usr/bin/env bash
# Install verified assets from ByGh00st/wraith's latest stable GitHub release.
set -euo pipefail
umask 077

die() { printf 'wraith installer: %s\n' "$*" >&2; exit 1; }
dry_run=false
case ${1:-} in
    '') ;;
    --dry-run) dry_run=true ;;
    --help) echo 'Usage: bash install.sh [--dry-run]'; exit 0 ;;
    *) die 'Only --dry-run or --help is accepted.' ;;
esac
[[ $# -le 1 ]] || die 'Unexpected arguments.'
[[ $(uname -s) == Linux ]] || die 'Only Linux is supported.'
case $(uname -m) in
    x86_64|amd64) arch=x86_64; deb_arch=amd64 ;;
    aarch64|arm64) arch=aarch64; deb_arch=arm64 ;;
    *) die 'Supported CPUs: x86_64 and aarch64.' ;;
esac
for tool in curl python3 mktemp; do
    command -v "$tool" >/dev/null || die "Install $tool first (Alpine: apk add bash curl python3)."
done
libc_kind=gnu
if [[ -f /etc/alpine-release ]] || [[ $(ldd --version 2>&1 || true) == *musl* ]]; then
    libc_kind=musl
elif ! getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
    die 'Cannot identify glibc or musl; refusing an incompatible binary.'
fi
format=tar
if [[ $libc_kind == gnu ]] && command -v apt-get >/dev/null && command -v dpkg >/dev/null; then
    [[ $(dpkg --print-architecture) == "$deb_arch" ]] || die 'CPU and dpkg architecture differ.'
    command -v dpkg-deb >/dev/null || die 'dpkg-deb is required.'
    format=deb
fi
temporary=$(mktemp -d)
install_tmp=''
as_root=()
cleanup() {
    if [[ -n $install_tmp ]]; then "${as_root[@]}" rm -f -- "$install_tmp"; fi
    rm -rf -- "$temporary"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
download() {
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --tlsv1.2 --retry 3 --connect-timeout 15 --max-time 300 --max-filesize "$3" \
        --header 'Accept: application/vnd.github+json' --user-agent 'wraith-installer' \
        --output "$2" "$1"
}
download 'https://api.github.com/repos/ByGh00st/wraith/releases/latest' "$temporary/release.json" 2097152
selection=$(python3 - "$temporary/release.json" "$format" "$arch" "$deb_arch" "$libc_kind" <<'PY_METADATA'
import json, re, sys
sys.stdout.reconfigure(newline="\n")
path, kind, arch, deb_arch, libc = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    release = json.load(stream)
tag = release.get("tag_name", "")
if release.get("draft") is not False or release.get("prerelease") is not False or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
    raise SystemExit("No supported stable release metadata")
version = tag[1:]
name = f"wraith_{version}_{deb_arch}.deb" if kind == "deb" else f"wraith-{version}-{arch}-unknown-linux-{libc}.tar.gz"
def asset_url(wanted):
    matches = [asset for asset in release.get("assets", []) if asset.get("name") == wanted]
    expected = f"https://github.com/ByGh00st/wraith/releases/download/{tag}/{wanted}"
    if len(matches) != 1 or matches[0].get("state") != "uploaded" or matches[0].get("browser_download_url") != expected:
        raise SystemExit(f"Release is missing a unique uploaded asset: {wanted}")
    return expected
print(version)
print(name)
print(asset_url(name))
print(asset_url("SHA256SUMS.txt"))
PY_METADATA
) || die 'Could not select a complete release for this platform.'
mapfile -t release_fields <<< "$selection"
version=${release_fields[0]}
asset_name=${release_fields[1]}
asset_path="$temporary/$asset_name"
download "${release_fields[2]}" "$asset_path" 536870912
download "${release_fields[3]}" "$temporary/SHA256SUMS.txt" 65536
python3 - "$asset_path" "$temporary/SHA256SUMS.txt" "$asset_name" <<'PY_CHECKSUM'
import hashlib, re, sys
path, checksum_path, name = sys.argv[1:]
with open(checksum_path, encoding="ascii") as stream:
    matches = [m[1] for line in stream if (m := re.fullmatch(r"([a-fA-F0-9]{64}) [ *]([^\r\n]+)\r?\n?", line)) and m[2] == name]
if len(matches) != 1:
    raise SystemExit("Missing or duplicate checksum for selected asset")
digest = hashlib.sha256()
with open(path, "rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest() != matches[0].lower():
    raise SystemExit("SHA256 mismatch; installation refused")
PY_CHECKSUM
if [[ $format == deb ]]; then
    [[ $(dpkg-deb -f "$asset_path" Package) == wraith ]] || die 'Unexpected package name.'
    [[ $(dpkg-deb -f "$asset_path" Version) == "$version" ]] || die 'Unexpected package version.'
    [[ $(dpkg-deb -f "$asset_path" Architecture) == "$deb_arch" ]] || die 'Unexpected package architecture.'
    destination=/usr/bin/wraith
else
    python3 - "$asset_path" "$temporary" "$arch" <<'PY_ARCHIVE'
import pathlib, shutil, sys, tarfile
archive, directory, arch = sys.argv[1:]
expected = {"wraith", "LICENSE", "README.md"}
seen = set()
with tarfile.open(archive, "r:gz") as tar:
    for member in tar:
        if member.name not in expected or member.name in seen or not member.isfile() or member.size > 268435456:
            raise SystemExit("Unexpected archive member, link or size")
        seen.add(member.name)
        with tar.extractfile(member) as source, open(pathlib.Path(directory) / member.name, "xb") as target:
            shutil.copyfileobj(source, target, 1024 * 1024)
if seen != expected:
    raise SystemExit("Incomplete release archive")
with open(pathlib.Path(directory) / "wraith", "rb") as stream:
    header = stream.read(20)
machine = 62 if arch == "x86_64" else 183
if header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != machine:
    raise SystemExit("Wrong ELF format or CPU architecture")
PY_ARCHIVE
    destination=/usr/local/bin/wraith
fi
if "$dry_run"; then
    printf 'Verified %s; would install %s (no system changes).\n' "$asset_name" "$destination"
    exit 0
fi
if [[ $EUID -ne 0 ]]; then
    command -v sudo >/dev/null || die 'Run as root or install sudo.'
    as_root=(sudo)
fi
if [[ $format == deb ]]; then
    # APT's sandbox user may read this public, checksum-verified package.
    chmod 0755 "$temporary"
    chmod 0644 "$asset_path"
    "${as_root[@]}" apt-get install -y "$asset_path"
else
    "${as_root[@]}" install -d -m 0755 /usr/local/bin /usr/local/share/doc/wraith
    install_tmp=$("${as_root[@]}" mktemp /usr/local/bin/.wraith-install.XXXXXXXXXX)
    "${as_root[@]}" install -m 0755 "$temporary/wraith" "$install_tmp"
    [[ $("$install_tmp" --version) == "wraith $version" ]] || die 'Downloaded binary failed its version check.'
    "${as_root[@]}" mv -fT -- "$install_tmp" "$destination"
    install_tmp=''
    "${as_root[@]}" install -m 0644 "$temporary/LICENSE" "$temporary/README.md" /usr/local/share/doc/wraith/
fi
[[ $("$destination" --version) == "wraith $version" ]] || die 'Installed version does not match the release.'
hash -r
resolved=$(command -v wraith || true)
[[ $resolved == "$destination" ]] || die "Installed $destination, but PATH resolves to '${resolved:-nothing}'. Adjust PATH or remove the old installation explicitly."
wraith --version
printf 'Installed %s. Runtime commands (Tor, iproute2, Netfilter and util-linux) must be available before starting a session.\n' "$destination"
