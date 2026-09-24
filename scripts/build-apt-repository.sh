#!/usr/bin/env bash
# Build a signed-layout APT repository from the two native Wraith .deb files.
# Signing is intentionally performed by the GitHub Actions workflow after this
# script creates indexes and a Release manifest.
set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
Usage: build-apt-repository.sh --input DIR --output DIR --version VERSION

DIR must contain exactly wraith_VERSION_amd64.deb and
wraith_VERSION_arm64.deb. OUTPUT must be empty or absent.
USAGE
    exit 2
}

input=''
output=''
version=''
while (($#)); do
    case "$1" in
        --input) input=${2:-}; shift 2 ;;
        --output) output=${2:-}; shift 2 ;;
        --version) version=${2:-}; shift 2 ;;
        *) usage ;;
    esac
done

[[ -n $input && -n $output && -n $version ]] || usage
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid package version.' >&2; exit 1; }
[[ -d $input ]] || { echo 'Input directory is missing.' >&2; exit 1; }
for command in apt-ftparchive dpkg-deb dpkg-scanpackages gzip; do
    command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 1; }
done

if [[ -e $output ]] && find "$output" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    echo 'Output directory must be empty.' >&2
    exit 1
fi
mkdir -p "$output"

for architecture in amd64 arm64; do
    package="$input/wraith_${version}_${architecture}.deb"
    [[ -f $package ]] || { echo "Missing package: $(basename "$package")" >&2; exit 1; }
    [[ $(dpkg-deb -f "$package" Package) == wraith ]] || { echo 'Unexpected package name.' >&2; exit 1; }
    [[ $(dpkg-deb -f "$package" Version) == "$version" ]] || { echo 'Unexpected package version.' >&2; exit 1; }
    [[ $(dpkg-deb -f "$package" Architecture) == "$architecture" ]] || { echo 'Unexpected package architecture.' >&2; exit 1; }
done

pool="$output/pool/main/w/wraith"
distribution="$output/dists/stable"
mkdir -p "$pool"
install -m 0644 "$input/wraith_${version}_amd64.deb" "$input/wraith_${version}_arm64.deb" "$pool/"

for architecture in amd64 arm64; do
    index="$distribution/main/binary-$architecture"
    mkdir -p "$index"
    (
        cd "$output"
        dpkg-scanpackages --arch "$architecture" pool /dev/null > "dists/stable/main/binary-$architecture/Packages"
    )
    [[ $(grep -c '^Package: wraith$' "$index/Packages") == 1 ]] || { echo 'Invalid Packages index.' >&2; exit 1; }
    gzip --no-name --best --stdout "$index/Packages" > "$index/Packages.gz"
done

valid_until=$(date --utc --date='+35 days' --rfc-email)
(
    cd "$output"
    apt-ftparchive \
        -o 'APT::FTPArchive::Release::Origin=ByGh00st' \
        -o 'APT::FTPArchive::Release::Label=Wraith' \
        -o 'APT::FTPArchive::Release::Suite=stable' \
        -o 'APT::FTPArchive::Release::Codename=stable' \
        -o 'APT::FTPArchive::Release::Architectures=amd64 arm64' \
        -o 'APT::FTPArchive::Release::Components=main' \
        -o 'APT::FTPArchive::Release::Description=Wraith signed APT repository' \
        -o "APT::FTPArchive::Release::Valid-Until=$valid_until" \
        release dists/stable > dists/stable/Release
)
grep -Fxq 'Suite: stable' "$distribution/Release"
grep -Fxq 'Codename: stable' "$distribution/Release"
grep -Fxq 'Components: main' "$distribution/Release"

touch "$output/.nojekyll"
