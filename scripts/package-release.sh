#!/usr/bin/env bash
# Package an already-built native Linux release. Does not install it.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
target=${1:?Usage: package-release.sh TARGET}
case "$target" in
    x86_64-unknown-linux-gnu|x86_64-unknown-linux-musl) deb_arch=amd64 ;;
    aarch64-unknown-linux-gnu|aarch64-unknown-linux-musl) deb_arch=arm64 ;;
    *) echo 'Unsupported release target' >&2; exit 1 ;;
esac
mkdir -p target dist
cargo metadata --locked --no-deps --format-version 1 > target/release-metadata.json
version=$(python3 scripts/check-release.py target/release-metadata.json "${WRAITH_RELEASE_TAG:-}")
binary="target/$target/release/wraith"
[[ $("$binary" --version) == "wraith $version" ]]
"$binary" --help >/dev/null
mkdir -p packaging/completions
"$binary" --generate-completions bash > packaging/completions/wraith.bash
"$binary" --generate-completions zsh > packaging/completions/_wraith
"$binary" --generate-completions fish > packaging/completions/wraith.fish
if [[ $target == *-musl ]]; then
    if readelf -l "$binary" | grep -q INTERP; then
        echo 'The musl release must be static; refusing a runtime-loader dependency.' >&2
        exit 1
    fi
else
    deb="dist/wraith_${version}_${deb_arch}.deb"
    cargo deb -p wraith-cli --target "$target" --no-build --no-strip --output "$deb"
    [[ $(dpkg-deb -f "$deb" Package) == wraith ]]
    [[ $(dpkg-deb -f "$deb" Version) == "$version" ]]
    [[ $(dpkg-deb -f "$deb" Architecture) == "$deb_arch" ]]
    extracted=$(mktemp -d)
    trap 'rm -rf -- "$extracted"' EXIT
    dpkg-deb --extract "$deb" "$extracted"
    [[ $(stat -c '%a' "$extracted/usr/bin/wraith") == 755 ]]
    [[ $("$extracted/usr/bin/wraith" --version) == "wraith $version" ]]
    test -f "$extracted/usr/share/doc/wraith/copyright"
    # cargo-deb may gzip installed documentation.
    test -f "$extracted/usr/share/doc/wraith/README.md" || test -f "$extracted/usr/share/doc/wraith/README.md.gz"
    test -f "$extracted/usr/share/bash-completion/completions/wraith"
    test -f "$extracted/usr/share/zsh/vendor-completions/_wraith"
    test -f "$extracted/usr/share/fish/vendor_completions.d/wraith.fish"
    sudo apt-get --simulate install "$(pwd)/$deb"
fi
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    -czf "dist/wraith-${version}-${target}.tar.gz" \
    -C "target/$target/release" wraith -C "$(pwd)" LICENSE README.md
