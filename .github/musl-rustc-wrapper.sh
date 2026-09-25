#!/bin/sh
# Only used inside the native Alpine builder, with cargo's explicit --target.
# Host build scripts need dlopen for bindgen/libclang. Target crates retain
# musl's static CRT default, so the distributed executable stays static.
set -eu
compiler=${1:?Expected rustc path}
shift
for argument in "$@"; do
    case "$argument" in
        --target|--target=*) exec "$compiler" "$@" ;;
    esac
done
exec "$compiler" "$@" -C target-feature=-crt-static
