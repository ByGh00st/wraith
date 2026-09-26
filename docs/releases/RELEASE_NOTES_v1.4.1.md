# Wraith v1.4.1

**Reliable full-security startup and private cleanup reporting.**

## Fixed

- `wraith -Fs` now works on standard Linux systems that report kernel lockdown as `none`, `integrity`, or unavailable. Kernel lockdown is a boot-time administrator policy, so Wraith observes it and never attempts to modify it.
- Wraith still snapshots, applies, verifies and restores its reversible strict-session controls.
- A failed startup no longer shows a duplicate normal banner or a misleading "clearnet active" dashboard.
- Cleanup no longer performs a public-IP/geo request. Its dashboard reports only local restoration and has complete Turkish and English strings, with English fallback text for the remaining bundled locales.

## Install

After the release workflow completes, configure the signed repository once and upgrade:

```bash
sudo apt update
sudo apt install wraith
wraith --version
```

For a direct download, use the [v1.4.1 release](https://github.com/ByGh00st/wraith/releases/tag/v1.4.1) and verify `SHA256SUMS.txt` before installation.

## Validation

- `cargo test -p wraith-core` — 55 unit tests and 5 L4/L7 coherence integration tests passed.
- Linux release CI builds and packages the CLI on its native runners. The local Windows CLI build requires CMake for BoringSSL and is not used as a release artifact.
