# Wraith v1.4.0


> **Historical release notice:** Legacy release pages, binary assets, and version tags for v1.0.0–v1.5.2 have been removed. Their source commits remain in Git history and may contain earlier network request handling. Maintained source and packages are published in [v1.5.4](https://github.com/ByGh00st/wraith/releases/tag/v1.5.4).

**Native Linux packages, verified installation and stronger session recovery.**

Wraith 1.4.0 ships Debian packages and GNU/musl archives for both x86_64 and ARM64. The installer selects the matching CPU and libc, verifies SHA-256, and checks the installed version and command path.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/ByGh00st/wraith/main/install.sh | sudo bash
wraith --version
```

The installer requires Bash, curl and Python 3.8+. If already root, use `bash` instead of `sudo bash`. Debian-family systems use APT and `/usr/bin/wraith`; archive installations use `/usr/local/bin/wraith`.

The v1.4.0 binary links and checksums have been withdrawn. Use the current [v1.5.4 release](https://github.com/ByGh00st/wraith/releases/tag/v1.5.4) for maintained packages.

## Changes

- **Distribution:** architecture-matched Debian packages, static musl builds, checked archive contents and a tag-driven release pipeline that publishes only after all assets upload.
- **Build stability:** ThinLTO, 16 codegen units, stripped symbols and limited Cargo/CMake concurrency. Disposable CI runners receive 4 GiB additional swap.
- **ARM64:** native seccomp architecture/syscall selection and verified native GNU/musl builds.
- **Network sessions:** namespace TCP profiles, local Tor access-link SYN normalization and inspect telemetry, preserving shared Tor exits.
- **Recovery and memory:** CSPRNG namespace veth MACs, durable ownership checks for orphan cleanup, and zeroization of owned session/snapshot buffers on normal drop.
- **Dependencies:** rustls 0.23.45 includes the fix for RUSTSEC-2026-0285.
- **Documentation:** refreshed README, installation matrix, source metrics, wiki and release guide.

## Compatibility and validation

Debian packages require `libc6 >= 2.34`; GNU archives need compatible glibc/libstdc++. Alpine users can install the installer prerequisites with `apk add bash curl python3`. Archive users must also install the runtime tools: Tor, iproute2, Netfilter and util-linux. No external APT repository is added. `wraith -u` remains a source-checkout update; package upgrades use the installer or a newer `.deb`.

For source builds on constrained machines:

```bash
CMAKE_BUILD_PARALLEL_LEVEL=2 cargo build --release --locked -j 2 -p wraith-cli
```

The release profile uses `panic = "abort"`: normal exits and ordinary errors run destructors, but a release panic does not. Reduced build concurrency and swap mitigate memory pressure without guaranteeing zero OOM failures; Cargo exit 101 alone does not identify OOM.

Validation includes **240 tests on each native GNU Linux architecture**, **238 Windows tests**, all-target Clippy with warnings denied, **14 installer scenarios**, actual Debian packaging and static musl executable checks. Privileged live network integration and full installed-system updates remain outside these checks.

[Getting started](https://github.com/ByGh00st/wraith/wiki/Getting-Started) · [Full changelog](https://github.com/ByGh00st/wraith/blob/main/CHANGELOG.md) · [Protection scope](https://github.com/ByGh00st/wraith/wiki/Threat-Model)
