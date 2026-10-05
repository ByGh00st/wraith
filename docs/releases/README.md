# Wraith Release Notes Archive

This directory contains detailed technical release notes and security advisories for each released version of Wraith.

For a chronological overview of all changes, please refer to the primary project [CHANGELOG.md](../../CHANGELOG.md).

Legacy release pages, binary assets, and version tags for v1.0.0–v1.5.2 have been removed. Their source commits remain in Git history, so existing clones and forks may still contain older code. See the current [v1.5.4 release](https://github.com/ByGh00st/wraith/releases/tag/v1.5.4) for packages.

---

## Releases Index

| Version | Release Type | Key Highlights | Document |
| :--- | :--- | :--- | :--- |
| **v1.5.4** | Session cleanup scope | Removes host log/history erasure, swap/cache purges, process masquerading, and debugger-triggered termination | [RELEASE_NOTES_v1.5.4.md](./RELEASE_NOTES_v1.5.4.md) |
| **v1.5.3** | Network handling and release maintenance | Tool-specific HTTP request rewriting removed; current relay preserves application User-Agent values; CI and APT publication updates | [RELEASE_NOTES_v1.5.3.md](./RELEASE_NOTES_v1.5.3.md) |
| **v1.5.0** | Stabilization Gate | Namespace integration checks, five parser fuzz targets, distribution builds, and Debian packaging checks | [RELEASE_NOTES_v1.5.0.md](./RELEASE_NOTES_v1.5.0.md) |
| **v1.4.7** | Security & Maintenance | TOCTOU key shredding protection, FQDN trailing-dot normalization, torrc directive injection guards, OsRng L2 MAC entropy, Seccomp memory inspection filter | [RELEASE_NOTES_v1.4.7.md](./RELEASE_NOTES_v1.4.7.md) |
| **v1.4.6** | Security & Hardening | Emergency Reset HUD, DoD 5220.22-M key shredding, RAMFS ephemeral WireGuard keys, pidfd rogue process containment | [RELEASE_NOTES_v1.4.6.md](./RELEASE_NOTES_v1.4.6.md) |
| **v1.4.3** | Maintenance | Indeterminate DNSSEC proof acceptance, direct DNS fallback validation | [RELEASE_NOTES_v1.4.3.md](./RELEASE_NOTES_v1.4.3.md) |
| **v1.4.2** | Maintenance | Root-owned legacy lease directory recovery repairs | [RELEASE_NOTES_v1.4.2.md](./RELEASE_NOTES_v1.4.2.md) |
| **v1.4.1** | Compatibility | Linux kernel lockdown policy compliance | [RELEASE_NOTES_v1.4.1.md](./RELEASE_NOTES_v1.4.1.md) |
| **v1.4.0** | Feature Release | Native Debian packaging, verification suites, and architecture alignment | [RELEASE_NOTES_v1.4.0.md](./RELEASE_NOTES_v1.4.0.md) |
| **v1.3.0** | Initial Baseline | Multi-tier proxy orchestration baseline release | [RELEASE_NOTES_v1.3.0.md](./RELEASE_NOTES_v1.3.0.md) |
