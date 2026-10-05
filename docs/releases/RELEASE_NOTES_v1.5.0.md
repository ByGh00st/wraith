# Wraith v1.5.0 — Stabilization and Packaging Update

> **Historical release notice:** Legacy release pages, binary assets, and version tags for v1.0.0–v1.5.2 have been removed. Their source commits remain in Git history and may contain earlier network request handling. Maintained source and packages are published in [v1.5.3](https://github.com/ByGh00st/wraith/releases/tag/v1.5.3).

This historical release added Linux namespace integration checks, parser fuzz targets, distribution-matrix builds, and Debian packaging validation. These checks cover the scenarios configured in the v1.5.0 workflows; they are not a guarantee of error-free operation on other kernels, distributions, or network configurations.

## Recorded CI scope

- Seven network-namespace integration scenarios exercised the configured routing and recovery paths on Linux.
- Five libFuzzer targets covered packet, DNS, proxy-request, Netlink, and HTTP relay parsers. Fuzzing results apply only to the inputs, duration, and toolchain used for each run.
- Build jobs covered Debian-family packages and GNU/musl archives for amd64 and arm64, with a compatibility matrix for Debian, Ubuntu, Kali, Arch, and Alpine.
- Debian validation included Lintian, man-page rendering, and package purge checks.

## Scope and limitations

Passing an automated check does not establish that every packet is routed as intended, that the host is isolated in all environments, or that all runtime artifacts are removed. Review the [threat model](../THREAT_MODEL.md), verify the active system state, and test on the target distribution before deployment.

The v1.5.0 release page, binary assets, and version tag have been removed. The historical source commit remains in Git history; its version tag and generated archive have been withdrawn. Maintained packages are in the [v1.5.3 release](https://github.com/ByGh00st/wraith/releases/tag/v1.5.3).
