# Wraith v1.5.0 — Stabilization and Packaging Update

This historical release added Linux namespace integration checks, parser fuzz targets, distribution-matrix builds, and Debian packaging validation. These checks cover the scenarios configured in the v1.5.0 workflows; they are not a guarantee of error-free operation on other kernels, distributions, or network configurations.

## Recorded CI scope

- Seven network-namespace integration scenarios exercised the configured routing and recovery paths on Linux.
- Five libFuzzer targets covered packet, DNS, proxy-request, Netlink, and HTTP relay parsers. Fuzzing results apply only to the inputs, duration, and toolchain used for each run.
- Build jobs covered Debian-family packages and GNU/musl archives for amd64 and arm64, with a compatibility matrix for Debian, Ubuntu, Kali, Arch, and Alpine.
- Debian validation included Lintian, man-page rendering, and package purge checks.

## Scope and limitations

Passing an automated check does not establish that every packet is routed as intended, that the host is isolated in all environments, or that all runtime artifacts are removed. Review the [threat model](../THREAT_MODEL.md), verify the active system state, and test on the target distribution before deployment.

This release is superseded. Its binaries have been withdrawn because this source snapshot predates the removal of tool-specific HTTP request rewriting. The immutable source tag remains available for historical review. Use the [v1.5.3 release](https://github.com/ByGh00st/wraith/releases/tag/v1.5.3) for maintained packages and source.
