# Wraith v1.5.3 — Network Privacy Baseline and Release Maintenance

This release centers the network stack on L3/L4 TCP normalization, Netlink routing, and RFC-aligned general HTTP privacy handling. Tool-specific HTTP request matching and User-Agent rewriting are removed; the local relay preserves application User-Agent values.

The repository-wide documentation review updates old release notes, wiki pages, CLI descriptions, and legal-use information with technically factual wording. Historical release pages identify superseded artifacts.

The release workflow now publishes the detailed release notes, runs locked workspace tests and Clippy on both GNU architectures, builds native Debian packages and GNU/musl archives for amd64 and arm64, and publishes signed APT metadata once. The standalone APT workflow is reserved for scheduled refresh and manual recovery.

The native Linux CI run also exposed a test-only import that was unused on Linux. The test module is now compiled only on the non-Linux targets where its unsupported-platform assertion applies.

The published [v1.5.3 GitHub release](https://github.com/ByGh00st/wraith/releases/tag/v1.5.3) includes the package assets and checksums.
