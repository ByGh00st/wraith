# Wraith v1.5.1 — TCP Normalization and HTTP Privacy Baseline

Wraith v1.5.1 updates the architecture around L3/L4 TCP stack normalization, Netlink routing, and RFC-aligned general network privacy handling. Tool-specific L7 signature matching, User-Agent substitution tables, obfuscated signature payloads, and the corresponding packet rewrite/detection paths have been removed.

The local HTTP relay now removes proxy-only address and authentication metadata and applies connection handling to the initial cleartext request. It preserves User-Agent values and does not rewrite HTTPS or claim browser impersonation. Browser-profile TLS remains scoped to Wraith-owned client requests and does not change third-party applications' CONNECT traffic.

The release also updates installation metadata, package versioning, project guidance, and the legal notice. Use Wraith only on systems and networks for which you have authority and any required consent. See the README's **Legal Notice & Dual-Use Compliance** and the GPL-3.0 license for applicable terms and limitations.

## Installation

The signed APT repository is refreshed by the release pipeline after the v1.5.1 package assets are published. On Debian-family systems with the repository configured:

```bash
sudo apt update
sudo apt install --only-upgrade wraith
```

Manual package downloads and checksums are published on the [v1.5.1 GitHub release page](https://github.com/ByGh00st/wraith/releases/tag/v1.5.1) when release publication completes.