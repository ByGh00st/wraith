# Wraith v1.5.2 — Documentation and Release Workflow Maintenance

This maintenance release applies a repository-wide review to archived release notes, wiki pages, and command documentation. It replaces promotional or ambiguous descriptions with factual wording while retaining clear statements about process controls, local cleanup, and their effects.

The v1.5.1 network changes remain in force: L3/L4 TCP stack normalization, Netlink routing, and RFC-aligned general HTTP privacy handling. Tool-specific L7 request rewriting and User-Agent modification remain removed.

The release workflow is now the sole automatic publisher of signed APT metadata after a tagged release. The standalone APT workflow remains available for scheduled metadata refresh and authorized manual recovery, preventing duplicate Pages deployments on release publication.

See the [v1.5.2 GitHub release](https://github.com/ByGh00st/wraith/releases/tag/v1.5.2) for verified Debian packages, GNU/musl archives, and checksums after publication.
