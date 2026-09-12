# Threat model and protection scope

This document describes intended boundaries, not audit findings or a certification. It complements the [security reporting policy](../SECURITY.md) and the [recorded validation](https://github.com/ByGh00st/wraith#validation).

## Assets and assumptions

The project aims to protect intended Tor routing, DNS integrity, sensitive runtime buffers and the user's ability to restore recorded host settings. The host administrator, kernel and installed toolchain are trusted. The operator must select the intended interface and use applications and protocols supported by the chosen configuration.

## Controls and limits

| Threat or failure | Relevant implementation | Boundary |
| :--- | :--- | :--- |
| Unintended direct TCP egress | Netfilter, dedicated Tor UID, strict policy and watchdog | Root can change policy; concurrent firewall writers are not coordinated |
| DNS response forgery | Local DNSSEC validation over verified Tor DoH | Authenticated unsigned delegations remain unsigned |
| HTTPS impersonation | Certificate-chain and hostname verification in the native client | Depends on trust anchors and a correct clock |
| TLS fingerprint differentiation | Browser-profile TLS/HTTP2 for Wraith-owned requests | Not universal JA3/JA4 matching; CONNECT retains application TLS |
| HTTP client header & Tool exposure | Real-time L7 Proxy Deep Packet Inspection (DPI) & wire-level UA rewriting | Does not decrypt HTTPS. Modifies cleartext HTTP headers. |
| Unsafe setup or interrupted cleanup | Pre-mutation state, snapshots and retryable restoration | Snapshots do not capture all metadata or independent external changes |
| Process inspection and buffer exposure | Ptrace restrictions, memory locking, authenticated vault and zeroization | Does not defend against a compromised kernel; crashes may skip destructors |
| Traffic timing observation | Optional netem and bounded cover requests | No demonstrated traffic-correlation resistance |

## Explicit non-goals

- Guaranteed anonymity, non-detection, or avoidance of destination blocklists.
- Protection from a malicious administrator, kernel, firmware or compromised endpoint.
- Transporting arbitrary UDP/QUIC through Tor.
- Rewriting every application's HTTPS ClientHello or installing a system MITM root CA.
- Erasing all copies of data on SSDs, snapshots, backups or remote systems.
- Treating cgroup bookkeeping or experimental physical-interface fastpath helpers as active eBPF protection.

Strict mode checks irreversible kernel prerequisites instead of applying them for a temporary session. Destructive cleanup options are separate from ordinary privacy sessions.

## Evidence and changes

Portable regression tests exercise protocol framing, real local TLS handshakes, DNSSEC rejection and state/policy handling. Linux cross-compilation checks platform-specific code. Neither establishes live Linux network correctness. Changes to these boundaries should include relevant tests, documentation and an explicit account of what was actually validated.
