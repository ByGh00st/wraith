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
| Local ISP/firewall TCP fingerprint observation | Namespace profiles plus Tor UID TTL and SYN option/MSS normalization | Preserve native window/scale and Tor Guard TLS; shared exit stack unchanged; verified by automated NetNS kernel suite and native live_wire_syn_audit test |
| HTTP client header & Tool exposure | Real-time L7 Proxy Deep Packet Inspection (DPI) & wire-level UA rewriting | Does not decrypt HTTPS. Modifies cleartext HTTP headers. |
| Unsafe setup or interrupted cleanup | Pre-mutation state, snapshots and retryable restoration | Snapshots do not capture all metadata or independent external changes |
| Process inspection and buffer exposure | Ptrace restrictions, memory locking, authenticated vault and owned state/snapshot zeroization | SIGKILL/abort/power loss skip destructors; allocator copies, third-party TLS and compromised kernels remain outside the guarantee |
| Orphaned network resources | Lifecycle lock, durable namespace/egress leases and ownership-checked teardown | Ambiguous resources are refused; network leases do not replace a persistent full host backup |
| Virtual-link identifiers | OS-CSPRNG local-unicast namespace MAC before activation | Does not change the physical MAC or identity at a remote Tor exit |
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

Automated E2E integration tests exercise live Linux Netfilter tables, Tor circuit bootstrapping, fail-closed watchdog kills, and zero-clearnet DNS leak detection within isolated Linux network namespaces (`tests/e2e/harness.sh`). Five continuous `libFuzzer` targets fuzz untrusted byte streams (TCP SYN morphing, Netlink frames, DNS packets, HTTP proxy requests, and DPI header sanitization). Multi-distribution Docker runs verify compatibility across Kali, Debian, Ubuntu, Arch, and Alpine. These automated gates establish verified network behavior without claiming theoretical immunity against global traffic correlation or exit-node adversary observation.
