# Threat model and boundaries

| Objective | Mechanism | Boundary |
| :--- | :--- | :--- |
| Restrict direct egress | Session firewall and optional namespace | Root and other privileged policy writers can change enforcement |
| Validate intercepted DNS | Local DNSSEC over Tor DoH | Authenticated unsigned delegations remain unsigned |
| Normalize selected TCP settings | Namespace sysctl, MSS and initial-window metrics | Does not control Tor exit TCP or guarantee OS fingerprint equivalence |
| Reduce local access-link TCP differences | Tor UID TTL + initial SYN option/MSS normalization | Local ISP/firewall observer; native window/scale and Tor Guard TLS remain unchanged |
| Profile Wraith HTTPS | Certificate-verified browser TLS client | Other applications retain their own handshakes |
| Remove HTTP address metadata | Initial request header filtering | Persistent follow-up requests are not reparsed |
| Restore settings | Saved state and checked cleanup | Restoration failures retain recovery state and require attention |
| Recover owned orphans | Lifecycle lock, namespace/egress leases and checked teardown | Ambiguous resources are refused; leases are not a full reboot-safe host backup |
| Reduce local virtual-link identifiers | CSPRNG local-unicast namespace MAC before activation | Does not replace the physical MAC or remote Tor exit identity |
| Clear owned memory | Zeroize-on-drop state, snapshots and protected serialization/secret buffers | SIGKILL, abort, power loss, allocator copies and third-party allocations are outside the guarantee |
| Reduce selected local traces | Optional cache, file and swap operations | SSD remapping, snapshots and backups can retain data |

The project does not guarantee anonymity, immunity to destination blocking, resistance to global traffic correlation or protection against a compromised kernel/firmware. Tor is not an arbitrary UDP/ICMP transport.

Access-link normalization preserves shared Tor exits and needs no VPS. IPv6 remains blocked; UDP bridge paths are outside the TCP engine. With WireGuard, the ISP sees the tunnel's outer packets. A failed worker blocks new queued SYNs, not existing established Tor connections. Queue telemetry is not a measured p0f fingerprint, and live NFQUEUE/Guard integration remains unverified.

See [L4 and L7](L4-and-L7.md), [TLS and HTTP](TLS-and-HTTP.md) and [recorded validation](Development.md) for implementation scope and test limits.
