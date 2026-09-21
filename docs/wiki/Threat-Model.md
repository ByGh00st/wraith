# Threat model and boundaries

| Objective | Mechanism | Boundary |
| :--- | :--- | :--- |
| Restrict direct egress | Session firewall and optional namespace | Root and other privileged policy writers can change enforcement |
| Validate intercepted DNS | Local DNSSEC over Tor DoH | Authenticated unsigned delegations remain unsigned |
| Normalize selected TCP settings | Namespace sysctl, MSS and initial-window metrics | Does not control Tor exit TCP or guarantee OS fingerprint equivalence |
| Profile Wraith HTTPS | Certificate-verified browser TLS client | Other applications retain their own handshakes |
| Remove HTTP address metadata | Initial request header filtering | Persistent follow-up requests are not reparsed |
| Restore settings | Saved state and checked cleanup | Restoration failures retain recovery state and require attention |
| Reduce selected local traces | Optional cache, file and swap operations | SSD remapping, snapshots and backups can retain data |

The project does not guarantee anonymity, immunity to destination blocking, resistance to global traffic correlation or protection against a compromised kernel/firmware. Tor is not an arbitrary UDP/ICMP transport.

See [L4 and L7](L4-and-L7.md), [TLS and HTTP](TLS-and-HTTP.md) and [recorded validation](Development.md) for implementation scope and test limits.
