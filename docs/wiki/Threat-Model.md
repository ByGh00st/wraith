# THREAT MODEL & OPERATIONAL BOUNDARIES

Formal analysis of security objectives, threat vectors, mitigation mechanisms, defensive boundaries, and explicit non-goals of the Wraith system.

---

## 1. Security Objectives & Assets Protected

Wraith is engineered to achieve specific, bounded technical objectives under defined operating assumptions:

1. **Fail-Closed Egress Isolation:** Prevent unauthorized non-Tor TCP egress from local userspace applications via kernel netfilter policies.
2. **Cryptographic DNS Authentication:** Neutralize DNS spoofing, cache poisoning, and resolver surveillance by validating DNSSEC chains of trust over Tor DoH (RFC 8484).
3. **Local Ephemeral Data Minimization:** Minimize forensic residue on the host by clearing volatile kernel caches, drop-caches, and temporary routing entries upon session termination.
4. **Passive Fingerprint Attenuation:** Standardize select network and application parameters (TCP TTL/timestamps, HTTP User-Agent headers, TLS ClientHello handshakes) to reduce passive attribution by network intermediaries.

---

## 2. Threat Vector & Mitigation Matrix

| Threat Vector | Mitigation Strategy | Operational Boundary / Residual Risk |
| :--- | :--- | :--- |
| **Unintended Clearnet Egress** | Default `DROP` policy on netfilter `OUTPUT` chain; atomic redirection to Tor TransPort (`9040`). | Host root or processes with `CAP_NET_ADMIN` can override iptables rules; concurrent external firewall daemons are uncoordinated. |
| **DNS Poisoning & Eavesdropping** | Local Hickory DNSSEC validator over Tor DoH (`127.0.0.1:5354`). | Domains without DNSSEC signatures (insecure delegations) remain unauthenticated; relies on Tor availability. |
| **WebRTC STUN Leakage** | Firewall drops outbound UDP traffic; automated RFC 5389 audit probe tests STUN ports (`19302`, `3478`). | Applications directly binding to raw sockets or secondary physical interfaces with root privileges can bypass filters. |
| **Cleartext HTTP Fingerprinting** | In-flight HTTP proxy (`127.0.0.1:9055`) strips identifying headers and normalizes User-Agent strings. | Applies only to unencrypted port 80 traffic; does not inspect or decrypt HTTPS traffic. |
| **Volatile Memory Inspection** | ChaCha20-Poly1305 encrypted RAMFS vault, `mlockall` page-locking, and zeroization of sensitive buffers. | Kernel-level rootkits, cold-boot physical memory attacks, or hardware DMA attacks remain unmitigated. |
| **Process Enumeration** | `prctl(PR_SET_NAME)` scheduler masking as `[kworker/u16:0]`. | Unprivileged users see masked comm; root users inspecting `/proc/{pid}/exe` can resolve the canonical executable path. |

---

## 3. Explicit Non-Goals & System Boundaries

To maintain legal and technical integrity, the following capabilities are explicitly declared outside the architectural scope of Wraith:

1. **No Absolute Anonymity Guarantee:** No software framework can guarantee absolute anonymity against sophisticated state-level adversaries, targeted physical surveillance, or zero-day vulnerabilities in the host operating system.
2. **Arbitrary UDP & ICMP Transport:** The Tor network protocol does not support arbitrary UDP packet routing or ICMP echo requests. Wraith drops non-DNS UDP and ICMP traffic by default to prevent clearnet IP leakage.
3. **Hardware & Firmware Security:** Compromised hardware, motherboard firmware (UEFI/BIOS), processor microcode vulnerabilities (e.g., Spectre, Meltdown), and hardware keyloggers are fundamentally outside the user-space boundary.
4. **Resistance to Global Statistical Traffic Correlation:** Tor is an onion-routing network designed for low-latency communication; it does not protect against a global passive adversary capable of simultaneously observing traffic ingress and egress at autonomous system boundaries.
5. **Decryption of Third-Party HTTPS:** Wraith does not perform TLS termination or Man-In-The-Middle (MITM) inspection on arbitrary HTTPS traffic. Applications communicating via HTTPS retain their native cryptographic certificates and TLS profiles.
