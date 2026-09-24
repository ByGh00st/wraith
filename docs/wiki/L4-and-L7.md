# L4 and L7: scope and verification

> **PROFILES** · Namespace TCP controls + Tor access-link normalization, with shared Tor exits.

Wraith's local L4 target is the **ISP, enterprise firewall or DPI observer between the machine and its Tor Guard/TCP bridge**. No external VPS is required. Destination websites still see the TCP stack of the shared Tor exit.

## What applies where?

| Control | Application point | Boundary |
| :--- | :--- | :--- |
| TCP sysctl profile | Wraith application namespace | Does not reproduce every OS TCP option or ordering |
| SYN MSS rule | Namespace netfilter | Does not control Tor exit-node TCP |
| Initial window metrics | Namespace default route | Configuration is not a captured wire signature |
| Random local-unicast MAC | Namespace-side veth before either endpoint is UP | Physical adapter and remote Tor exit identity are separate |
| Tor TCP TTL | Tor UID's IPv4 output outside loopback | Host TCP sysctls remain unchanged |
| SYN option/MSS normalization | Tor UID's initial IPv4 SYNs, before Guard connections | Preserve native window/scale; shared exit TCP is unchanged |
| Browser ClientHello | Wraith TLS client and its public API | Does not rewrite arbitrary tunneled HTTPS |
| HTTP normalization | Initial cleartext request through port 9055 | Later requests on a persistent stream are not reparsed |

```bash
sudo wraith start --morph-l4 auto --tls-profile safari
# In another terminal, from your normal sudo account:
sudo wraith exec -- curl https://example.com
```

This puts curl in the namespace. Curl still constructs its own TLS handshake. Use `wraith fetch` or `BrowserTlsClient` when Wraith should construct the ClientHello.

## Reference profiles

| Profile | TTL | Window scaling | Timestamps | SACK | MSS target |
| :--- | ---: | :---: | ---: | :---: | ---: |
| Windows11 | 128 | On | 0 | On | 1460 |
| MacOS | 64 | On | 1 | On | 1440 |
| LinuxDefault | 64 | On | 1 | On | Kernel-selected |

Linux timestamps use `0` for disabled, `1` for enabled with a per-connection random offset, and `2` for enabled without that offset. `LinuxDefault` is a reference baseline, not a read of distribution-specific settings. Sysctl does not guarantee an exact macOS SYN window or native OS TCP option ordering.

## Namespace boundary and API

Only `wraith_ns` and approved per-network-namespace TCP keys are accepted. The engine checks namespace device/inode identity against the host/current namespace, retains an open descriptor, and executes sysctl commands through `nsenter` from util-linux. Renaming or replacing the namespace path does not retarget the sysctl transaction. The Rust caller never enters another namespace, and the legacy global host writer always returns an error.

`apply_sysctl_profile` returns an explicit applied or skipped result. `FailClosed` propagates failures. `RestoreAndContinue` may skip eligible failures only before mutation or after successful rollback; namespace guard failures and failed rollback remain errors. The `syn_mss` field accepts the old serialized `forced_syn_mss` name for compatibility.

These writes form a recoverable sequence, not one kernel-atomic multi-key operation. Application workloads should enter after setup succeeds. A crash cannot run in-memory rollback; recovery depends on the journaled namespace lifecycle.

## CLI selection and inspect

`--morph-l4 auto` creates the namespace, arms the Tor access-link policy and follows the session TLS platform. `--tls-profile chrome` (the default) maps to Windows11, `firefox` to LinuxDefault, and `safari` to MacOS. The selected TLS profile is used by DoH, DNSSEC validation queries and optional cover requests. It does not change Tor's outer handshake or the TLS implementation of an application launched with `exec`; `fetch` has its own TLS selection.

| CLI mode | Namespace behavior |
| :--- | :--- |
| `--morph-l4 windows` / `windows11` | Windows reference: TTL 128, MSS cap 1460, initcwnd 10 / initrwnd 44 |
| `--morph-l4 macos` | macOS reference: TTL 64, MSS cap 1440, initcwnd 10 / initrwnd 45 |
| `--morph-l4 linux` | Linux reference sysctls, no MSS or FIB override |
| `--namespace --morph-l4 off` | Namespace routing remains active; both namespace tuning and Tor egress normalization are disabled |

The old `--tcp-profile`, `--l4-profile` and `--os-profile` spellings remain aliases. Explicit `auto` enables namespace setup, as do `--namespace`, `--tcp-mask` and full-security. `off` alone does not create a namespace and conflicts with full-security or `--tcp-mask`. CLI values override persistent `hardening.morph_l4` / `hardening.tls_profile` settings.

`-Fs` includes namespace + Tor access-link L4 `auto`, with Chrome TLS unless another session TLS profile is selected. Strict mode accepts only matching L4/TLS platforms; ordinary sessions may select them independently. A missing or incompatible namespace snapshot, configuration drift or failed final readback prevents strict activation. Every L4-enabled session also requires a live egress worker, owned queue and rules before activation. See the [full-security guide](Advanced-Configuration.md#full-security-preset) for the complete required bundle.

`sudo wraith -i` displays the recorded strict/standard policy and reads the namespace's live TTL, window scaling, timestamps, SACK, MSS rule presence and FIB metrics. It reports configuration match, drift or unavailable readback. The namespace device/inode must match the recorded lifetime; legacy snapshots without sufficient data cannot claim successful verification. The profile shown is the saved selection, not a hard-coded Windows result. Matching configuration is explicitly separate from an unmeasured wire fingerprint.

### Cross-layer pairing and drift

The `L4↔L7 configured pairing` row compares the selected Wraith TLS platform with **both** namespace and Tor egress reference profiles. Matching platforms report compatibility with wire coherence unmeasured; a mismatch reports `ANOMALY`. Missing or malformed snapshots remain unavailable. This does not inspect application ClientHellos or certify that Tor's outer TLS looks like a browser.

Illustrative excerpt with shortened labels, not a recorded live run:

```text
L4 TCP profile           Windows 11
L4 live readback         ✔ Matches configured profile
TTL / WS / TS / SACK     128 / 1 / 0 / 1
SYN MSS cap              1460 bytes — rule present
FIB initcwnd / initrwnd   10 / 44 segments
Session TLS profile      chrome
L4↔L7 configured pairing Compatible reference platforms; wire unmeasured
Namespace L2 MAC         02:11:22:33:44:55 — local unicast; matches lease
Tor L4 policy / worker   Rules present / Owned queue bound
State buffer handling    Zeroize on drop; abrupt exit excluded
```

Namespace MAC inspection checks the actual address and ownership alias against its lease. It reports `DRIFT` on a mismatch. The buffer-handling row describes the inspecting process's implementation; it cannot verify erasure in a terminated worker.

### L2 before L4

Every new Wraith namespace receives a fresh OS-CSPRNG MAC on its veth peer, including `--namespace --morph-l4 off`. The generator sets the local bit and clears multicast. Setup verifies the address before raising either veth endpoint; failures prevent activation. Host `--mac` remains a separate physical-interface operation. Ethernet addresses stay on their link and do not traverse Tor circuits.

[Detailed design and API example](https://github.com/ByGh00st/wraith/blob/main/docs/L4-SYSCTL-DESIGN.md)

## Tor → Guard: actual packet normalization

<table>
<tr><td width="50%" valign="top"><b>🧬 Selective wire changes</b><br>TTL · SYN option order · MSS cap · Windows timestamp removal</td><td width="50%" valign="top"><b>↩️ Recorded lifecycle</b><br>Bind queue → journal → attach rules → start Tor → verify</td></tr>
</table>

| Field | Windows11 | MacOS | LinuxDefault |
| :--- | :--- | :--- | :--- |
| IPv4 TTL, all Tor TCP packets | 128 | 64 | 64 |
| SYN MSS cap | 1460 | 1440 | Preserve kernel MSS |
| Known option order, when present | MSS, NOP, WS, NOP, NOP, SACK | MSS, NOP, WS, NOP, NOP, TS, SACK | MSS, SACK, TS, NOP, WS |
| Timestamp offer | Remove | Preserve | Preserve |
| Window and scale value | Preserve | Preserve | Preserve |

The engine never increases the kernel's MSS offer or invents absent capabilities. It preserves sequence numbers, flags, unknown extension contents and payload, then recomputes IPv4/TCP checksums. It rejects invalid lengths, fragmentation, malformed known options and authenticated TCP headers. This is selective normalization; native window sizes, IP ID behavior and TCP timing remain kernel-generated.

The dedicated Tor UID's non-loopback IPv4 TCP enters the owned `WRAITH_L4_EGRESS` mangle chain. TTL applies to all those TCP packets, while only initial SYNs enter **NFQUEUE 41884**. Other processes sharing that UID are also covered. Missing queue/TTL support or conflicting ownership refuses startup. The worker uses safe Rust with an owned close-on-exec netlink socket; no additional userspace dependency is needed.

`sudo wraith -i` adds the egress profile, policy presence, owned queue binding, queued/pending SYNs and kernel/netlink delivery drop counters. Counters do not establish successful rewriting, completed connections or a p0f match. A failed worker leaves new SYNs blocked; existing established connections can continue. There is no unmodified fallback or queue-bypass.

Shutdown stops managed Tor before removing the rules and restoring the pre-session firewall. A failed Tor stop or namespace teardown withholds firewall restoration and retains recovery state. A panic leaves policy and the journal for recovery. `exec` refuses application entry during Arming.

Session IPv6 remains blocked. UDP bridge paths are outside this TCP engine. With WireGuard, the ISP sees outer tunnel packets; the normalized Tor TCP remains inside. Tor's own Guard TLS handshake is unchanged, so this feature does not make Tor indistinguishable from Chrome or guarantee DPI non-detection.

[Access-link architecture and failure handling](https://github.com/ByGh00st/wraith/blob/main/docs/L4-EGRESS-DESIGN.md)

## Strict application and rollback

1. Capture original sysctl values and route metrics before mutation.
2. Write each requested sysctl and verify its readback.
3. Install and verify the owned `wraith-l4` IPv4 SYN MSS rule, then apply and read back FIB metrics. Abort incomplete setup and attempt restoration, including the attempted setting.
4. Surface rollback errors instead of reporting success.
5. Require one unicast default route with a device; reject absent, ambiguous, multipath or unsupported locked metrics.
6. Restore saved `initcwnd` and `initrwnd` values and verify them, even when the namespace remains alive. Zero removes the explicit override in favor of the kernel default.

All three tiers and their rollback share one pinned namespace descriptor. MSS rules are checked with `iptables -C`, use a bounded xtables lock wait, and reject duplicate ownership. An MSS readback failure triggers rule cleanup. FIB route changes preserve recorded `proto`, `scope` and `src` attributes; unfamiliar or locked metrics are rejected before mutation to avoid losing route settings. Route restoration refuses a changed route identity or recorded attributes. Older snapshots without the original metrics require namespace teardown for full restoration. Session cleanup normally deletes its namespace; the explicit restore helper can also restore new snapshots without deletion.

Before a new session, the lifecycle lock serializes ownership checks and recovery. Durable namespace/egress leases allow cleanup of verified orphan resources, while ambiguous names or live namespace applications block deletion. Removing an owned namespace discards its MSS, FIB and sysctl overrides; no global host TCP reset is needed. See [orphan preflight](Troubleshooting.md#automatic-orphan-preflight).

## Native SYN audit

The ignored [`live_wire_syn_audit.rs`](https://github.com/ByGh00st/wraith/blob/main/crates/wraith-net/tests/live_wire_syn_audit.rs) creates the production Windows-profile namespace in a private mount/network sandbox. AF_PACKET plus `etherparse` checks TTL 128, initial SYN flags, MSS 1460, absent timestamps, the controlled receive window 64240 and the generated source MAC. It also reads back `initrwnd 44` and repeats orphan preflight after teardown.

Window 64240 is asserted for this fixture's MTU 1500, MSS 1460 and adequate receive buffer. It is not a universal Windows fingerprint or a change to the preserved native window in the Tor egress engine. The audit is cross-compiled but has not been executed live here. See [execution requirements](Development.md#native-linux-wire-audit).

## What remains unmeasured?

The new egress policy changes selected packets from the host Tor daemon; the remote Tor exit still has its own TCP stack. A matching reference profile does not prove that the SYN and ClientHello observed by a destination form a consistent browser/OS identity.

Portable tests cover CLI aliases, explicit auto/off, L7-to-L4 mapping, missing backups, failed writes, MSS installation/readback/rollback, telemetry drift and replaced namespaces/routes. Access-link tests cover fixed packet layouts/checksums, malformed inputs, netlink framing and ownership, policy failures and cleanup ordering. Linux-specific process and network code is cross-compiled. Live privileged NFQUEUE integration, Guard connectivity and p0f capture have not been performed.

**Related:** [TLS and HTTP](TLS-and-HTTP.md) · [Development](Development.md)
