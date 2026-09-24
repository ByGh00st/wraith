# L4 profile and namespace sysctl design

This design covers profile validation, namespace sysctl transactions, CLI selection, MSS/FIB startup and inspect telemetry. Application entry is allowed only after the fail-closed setup completes.

## Profile model

`wraith_core::tcp_fingerprint::TcpFingerprintProfile` contains `default_ttl`, `tcp_window_scaling`, `tcp_timestamps`, `tcp_sack` and `syn_mss`, plus the existing optional tuning fields. Old serialized `forced_syn_mss` fields remain readable through a serde alias. Custom profiles are validated before application.

| Target | TTL | Scaling | Timestamps | SACK | MSS target |
| :--- | ---: | :---: | ---: | :---: | ---: |
| Windows11 | 128 | On | 0 | On | 1460 |
| MacOS | 64 | On | 1 | On | 1440 |
| LinuxDefault | 64 | On | 1 | On | Kernel-selected |

`LinuxDefault` is a reference baseline, not a runtime read of every distribution's defaults. A 65535-byte macOS SYN window is a reference target; these sysctls do not force an exact window size or TCP option layout.

Linux timestamp semantics are **0 disabled, 1 enabled with a per-connection random offset, 2 enabled without that offset**. See the [kernel IP sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html).

Browser/OS pairing is explicit metadata: Chrome/Windows, Firefox/Linux, Safari/macOS. `BrowserProfile::l4_profile()` returns the matching profile, and the same browser selection explicitly sets the platform in the TLS client's emulation configuration. A JA3/JA4 value alone does not uniquely identify an OS.

## Execution boundary

```text
Validated profile
    -> open /run/netns/wraith_ns
    -> reject host/current namespace device+inode
    -> retain the open namespace descriptor
    -> snapshot all requested settings
    -> nsenter subprocess: write and read back each setting
    -> success, or reverse rollback of attempted writes
```

Only the managed namespace name is accepted. Arbitrary paths, other namespace names and sysctl keys outside the per-network-namespace allowlist are rejected. The legacy host writer always returns `HostMutationForbidden`.

The parent holds one descriptor throughout all three tiers and rollback. Each subprocess enters it through `/proc/<parent-pid>/fd/<fd>`; it does not reopen a mutable namespace name. The Rust caller never calls `setns`, so Tokio worker threads retain their namespace. The implementation adds no unsafe Rust. `nsenter` from util-linux is a runtime dependency.

The normal trust boundary assumes an uncompromised kernel and trusted host administrator. A privileged adversary capable of altering the process or mount environment is outside this boundary.

## Failure policy and API

```rust,ignore
use wraith_core::tcp_fingerprint::TcpFingerprintProfile;
use wraith_net::tcp_stack::{
    apply_sysctl_profile, SysctlApplyOutcome, SysctlFailurePolicy,
};

let profile = TcpFingerprintProfile::windows11();
match apply_sysctl_profile("wraith_ns", &profile, SysctlFailurePolicy::FailClosed)? {
    SysctlApplyOutcome::Applied(snapshot) => {
        // Keep the snapshot for the existing session recovery mechanism.
    }
    SysctlApplyOutcome::Skipped { cause, .. } => {
        // Possible only with RestoreAndContinue. Never display this as active.
        tracing::warn!(%cause, "TCP profile was not applied");
    }
}
```

`FailClosed` propagates errors. `RestoreAndContinue` may return `Skipped` for eligible sysctl failures only when no writes occurred or rollback completed. Host/namespace guard failures and failed rollback always remain errors. Errors retain `thiserror` variants; application callers can add `anyhow::Context` without replacing the library's typed API.

This is a recoverable sequence, not a kernel-atomic multi-key transaction: intermediate values exist while it runs. The namespace should not accept application workloads until setup succeeds. A process crash cannot execute an in-memory rollback; the journal and durable ownership lease support later teardown. `wraith -x` and startup preflight validate ownership before cleanup. The panic sentry preserves restrictive policy and recovery records rather than promising synchronous teardown.

## CLI, MSS and route integration

`--morph-l4 auto|windows|windows11|macos|linux|off` replaces the displayed `--tcp-profile` name while retaining its aliases. Explicit `auto` enables a namespace and follows the session `--tls-profile chrome|firefox|safari` platform. Off preserves namespace isolation if requested but conflicts with full-security or `--tcp-mask`. Persisted settings live under `hardening.morph_l4` and `hardening.tls_profile`; explicit CLI values win.

The namespace creator applies `apply_profile_to_netns(..., true)` after creating the default route. `create_namespace_with_optional_l4_profile(None)` builds the same isolation without changing TCP parameters. Startup errors trigger owned-resource teardown, and cleanup errors remain visible for recovery.

Creation also persists a private namespace lease before veth/rule setup, tags both peers and host rules, and assigns an OS-CSPRNG local-unicast MAC to the namespace peer before either endpoint is UP. Teardown checks the namespace lifetime, boot, ownership tags, resolver contents and absence of namespace applications. Removing the owned namespace discards its TCP overrides; ambiguous legacy resources are refused. The lifecycle lock serializes CLI preflight and final cleanup.

`NetnsTcpSnapshot` and `RouteMetricSnapshot` zeroize on drop; snapshot maps wipe their owned keys and values. This does not replace the on-disk recovery record or run destructors after SIGKILL/abort. The ignored [native wire audit](../crates/wraith-net/tests/live_wire_syn_audit.rs) cross-compiles and can check a real Windows-profile SYN in a private Linux sandbox. Its controlled window-64240 fixture has not been executed in the recorded Windows-host validation.

1. Read the required route snapshot before sysctl mutation.
2. Apply and read back every requested sysctl.
3. Install an IPv4 SYN MSS cap with `iptables -w 5 -t mangle`, comment `wraith-l4`, and `TCPMSS --set-mss`. Check for existing ownership first, then verify with `-C`. On failure, remove any attempted rule and check again.
4. Change and read back `initcwnd` / `initrwnd`. Preserve recorded protocol, scope and source attributes. Reject unsupported route attributes or changed route identities instead of discarding them.
5. Persist the applied profile and original values only after all tiers succeed. In the library's non-strict mode, an eligible failure rolls back all tiers before returning a skipped snapshot. Failed rollback is always an error.

`initrwnd` influences the receive window and `initcwnd` controls the initial send congestion window, in segments; neither forces an exact SYN window byte count. See the [iproute2 route reference](https://github.com/iproute2/iproute2/blob/main/man/man8/ip-route.8.in).

## Inspect observations

`inspect_tcp_stack` opens the managed namespace, verifies its saved device/inode, reads requested sysctls, checks the owned MSS rule and reads route metrics. `wraith -i` displays those observations and compares them with the saved applied profile and route identity. Read errors and insufficient legacy data produce an unavailable status. A mismatch produces configuration drift; neither status is a captured p0f/JA3/JA4 measurement.

The new snapshot fields use serde defaults. Old untagged MSS rules remain removable through old snapshots; new rules use the ownership comment. Snapshots retain original sysctls and route metrics for rollback.

## Verification boundary

Tests cover profile parsing, old MSS serialization, numeric sysctl conversion, invalid inputs, host aliases, allowed namespace names, missing backups, failed writes and rollback. The local TLS test also checks the request's selected platform. No privileged live Linux network tests are run by these portable checks.

Namespace configuration alone cannot control the host Tor connection or a Tor exit's TCP stack. The separate [Tor access-link engine](L4-EGRESS-DESIGN.md) now applies UID-scoped TTL and SYN option/MSS normalization before Guard connections. Host TCP sysctls and shared Tor exits remain unchanged. Packet-level OS equivalence and same-flow SYN/ClientHello coherence still require live measurements.
