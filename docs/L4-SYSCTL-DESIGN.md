# L4 profile and namespace sysctl design

This increment implements the profile model and namespace sysctl foundation (steps 1 and 2). It builds on the existing MSS, routing and session recovery code. It does not introduce the proposed `--morph-l4` option or change the inspect UI.

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

The parent holds the descriptor throughout the sysctl transaction. Each subprocess enters it through `/proc/<parent-pid>/fd/<fd>`; it does not reopen a mutable namespace name. The Rust caller never calls `setns`, so Tokio worker threads retain their namespace. The implementation adds no unsafe Rust. `nsenter` from util-linux is a runtime dependency.

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

This is a recoverable sequence, not a kernel-atomic multi-key transaction: intermediate values exist while it runs. The namespace should not accept application workloads until setup succeeds. A process crash cannot execute an in-memory rollback; the existing journaled namespace teardown is the recovery boundary. Further crash/panic integration belongs to step 3.

## Verification boundary

Tests cover profile parsing, old MSS serialization, numeric sysctl conversion, invalid inputs, host aliases, allowed namespace names, missing backups, failed writes and rollback. The local TLS test also checks the request's selected platform. No privileged live Linux network tests are run by these portable checks.

Namespace configuration cannot control the host Tor connection or a Tor exit's TCP stack. Packet-level OS equivalence and same-flow SYN/ClientHello coherence still require live measurements.
