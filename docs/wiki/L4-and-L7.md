# L4 and L7: scope and verification

> **PROFILES** · TCP settings, TLS handshakes and measured fingerprints are different things.

## What applies where?

| Control | Application point | Boundary |
| :--- | :--- | :--- |
| TCP sysctl profile | Wraith application namespace | Does not reproduce every OS TCP option or ordering |
| SYN MSS rule | Namespace netfilter | Does not control Tor exit-node TCP |
| Initial window metrics | Namespace default route | Configuration is not a captured wire signature |
| Browser ClientHello | Wraith TLS client and its public API | Does not rewrite arbitrary tunneled HTTPS |
| HTTP normalization | Initial cleartext request through port 9055 | Later requests on a persistent stream are not reparsed |

```bash
sudo wraith start --namespace --tcp-profile windows11
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

The current CLI remains `--tcp-profile` with namespace setup. The proposed `--morph-l4` option and expanded inspect display are not implemented yet. This increment completes the profile/sysctl foundation, not those later CLI steps.

[Detailed design and API example](https://github.com/ByGh00st/wraith/blob/main/docs/L4-SYSCTL-DESIGN.md)

## Strict application and rollback

1. Capture original sysctl values and route metrics before mutation.
2. Write each requested sysctl and verify its readback.
3. Abort incomplete strict setup and attempt restoration, including the attempted setting.
4. Surface rollback errors instead of reporting success.
5. Require one unicast default route with a device; reject absent, ambiguous, multipath or unsupported locked metrics.
6. Restore saved `initcwnd` and `initrwnd` values and verify them, even when the namespace remains alive. Zero removes the explicit override in favor of the kernel default.

Route restoration refuses a changed route identity. Older snapshots without the original metrics require namespace teardown for full restoration. Session cleanup normally deletes its namespace; the explicit restore helper can also restore new snapshots without deletion.

## What remains unmeasured?

The host Tor daemon and remote Tor exit have separate TCP stacks. Namespace normalization does not control either stack. A matching reference profile does not prove that the SYN and ClientHello observed by a destination form a consistent browser/OS identity.

Portable tests inject missing backups, failed writes, rollback failures, readback differences and replaced routes. Linux-specific process and network code is cross-compiled. Live privileged Linux integration and a same-flow SYN/ClientHello capture have not been performed.

**Related:** [TLS and HTTP](TLS-and-HTTP.md) · [Development](Development.md)
