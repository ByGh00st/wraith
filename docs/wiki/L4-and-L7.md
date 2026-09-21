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
