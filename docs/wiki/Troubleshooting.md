# Troubleshooting & recovery

> **06 / RECOVER** · Use the reported failure and recorded state to guide the next step.

## Start with the symptom

| Symptom | Check first | Next step |
| :--- | :--- | :--- |
| Strict startup is refused | The named host prerequisite or setup error | Review [advanced configuration](Advanced-Configuration.md) |
| Wi-Fi disconnects after a MAC change | Adapter association and DHCP | Restore/reassociate the selected interface |
| UDP or QUIC application fails | Whether it requires unsupported UDP transport | Check application TCP support |
| DNS returns SERVFAIL | Tor/DoH availability, system clock and DNSSEC proofs | Inspect the reported resolver failure |
| Fetch rejects a certificate | Hostname, certificate chain and clock | Correct the endpoint or trust problem; verification stays enabled |
| Fetch refuses an output file | Whether the target already exists | Choose a new output filename |
| Source update is refused | Origin, branch, dirty checkout or divergent history | Preserve local work; use a fresh clone if history was rewritten |
| Build fails | Rust and native compiler dependencies | Correct the dependency; source synchronization is a separate step |
| Cleanup is incomplete | The resource named in the error | Resolve the cause and retry the recorded cleanup |

## Retry cleanup

```bash
sudo wraith -x
```

Wraith retains recovery state when cleanup fails. Keep that state available, address the reported problem and retry. The panic handler restores terminal presentation while preserving restrictive policy; it does not reset firewall rules to unrestricted access or select public DNS.

## What gets restored

| Resource | Recorded recovery |
| :--- | :--- |
| IPv4 / IPv6 firewall | Saved tables after required host cleanup |
| Resolver and Tor configuration | Saved file content or original entry |
| MAC and hostname | Journaled values |
| Reversible sysctl settings | Previous values |
| Browser preferences | Managed block removed; unrelated preferences preserved |
| Font configuration | Saved entry / backup and cache refresh |
| Namespace and WireGuard | Recorded resource teardown |
| Traffic shaper | Owned netem handle `a731:` |

Snapshots do not capture every ACL/xattr, Tor working data or unrelated changes by other programs. Coordinate with other privileged firewall managers. Live Linux routing and kernel recovery still need integration validation.

## Report a reproducible issue

Include the command, distribution, selected interface, expected result, actual result and sanitized error output. Omit keys, passwords and tokens. File it in [GitHub Issues](https://github.com/ByGh00st/wraith/issues).

**Next:** [Architecture →](Architecture.md)

## Recovery details

Reset scripts delegate to the installed `wraith stop` implementation. They do not flush arbitrary firewall rules or invent fallback DNS. Without a recovery record they are a no-op; with a record but no executable they report an error.

A live legacy session without process-lifetime identity cannot be signaled automatically. Stop its original foreground worker with Ctrl+C, or its owning systemd service, then retry recovery. Do not delete the journal as a workaround.

TCP setup errors identify missing backups, readback differences or unsupported routes. Route restoration rejects a changed default-route identity rather than editing a replacement route. Old TCP snapshots without route metrics require namespace teardown for complete restoration.

## TCP foundation checks

- Missing `nsenter`: install the distribution's util-linux package and retry setup.
- Host alias or unmanaged namespace: use the namespace created by Wraith; arbitrary namespace paths are rejected.
- Unapproved sysctl or invalid profile value: correct the profile rather than bypassing validation.
- Namespace replaced during recovery: keep the recovery record and resolve ownership; the engine refuses to write into a different namespace lifetime.
- Unknown `--morph-l4`: update the source and rebuild/install the binary. `--tcp-profile` remains a compatible alias.
- `--morph-l4 off` conflicts with full-security or `--tcp-mask`: choose an explicit profile, or remove those enabling options. Use `--namespace --morph-l4 off` for isolation with untouched TCP defaults.
- L4 readback unavailable: run `sudo wraith -i`; inspect its error for a missing/replaced namespace, insufficient permissions or a legacy snapshot. Recover the old session before starting a new one.
- MSS rule readback or FIB setup failure: startup aborts and attempts rollback. Ensure iptables supports TCPMSS/comment and the namespace has its single managed default route. Do not insert duplicate `wraith-l4` rules.
- Unsupported route attributes: Wraith refuses a lossy FIB rewrite; recover and create a fresh managed namespace rather than deleting unrelated route metrics.
