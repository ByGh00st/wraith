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
| Namespace still contains processes | Applications launched through `wraith exec` | Close them, then retry `sudo wraith -x` |
| Ownership is ambiguous | Namespace lifetime, veth alias, lease or chain conflict | Preserve the evidence; do not flush tables or delete links by prefix |

## Build and package diagnostics

| Failure | Check / action |
| :--- | :--- |
| Cargo exits with 101 | Read the first compiler/build-script error; 101 alone does not identify OOM. |
| `signal: 9, SIGKILL` / linker killed | Check `journalctl -k` or `dmesg` for OOM evidence. Close memory-heavy jobs or use a larger builder; limit Cargo and CMake jobs to two. |
| `libclang` cannot load on Alpine | Native bindgen build scripts must support dynamic loading. Use the documented musl builder; the final release binary remains static. |
| `cargo deb --dry-run` rejected | cargo-deb 3.8.0 does not provide this flag. Build first, then run the package-validation script. |
| Latest release lacks matching assets | Use the source installer until a complete release is published; do not substitute another CPU/libc binary. |
| APT refuses a dependency | Check distribution/library compatibility. Do not force-install the package while skipping dependencies. |
| Version check reports PATH conflict | Run `type -a wraith`; explicitly reconcile an earlier `/usr/local/bin` install with the APT-owned `/usr/bin/wraith`. |
| SHA-256, metadata or archive validation fails | Installation is refused. Check the selected official release and download again; do not bypass verification. |

```bash
CMAKE_BUILD_PARALLEL_LEVEL=2 cargo build --release --locked -j 2 -p wraith-cli
```

The release workflow adds 4 GiB of swap on disposable GitHub runners. This reduces memory pressure; it does not guarantee zero OOM failures or modify the user's swap configuration. The repository previously had LTO disabled, so ThinLTO must not be described as a measured RAM improvement over that baseline.

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

Reset scripts delegate to the installed `wraith stop` implementation when recorded recovery is available. They do not flush arbitrary firewall rules or invent fallback DNS. `wraith stop` also checks durable owned network leases when the main session journal is absent; with neither a journal nor leases, it changes nothing. Script-level missing-record handling remains separate from this CLI preflight.

A live legacy session without process-lifetime identity cannot be signaled automatically. Stop its original foreground worker with Ctrl+C, or its owning systemd service, then retry recovery. Do not delete the journal as a workaround.

TCP setup errors identify missing backups, readback differences or unsupported routes. Route restoration rejects a changed default-route identity rather than editing a replacement route. Old TCP snapshots without route metrics require namespace teardown for complete restoration.

## Automatic orphan preflight

New starts first recover a dead recorded session, then run ownership-checked orphan cleanup under the lifecycle lock. Leases live in `/var/lib/wraith/netns-owner.json` and `egress-owner.json`; keep them while resolving a failure. Namespace ownership includes the boot ID, namespace device/inode and matching random veth/rule tags.

| Reported condition | Expected behavior |
| :--- | :--- |
| Owned namespace and links, no applications inside | Remove scoped resources; repeat cleanup is safe |
| Namespace replaced or old-boot lease points at current objects | Refuse deletion; current object ownership needs resolution |
| Unmarked `veth_wraith*`, unknown egress rule or unexpected resolver entry | Refuse deletion; a name match is insufficient |
| Another lifecycle operation is running | Retry after that operation finishes |
| Managed Tor or namespace cannot stop | Keep firewall enforcement and recovery state |

A reboot may discard `/var/run/wraith.state`; network ownership leases do not restore every prior host setting. SIGKILL also prevents in-memory destructors from running. Neither event can be described as guaranteed clean shutdown or guaranteed memory erasure.

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

## Tor access-link L4 checks

| Symptom | Meaning / action |
| :--- | :--- |
| Queue bind or TTL/NFQUEUE setup fails | Verify kernel Netfilter support and permissions. L4 startup fails instead of silently using unmodified SYNs. |
| Queue 41884 or owned chain already exists | Recover the previous Wraith session; do not delete another process's queue or firewall rules. |
| `-i` reports an unavailable queue | New SYNs remain blocked if the queue rule is present. Stop/recover before starting a fresh session. |
| Drop counters rise | Kernel queue saturation or netlink delivery loss; these counters do not establish successful handshakes. |
| Tor cannot be stopped during recovery | Firewall restoration is withheld. Retain the journal, resolve the managed-process failure and retry `sudo wraith -x`. |
| `L4↔L7 configured pairing` reports `ANOMALY` | Recorded TLS, namespace L4 and Tor egress reference platforms differ. Restart with a matching selection; this alert is not a captured JA3/JA4 result. |
| Namespace MAC reports `DRIFT` | The live address or ownership alias differs from its lease; recover the session and resolve the writer that changed it. |
| A remote website still sees another TCP stack | Expected: the shared Tor exit opens that connection. Local access-link normalization targets the ISP/Guard path. |

Native window/scale, IP ID behavior, TCP timing and Tor's outer TLS are preserved. UDP bridge paths and outer WireGuard packets are outside this TCP rewriting scope. See [L4 and L7](L4-and-L7.md) for field-level behavior.

## CLI and configuration errors

- **Choose one operation:** run status, update, cleanup and start as separate invocations. Use `start -F`, not `-F start`.
- **Interactive selection requires a terminal:** keep selection in the foreground or supply explicit interface/DoH values to the daemon.
- **Unknown configuration field / invalid TOML:** repair the named file. Failed loads do not overwrite it with defaults; stop/recovery remains available independently of startup configuration.
- **Unknown bridge transport:** supported launch transports are obfs4, snowflake and meek-azure; `moat` selects discovery. WebTunnel is not implemented.
- **Rotation interval out of range:** use 1..4294967295 seconds, or omit it. Only the service installer treats 0 as disabled.
- **Missing shred target / invalid pass count:** the command returns an error; it does not report successful deletion.
