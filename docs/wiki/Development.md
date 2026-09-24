# Development and validation

> **08 / CONTRIBUTE** · Separate executed tests from unmeasured properties.

## Recorded checks — 2026-09-24

Release-preparation baseline: [`1cee183`](https://github.com/ByGh00st/wraith/commit/1cee183). The [native build matrix](https://github.com/ByGh00st/wraith/actions/runs/35992818793) passed on all four x86_64/ARM64 GNU/musl targets and produced two Debian packages plus four archives. Manual validation skipped release publication.

| Check | Result |
| :--- | :--- |
| Workspace check, all targets | Passed on Windows and both native GNU Linux architectures |
| Windows workspace tests | **238 passed, 0 failed, 1 ignored** |
| Native GNU Linux tests, x86_64 and ARM64 | **240 passed on each, 0 failed, 1 ignored** |
| Windows all-target Clippy | Passed with warnings denied |
| GNU Linux all-target Clippy | Passed natively on both architectures and by cross-compilation; warnings denied |
| Installer preview regressions | 14 platform/failure scenarios passed on Windows and Ubuntu; no installation |
| Native Debian packages | Both architectures built; extraction, identity, permissions, version and APT simulation passed |
| Static musl archives, x86_64 and ARM64 | Native builds, `--version` / `--help` and no-interpreter ELF checks passed |
| Dependency audit | Passed with warnings denied; 351 locked dependencies |
| Native Linux SYN audit | Compiled; ignored and not executed |
| Privileged live Linux networking | Not performed |
| Same-flow SYN and ClientHello capture | Not performed |
| Complete installed-system update | Not exercised |

Coverage includes local real TLS handshakes, certificate/hostname rejection, response limits, CONNECT framing, half-close responses, stalled writes, HTTP address-header removal, DNSSEC validation failures, state preservation, process-stat parsing, route-metric restoration, profile validation, legacy MSS-field compatibility, sysctl encoding, host-write rejection, namespace name/identity guards firewall construction, CLI auto/off and aliases, MSS ownership/readback/rollback, and live-telemetry drift detection. Additional regressions cover competing shortcuts, subcommand option scope, child argument boundaries, invalid configuration without data loss, legacy read-only loading, configuration path precedence, and background worker ownership. Installer shell syntax was checked without installing a service. Strict-preset regressions cover configuration/CLI parity, disabled defaults, the full L4/TLS compatibility matrix, refused activation on absent snapshots or failed readback, host prerequisite validation, legacy-state compatibility and unsupported packet capture. The local TLS exchange also checks the selected platform in HTTP headers.

Access-link regressions cover fixed SYN layouts and independently calculated checksums, extension/payload preservation, malformed and truncated packets, netlink framing and ACKs, queue ownership metadata, policy setup failures, activation boundaries and withheld firewall restoration after a failed Tor stop. The NFQUEUE engine uses the existing safe Rust netlink dependency. The new native wire audit adds Linux-only development dependencies on `socket2` and `etherparse`.

Hardening regressions cover sensitive-map replacement/clear/error/unwind drops, serialized map compatibility, state and TCP snapshot zeroization, redacted WireGuard keys, MAC bit layout and readback failures, refusal of unmarked/non-veth resources, reciprocal legacy veth ownership and configured L4↔L7 mismatches. Repeated actual orphan preflight is exercised by the ignored live test, not the portable suite.

Native GNU tests include Linux pidfd identity regressions. NFQUEUE protocol/unit checks ran; the privileged queue worker and wire audit were not exercised live. Live Guard connectivity, PMTU/retransmission behavior and p0f captures remain unmeasured. The final `cargo audit --deny warnings` scan passed for 351 locked dependencies after upgrading `rustls` to 0.23.45 for [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285). Advisory scanning does not establish absence of all defects.

## Reproduce

```bash
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo audit --deny warnings
# Cross-check Linux-specific production and test code:
cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu --locked -- -D warnings
```

Cross-compilation needs the Linux Rust target, compatible C/C++ tools and headers, CMake, Perl and libclang. All-target Clippy includes test targets; the earlier test-module-order warnings have been corrected. Portable tests do not execute privileged Linux firewall operations.

## Release packaging

Follow the [release guide](https://github.com/ByGh00st/wraith/blob/main/docs/RELEASING.md) for version checks, native Debian packaging, musl builders and tag publication. The manual GitHub workflow builds artifacts without publishing a release. The [v1.4.2 release](https://github.com/ByGh00st/wraith/releases/tag/v1.4.2) uses the matching version tag and the same artifact validation steps.

```bash
bash -n install.sh build.sh scripts/package-release.sh .github/musl-rustc-wrapper.sh
python3 scripts/test-install.py
```

The 14 installer scenarios exercise CPU/libc selection and rejection of checksum mismatches, duplicate/missing/foreign-origin assets, prereleases, wrong ELF architecture, archive links and path traversal. They use synthetic fixtures and do not establish successful APT installation. Actual Debian packaging is checked separately by cargo-deb, extraction and APT dependency simulation.

`cargo-deb 3.8.0` rejects `--dry-run`; the supported validation path compiles first and uses `--no-build --no-strip` through `scripts/package-release.sh`. The download-only `install.sh --dry-run` is a different feature.

Release builds use `panic = "abort"`; unit tests use unwinding. Successful unwind-drop tests cover that test execution mode, not destructor execution after release panics.

## Native Linux wire audit

```bash
sudo -E cargo test -p wraith-net --test live_wire_syn_audit -- --ignored --nocapture
```

The [`live_wire_syn_audit.rs`](https://github.com/ByGh00st/wraith/blob/main/crates/wraith-net/tests/live_wire_syn_audit.rs) integration test is intentionally `#[ignore]`. Run it on Linux with build dependencies, util-linux (`unshare`, `mount`, `nsenter`), iproute2, iptables/ip6tables and their save tools. The kernel must support namespaces, veth and the required Netfilter targets. It needs root with network administration, raw socket and mount-namespace privileges; a restricted container can still refuse it.

| Phase | What it checks |
| :--- | :--- |
| Isolation | Re-execute under private mount/network namespaces; verify their identities differ from the parent |
| Filesystem scope | Privately bind `/etc`, `/run` and `/var/lib` so fixed Wraith paths do not reach the host |
| Production setup | Apply the same Windows profile as `--morph-l4 windows`, with owned namespace, MAC, MSS rule and FIB metrics |
| Native capture | Use `socket2` AF_PACKET and `etherparse` on the private host-side veth |
| SYN invariants | TTL 128, SYN without ACK, MSS 1460, no timestamps, window 64240 and the expected local-unicast source MAC |
| Cleanup | Teardown and run orphan preflight twice |

The trigger is a nonblocking TCP connect to the benchmark range `198.18.0.1:443` inside the isolated namespace. It never uses a real external route. A bounded capture waits for the initial SYN. Window 64240 is a controlled MTU 1500 / MSS 1460 / adequate receive-buffer / `initrwnd 44` fixture; a different kernel result fails the audit rather than being labeled a native Windows signature.

This audit has **not been run live** in the recorded checks. It does not validate the host NFQUEUE worker, Guard connectivity, real-path PMTU/retransmission behavior or a same-flow SYN/ClientHello identity. Packet-capture success would establish only the listed fixture invariants.

## Contributions

Describe a concrete trigger, expected behavior and observed result. Keep fixes scoped and include relevant checks. See [Issues](https://github.com/ByGh00st/wraith/issues), [Contributing](https://github.com/ByGh00st/wraith/blob/main/CONTRIBUTING.md) and the [security policy](https://github.com/ByGh00st/wraith/blob/main/SECURITY.md).

Documentation is stored in `docs/wiki/` and published to GitHub Wiki. Repository pages use `.md` links; wiki pages use extensionless names. Keep both copies synchronized.

## Responsible use and license

Use Wraith for privacy, learning, research and authorized administration. Obtain permission before assessing other systems and stay within scope. This guidance does not add restrictions to GPL-3.0. The project provides no anonymity, non-detection or destination-blocklist guarantee.
