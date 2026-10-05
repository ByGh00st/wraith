# Development and validation

> **08 / CONTRIBUTE** · Separate executed tests from unmeasured properties.

## Recorded checks — v1.5.4, 2026-10-05

On commit [`7f34a14`](https://github.com/ByGh00st/wraith/commit/7f34a14377323de05655864a54769d2e6e839244), the [kernel integration run](https://github.com/ByGh00st/wraith/actions/runs/37369837834), [distribution matrix](https://github.com/ByGh00st/wraith/actions/runs/37369837760), and [Debian package audit](https://github.com/ByGh00st/wraith/actions/runs/37369837719) completed successfully. The local workspace test run recorded 260 passed, 0 failed and 1 ignored; all-target Clippy passed with warnings denied. The release workflow separately builds and validates the four GNU/musl targets and package assets before publication.

| Check | Result |
| :--- | :--- |
| Workspace check, all targets | Passed on the v1.5.4 development checkout |
| Workspace tests | **260 passed, 0 failed, 1 ignored** |
| All-target Clippy | Passed with warnings denied |
| Kernel integration | Seven namespace scenarios and the native SYN audit passed in CI |
| Distribution matrix | Kali, Debian 12, Ubuntu 24.04, Arch and Alpine jobs passed |
| Debian package audit | Lintian and package purge/orphan checks passed |
| Release artifacts | GNU/musl x86_64 and ARM64 targets are built and checked by the release workflow |

Coverage includes local real TLS handshakes, certificate/hostname rejection, response limits, CONNECT framing, half-close responses, stalled writes, HTTP address-header removal, DNSSEC validation failures, state preservation, process-stat parsing, route-metric restoration, profile validation, legacy MSS-field compatibility, sysctl encoding, host-write rejection, namespace name/identity guards firewall construction, CLI auto/off and aliases, MSS ownership/readback/rollback, and live-telemetry drift detection. Additional regressions cover competing shortcuts, subcommand option scope, child argument boundaries, invalid configuration without data loss, legacy read-only loading, configuration path precedence, and background worker ownership. Installer shell syntax was checked without installing a service. Strict-preset regressions cover configuration/CLI parity, disabled defaults, the full L4/TLS compatibility matrix, refused activation on absent snapshots or failed readback, host prerequisite validation, legacy-state compatibility and unsupported packet capture. The local TLS exchange also checks the selected platform in HTTP headers.

Access-link regressions cover fixed SYN layouts and independently calculated checksums, extension/payload preservation, malformed and truncated packets, netlink framing and ACKs, queue ownership metadata, policy setup failures, activation boundaries and withheld firewall restoration after a failed Tor stop. The NFQUEUE engine uses the existing safe Rust netlink dependency. The new native wire audit adds Linux-only development dependencies on `socket2` and `etherparse`.

Hardening regressions cover sensitive-map replacement/clear/error/unwind drops, serialized map compatibility, state and TCP snapshot zeroization, redacted WireGuard keys, MAC bit layout and readback failures, refusal of unmarked/non-veth resources, reciprocal legacy veth ownership and configured L4↔L7 mismatches. Repeated actual orphan preflight is exercised by the ignored live test, not the portable suite.

Native GNU tests include Linux pidfd identity regressions. The privileged wire audit and NFQUEUE access-link normalization are verified live under an isolated network namespace sandbox in automated CI (`e2e-kernel-test.yml`). The final `cargo audit --deny warnings` scan passed for 351 locked dependencies after upgrading `rustls` to 0.23.45 for [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285). Advisory scanning checks reported vulnerabilities against the advisory database.

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

Follow the [release guide](https://github.com/ByGh00st/wraith/blob/main/docs/RELEASING.md) for version checks, native Debian packaging, musl builders and tag publication. The manual GitHub workflow builds artifacts without publishing a release. The [v1.5.4 release](https://github.com/ByGh00st/wraith/releases/tag/v1.5.4) uses the matching version tag and the same artifact validation steps.

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

In the v1.5.4 validation run, this audit and end-to-end network namespace kernel tests were verified live under an isolated network namespace sandbox in automated CI (`e2e-kernel-test.yml`). The test validates the host NFQUEUE worker, access-link normalization, MSS clamp invariants, and packet layout integrity under native Linux.

## Codebase Metrics (Tokei)

```text
===============================================================================
 Language            Files        Lines         Code     Comments       Blanks
===============================================================================
 Shell                  20         1644         1359          139          146
 TOML                   10          333          303            0           30
 YAML                  342        12543        12538            0            5
 Markdown               33         2630            0         1814          816
 Python                  3          276          247            5           24
-------------------------------------------------------------------------------
 Rust (6 Crates)        85        26959        23647          769         2543
===============================================================================
 Total                 499        44473        38179         2730         3564
===============================================================================
```

## Contributions

Describe a concrete trigger, expected behavior and observed result. Keep fixes scoped and include relevant checks. See [Issues](https://github.com/ByGh00st/wraith/issues), [Contributing](https://github.com/ByGh00st/wraith/blob/main/CONTRIBUTING.md) and the [security policy](https://github.com/ByGh00st/wraith/blob/main/SECURITY.md).

Documentation is stored in `docs/wiki/` and published to GitHub Wiki. Repository pages use `.md` links; wiki pages use extensionless names. Keep both copies synchronized.

## Responsible use and license

Use Wraith for privacy, learning, research and authorized administration. Obtain permission before assessing other systems and stay within scope. This guidance does not add restrictions to GPL-3.0. The project provides no anonymity, non-detection or destination-blocklist guarantee.
