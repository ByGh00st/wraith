# Development and validation

> **08 / CONTRIBUTE** · Separate executed tests from unmeasured properties.

## Recorded checks — 2026-09-21

Implementation baseline: [`3836e3b`](https://github.com/ByGh00st/wraith/commit/3836e3b).

| Check | Result |
| :--- | :--- |
| Portable workspace tests | **163 passed** |
| Linux-target production Clippy | Passed with warnings denied |
| Linux-target test compilation | Passed; Linux tests were not executed on the Windows host |
| Privileged live Linux networking | Not performed |
| Same-flow SYN and ClientHello capture | Not performed |
| Complete installed-system update | Not exercised |

Coverage includes local real TLS handshakes, certificate/hostname rejection, response limits, CONNECT framing, half-close responses, stalled writes, HTTP address-header removal, DNSSEC validation failures, state preservation, process-stat parsing, route-metric restoration and firewall construction.

Linux pidfd identity tests compile with the Linux target; that is not a claim that they ran on Linux. No new dependency audit was performed in this change.

## Reproduce

```bash
cargo test --workspace --locked
cargo check --workspace --tests --target x86_64-unknown-linux-gnu --locked
cargo clippy --workspace --target x86_64-unknown-linux-gnu --locked -- -D warnings
```

Cross-compilation needs the Linux Rust target, compatible C/C++ tools and headers, CMake, Perl and libclang. The Clippy result above covers production targets; pre-existing test lints are not included in that claim. Portable tests do not execute privileged Linux firewall operations.

## Contributions

Describe a concrete trigger, expected behavior and observed result. Keep fixes scoped and include relevant checks. See [Issues](https://github.com/ByGh00st/wraith/issues), [Contributing](https://github.com/ByGh00st/wraith/blob/main/CONTRIBUTING.md) and the [security policy](https://github.com/ByGh00st/wraith/blob/main/SECURITY.md).

Documentation is stored in `docs/wiki/` and published to GitHub Wiki. Repository pages use `.md` links; wiki pages use extensionless names. Keep both copies synchronized.

## Responsible use and license

Use Wraith for privacy, learning, research and authorized administration. Obtain permission before assessing other systems and stay within scope. This guidance does not add restrictions to GPL-3.0. The project provides no anonymity, non-detection or destination-blocklist guarantee.
