# Contributing to Wraith

Contributions to routing correctness, recovery, usability, documentation and reproducible tests are welcome. Start with the [wiki](https://github.com/ByGh00st/wraith/wiki) and [architecture](https://github.com/ByGh00st/wraith/wiki/Architecture).

**Suspected vulnerability? Follow [SECURITY.md](SECURITY.md) before opening a public issue or PR.**

## Choose a focused change

For a bug, describe the trigger, expected result and observed result. For a substantial feature, open a proposal explaining the use case and tradeoffs before undertaking a large implementation. Small fixes and documentation corrections can go directly to a pull request.

Keep unrelated refactors and generated-file churn out of the change. Preserve user configuration and the existing license.

## Development setup

Use stable Rust **1.88 or newer**. Native dependencies include C/C++ compilers, CMake, Perl, libclang and pkg-config for BoringSSL and ring. Build as an ordinary user.

```bash
git clone https://github.com/ByGh00st/wraith.git
cd wraith
cargo build --workspace --locked
```

Fork the repository if you do not have write access, and open your PR against `main`. Windows can run portable tests; the installed runtime targets x86_64 Linux. Cross-compilation requires the matching Rust target, native cross-compilers and headers.

## Validation appropriate to the change

Finish related edits before running a consolidated check. For Rust behavior changes:

```bash
cargo test --workspace --locked
cargo clippy --workspace --tests --target x86_64-unknown-linux-gnu --locked -- -D warnings
```

For dependency changes, also run `cargo audit --deny warnings` with cargo-audit installed. For shell changes, use `bash -n` on the affected scripts. For documentation-only changes, check links, examples and rendering; rerunning the whole Rust suite is unnecessary.

Format changed Rust code consistently without reformatting unrelated files. Include meaningful regressions for security or protocol changes, using local mock endpoints where possible. Clearly distinguish portable tests, cross-compilation and live Linux integration results.

Privileged integration tests belong on an authorized disposable Linux environment with a recovery path. Do not use your everyday network configuration as an implicit test fixture.

## Engineering expectations

- Keep certificate-chain and hostname verification enabled; never add a direct-network fallback to a Tor-only path.
- Record state before host mutations, propagate required failures and preserve retryable cleanup.
- Preserve unrelated firewall, resolver, browser and file settings. Avoid broad deletion, unconditional firewall flushes and root Cargo builds.
- Bound untrusted input, response sizes, concurrent work and network timeouts. Exclude secrets from logs.
- Document the actual scope of a protection. Do not describe metadata helpers, packet observations or incomplete features as enforced shields.
- Update relevant help, wiki guidance and dependency requirements when behavior changes.

## Pull requests

Explain the concrete problem, resulting behavior and validation. Include before/after screenshots for visual changes when practical. Disclose untested paths and material compatibility changes; do not label compilation as live runtime validation.

Contributions are distributed under the project's existing [GNU GPL v3.0 license](LICENSE). Submit only material you have the right to contribute and retain applicable third-party notices. There is no separate CLA specified by this guide.

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for collaboration expectations.
