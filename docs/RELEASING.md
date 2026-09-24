# Building and releasing Wraith

The workspace version is **1.4.2**. Manual CI runs validate artifacts; pushing the matching version tag triggers GitHub release publication.

## Build policy

Use stable Rust and `Cargo.lock`. The release profile selects `opt-level = 3`, `lto = "thin"`, `codegen-units = 16`, `panic = "abort"`, `strip = true` and `debug = false`. Cargo and CMake concurrency are capped at two:

```bash
CMAKE_BUILD_PARALLEL_LEVEL=2 cargo build --release --locked -j 2 -p wraith-cli
```

ThinLTO can reduce linking memory relative to fat LTO; the previous Wraith profile had LTO disabled, so this is not a measured reduction against that baseline. A generic Cargo exit 101 is not proof of OOM. Look for a killed compiler/linker and kernel OOM records. CI adds 4 GiB swap on each disposable runner and removes its own swap file on completion; neither this nor `-j 2` guarantees zero OOM failures.

Release panics abort: normal scope exits and ordinary errors run destructors, but a release panic does not unwind zeroizing buffers. Tests still unwind. Network recovery relies on durable ownership/state records and a subsequent explicit recovery attempt, not panic-time asynchronous cleanup.

## Artifact matrix

| Native target | Runner / builder | Artifacts |
| :--- | :--- | :--- |
| `x86_64-unknown-linux-gnu` | Ubuntu 22.04 | amd64 `.deb` + GNU archive |
| `aarch64-unknown-linux-gnu` | Ubuntu 22.04 ARM64 | arm64 `.deb` + GNU archive |
| `x86_64-unknown-linux-musl` | Native Alpine container on x86_64 | Static musl archive |
| `aarch64-unknown-linux-musl` | Native Alpine container on ARM64 | Static musl archive |

GNU binaries depend on compatible glibc/libstdc++ (current Debian metadata requires `libc6 >= 2.34`); cargo-deb discovers library dependencies and adds the declared runtime tools. Debian packages contain `/usr/bin/wraith` (0755) and documentation under `/usr/share/doc/wraith`. Each archive contains only `wraith`, `LICENSE` and `README.md`.

The Alpine compiler wrapper is confined to the container. Cargo is invoked with an explicit `--target`: host build scripts/procedural macros can load libclang dynamically, while target crates keep musl's static CRT default. Packaging rejects a musl executable with an ELF interpreter. Do not remove `--target` or reuse this wrapper for unrelated host builds.

## Validate a Debian package locally

On the matching GNU Linux architecture, install C/C++, CMake, Perl, libclang, pkg-config, OpenSSL development headers and dpkg-dev. Build as an ordinary user:

```bash
cargo install cargo-deb --version 3.8.0 --locked -j 2
target=$(rustc -vV | sed -n 's/^host: //p')
export CMAKE_BUILD_PARALLEL_LEVEL=2 CARGO_BUILD_JOBS=2
cargo build --release --locked -j 2 -p wraith-cli --target "$target"
bash scripts/package-release.sh "$target"
```

The script checks resolved workspace/internal dependency versions, packages with `cargo deb --no-build --no-strip`, verifies package name/version/architecture, extracts the binary and documentation, checks permissions and executes `--version`. It asks APT to **simulate** dependency resolution without installing the package. Output goes to `dist/`.

`cargo-deb 3.8.0` does **not** implement `--dry-run`. Use the real packaging validation above. `install.sh --dry-run` is a separate installer preview that downloads and validates published assets without executing them or changing system files.

## Validate and publish

1. Update `[workspace.package].version`, internal dependency constraints and `Cargo.lock`; all six crates inherit the workspace version. Update documentation and the changelog, including the pending-release notices in the README and wiki when publication is intended.
2. Run the relevant checks together:

   ```bash
   cargo check --workspace --all-targets --locked
   cargo test --workspace --locked
   cargo clippy --workspace --all-targets --locked -- -D warnings
   bash -n build.sh install.sh scripts/package-release.sh .github/musl-rustc-wrapper.sh
   python3 scripts/test-install.py
   ```

3. Push the reviewed commit and run `gh workflow run release.yml --ref main`. This builds native packages on all four targets and retains CI artifacts for seven days. It does not publish. Inspect every build result; the privileged wire audit remains ignored.
4. When publication is intended, create and push the matching tag from the reviewed commit:

   ```bash
   git tag -a v1.4.2 -m "Wraith v1.4.2"
   git push origin v1.4.2
   ```

5. The tag run refuses a workspace/tag mismatch, requires both Debian packages and all four archives, generates `SHA256SUMS.txt`, uploads all seven files to a draft release, then publishes it as latest. Partial builds do not publish. An upload failure can leave a draft for inspection/retry.

Pinned GitHub Actions implement checkout, artifact transfer and `softprops/action-gh-release@v2`. The Rust channel and Linux package repositories remain moving inputs; this is not a bit-for-bit reproducibility claim. Archive metadata is normalized to the commit timestamp and root ownership.

The installer selects only stable releases with the exact expected asset names and official repository URLs. Checksums detect corruption/mismatches but share GitHub's release trust boundary. The separate `apt-repository.yml` workflow downloads only a published stable release, verifies its checksums, generates APT indexes and signs `InRelease` with the archive key held in the `WRAITH_APT_SIGNING_KEY` Actions secret. It publishes the repository through GitHub Pages and refreshes `Valid-Until` monthly. The public key fingerprint is stored in `packaging/apt/signing-key-fingerprint.txt`; key rotation requires publishing a transition before replacing that value. The `-u` CLI operation continues to update source checkouts only.
