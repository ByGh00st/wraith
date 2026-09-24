# Getting started

> **01 / SETUP** · Install on your Linux host, then start and inspect a session.

## Requirements

The installed runtime targets **x86_64 and ARM64 Linux**, primarily Debian, Ubuntu, Kali and Parrot-style environments. Windows supports portable development tests, not privileged networking sessions.

| Component | Purpose |
| :--- | :--- |
| Bash, curl and Python 3.8+ | Download and verify release packages |
| Rust 1.88 or newer (source builds only) | Build the locked workspace |
| C/C++, CMake, Perl, libclang and pkg-config | Build the native TLS dependencies |
| Tor with a dedicated non-root account | Tor transport |
| iptables/ip6tables and save/restore tools | Session policy and recovery |
| Kernel TTL/NFQUEUE and owner/comment support | Tor access-link L4 modes; no separate userspace queue library required |
| iproute2 | Interfaces, namespaces and optional shaping |
| util-linux (`nsenter`) | TCP settings through a pinned namespace descriptor |
| fontconfig | Font controls |

Install Rust under your ordinary account before using the helper. Optional WireGuard and virtual-display features also require their corresponding system tools.

## Install an official release

Get the packages and checksums from the **[v1.4.3 release](https://github.com/ByGh00st/wraith/releases/tag/v1.4.3)**, configure the signed APT repository once, or let the installer select the latest stable version for your system.

For Debian, Ubuntu and Kali, add the signed repository once and then use normal APT commands:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://bygh00st.github.io/wraith/wraith-archive-keyring.asc | sudo tee /etc/apt/keyrings/wraith.asc >/dev/null
echo 'deb [signed-by=/etc/apt/keyrings/wraith.asc] https://bygh00st.github.io/wraith stable main' | sudo tee /etc/apt/sources.list.d/wraith.list >/dev/null
sudo apt update
sudo apt install wraith
```

Verify the key's fingerprint before trusting it: `8B71 B4C4 22EF 0171 6338 4556 5D6B 16E4 201C 32FB`. Later releases arrive through `sudo apt upgrade`.

```bash
curl -fsSL https://raw.githubusercontent.com/ByGh00st/wraith/main/install.sh | sudo bash
wraith --version
```

| Platform | Installation | Global command path |
| :--- | :--- | :--- |
| Debian/Ubuntu/Kali with glibc | Architecture-matched `.deb` through APT | `/usr/bin/wraith` |
| Other glibc distributions | GNU archive | `/usr/local/bin/wraith` |
| Alpine/musl | Static musl archive | `/usr/local/bin/wraith` |

Both x86_64 and ARM64 are selected automatically. The installer requires Bash, curl and Python 3.8+ (`apk add bash curl python3` on Alpine). When already root, replace `sudo bash` with `bash`. It verifies SHA-256, package identity or archive/ELF structure, and the installed version. Archives do not install Tor, Netfilter or other runtime tools; install those through your distribution. GNU artifacts are built on Ubuntu 22.04 and need compatible glibc/libstdc++ versions. The current Debian packages require `libc6 >= 2.34`; older systems can build from source.

Manual Debian installation for v1.4.3:

```bash
wget https://github.com/ByGh00st/wraith/releases/download/v1.4.3/wraith_1.4.3_amd64.deb
wget https://github.com/ByGh00st/wraith/releases/download/v1.4.3/SHA256SUMS.txt
sha256sum --ignore-missing --check SHA256SUMS.txt
sudo apt install ./wraith_1.4.3_amd64.deb
wraith --version
```

Use `arm64` in the filename on ARM64. APT owns the installed package. The signed Wraith repository above enables `apt install wraith` and upgrades after its one-time setup. To remove the APT package, complete `sudo wraith -x` first, then run `sudo apt remove wraith`. `wraith -u` only updates a source checkout.

For an installation preview, download `install.sh`, inspect it, then run `bash install.sh --dry-run`. This fetches and validates the assets without executing the binary or changing system files. Checksums use the same GitHub trust boundary as the release. A PATH conflict is reported rather than silently deleting a previous installation; inspect `type -a wraith` if necessary.

## Install from the official repository

```bash
git clone https://github.com/ByGh00st/wraith.git
cd wraith
chmod +x build.sh
sudo ./build.sh
```

The helper installs Debian-family packages, builds as the invoking user with `Cargo.lock`, and installs `/usr/local/bin/wraith` after success. Run it through sudo from the account that owns the Rust toolchain; direct root Cargo builds are refused. Stop an old session before upgrading when practical.

<details>
<summary><b>Prefer a manual build?</b></summary>

Install the required system dependencies, then build as your ordinary account:

```bash
CMAKE_BUILD_PARALLEL_LEVEL=2 cargo build --release --locked -j 2
sudo install -m 0755 target/release/wraith /usr/local/bin/wraith
wraith --version
wraith --help
```

</details>

Release builds use ThinLTO, 16 codegen units, stripped symbols, no debug information and `panic = "abort"`. `build.sh` limits Cargo and CMake concurrency to two. Use `cargo build --release -j 2` on low-memory machines; this is a mitigation, not a zero-OOM guarantee. See [build diagnostics](Troubleshooting.md#build-and-package-diagnostics) and the [release procedure](https://github.com/ByGh00st/wraith/blob/main/docs/RELEASING.md).

## Your first session

```bash
sudo wraith -s
```

Ordinary start runs a background worker. Inspect or stop it with:

```bash
sudo wraith -i     # Inspect status
sudo wraith -x     # Stop and restore recorded settings
```

Strict and interactive sessions stay in the foreground; Ctrl+C there also requests cleanup. If cleanup reports an error, follow [the recovery guide](Troubleshooting.md) before starting another session.

**Next:** [Daily workflow →](Daily-Workflow.md)
