# Getting started

> **01 / SETUP** · Install on your Linux host, then start and inspect a session.

## Requirements

The installed runtime targets **x86_64 Linux**, primarily Debian, Ubuntu, Kali and Parrot-style environments. Windows supports portable development tests, not privileged networking sessions.

| Component | Purpose |
| :--- | :--- |
| Rust 1.88 or newer | Build the locked workspace |
| C/C++, CMake, Perl, libclang and pkg-config | Build the native TLS dependencies |
| Tor with a dedicated non-root account | Tor transport |
| iptables/ip6tables and save/restore tools | Session policy and recovery |
| Kernel TTL/NFQUEUE and owner/comment support | Tor access-link L4 modes; no separate userspace queue library required |
| iproute2 | Interfaces, namespaces and optional shaping |
| util-linux (`nsenter`) | TCP settings through a pinned namespace descriptor |
| fontconfig | Font controls |

Install Rust under your ordinary account before using the helper. Optional WireGuard and virtual-display features also require their corresponding system tools.

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
cargo build --release --locked
sudo install -m 0755 target/release/wraith /usr/local/bin/wraith
wraith --version
wraith --help
```

</details>

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
