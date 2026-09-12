# GETTING STARTED // DEPLOYMENT & INITIALIZATION

Operational deployment guide, compiler dependencies, runtime prerequisites, and session initialization protocols for Wraith.

---

## 1. System Requirements & Prerequisites

Wraith is designed and verified for **Linux x86_64** platforms (Debian GNU/Linux, Kali Linux, Ubuntu LTS, Arch Linux, Fedora).

| Component | Minimum Version | Purpose |
| :--- | :--- | :--- |
| **Linux Kernel** | 5.4+ (LTS) | Netfilter packet redirection, Seccomp-BPF filtering, network namespaces (`CLONE_NEWNET`) |
| **Rust Toolchain** | 1.88+ (Stable) | Workspace compilation, type verification, dependency lockfile resolution |
| **Tor Daemon** | 0.4.7+ | Local transparent proxy transport (`TransPort 9040`), `DNSPort`, `ControlPort 9051` |
| **Networking Utilities** | iproute2, iptables | Packet filtering, policy routing, interface manipulation, journaled rule restoration |
| **C/C++ Toolchain** | Clang/GCC, CMake, Perl | Compilation of native cryptographic libraries (BoringSSL via `btls-sys`) |

---

## 2. Installation Procedures

### Method 1: Automated Deployment (`build.sh`)

The provided deployment script compiles the workspace with user-level privileges, installs distribution dependencies, deploys the binary to `/usr/local/bin/wraith`, and verifies file permissions:

```bash
git clone https://github.com/ByGh00st/wraith.git
cd wraith
chmod +x build.sh
sudo ./build.sh
```

### Method 2: Manual Source Compilation

For production environments requiring manual provenance and build verification:

```bash
# 1. Install distribution dependencies (Debian/Kali/Ubuntu):
sudo apt update && sudo apt install -y tor iptables iproute2 build-essential cmake perl libclang-dev pkg-config

# 2. Compile release binary against locked dependencies:
cargo build --release --locked

# 3. Deploy binary to system path with standard root execution privileges:
sudo install -m 0755 target/release/wraith /usr/local/bin/wraith

# 4. Verify installation and compiler metadata:
wraith --version
wraith --help
```

### Method 3: Systemd Daemon Deployment

To run Wraith as an unmanaged system service bound to network availability:

```bash
# Interactive configuration wizard:
sudo ./install-daemon.sh

# Non-interactive automated deployment:
sudo ./install-daemon.sh --non-interactive --boot-mode standard --profile stealth --doh quad9
```

> [!NOTE]
> Daemon deployment configures `wraith.service` with dependency on `network-online.target`. It does not claim or provide early-boot network isolation prior to network interface initialization.

---

## 3. Session Lifecycle Management

### Phase 1: Initialize Session
```bash
sudo wraith -s
```
*Executes the following operations sequentially:*
1. Spawns an isolated Tor instance or attaches to an authenticated local control port.
2. Configures netfilter rules: redirects outbound TCP to `127.0.0.1:9040` (Tor TransPort) and DNS to `127.0.0.1:5354` (Hickory DoH/DNSSEC relay).
3. Binds in-flight HTTP header relay to `127.0.0.1:9055` for port 80 sanitization.
4. Enforces default `DROP` policies on `OUTPUT`, `FORWARD`, and IPv6 chains.

### Phase 2: Inspect Telemetry & Route
```bash
sudo wraith -i
```
*Queries the local Tor ControlPort (`127.0.0.1:9051`) and verification endpoints to report current exit node IP, geographical jurisdiction, circuit relay hops, and lockfile state.*

### Phase 3: Terminate Session & Restore Host
```bash
sudo wraith -x
```
*Restores pre-session state deterministically:*
1. Flushes session netfilter chains and restores original iptables/ip6tables rules from saved journals.
2. Restores `/etc/resolv.conf` to original configuration or symlink target.
3. Re-enables standard IPv6 egress policies if previously active.
4. Removes ephemeral lockfiles, in-memory vault allocations, and process state.
