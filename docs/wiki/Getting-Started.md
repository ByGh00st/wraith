# 🚀 GETTING STARTED WITH WRAITH

This guide details host prerequisites, compilation workflows, automated deployment, and initializing your first privileged privacy session.

---

## 💻 System Prerequisites

Wraith targets **Linux x86_64** systems (Debian, Kali Linux, Ubuntu, Arch Linux, Fedora).

| Component | Minimum Version | Purpose |
| :--- | :--- | :--- |
| **Linux Kernel** | 5.4+ | Netfilter hooks, Seccomp-BPF, network namespaces |
| **Rust Toolchain**| 1.75+ (Stable) | Compiling the workspace and cryptographic modules |
| **Tor** | 0.4.7+ | Transparent proxying, DNSPort, ControlPort |
| **iptables & iproute2** | Standard | Netfilter packet redirection and fail-closed killswitch |
| **Build Tools** | CMake, Perl, Clang, GCC | Required for compiling BoringSSL and TLS camouflage |

---

## 📦 Installation Methods

### Method 1: Automated System Deployment (Recommended)

The automated installer compiles the workspace without elevated root permissions, installs dependencies, places the binary in `/usr/local/bin/wraith`, and initializes system directories:

```bash
git clone https://github.com/ByGh00st/wraith.git
cd wraith
chmod +x build.sh
sudo ./build.sh
```

### Method 2: Manual Cargo Compilation

If you prefer building from source manually:

```bash
# 1. Install build dependencies on Debian/Ubuntu/Kali:
sudo apt update && sudo apt install -y tor iptables iproute2 build-essential cmake perl libclang-dev pkg-config

# 2. Compile optimized release binary:
cargo build --release --locked

# 3. Install binary to system PATH:
sudo install -m 0755 target/release/wraith /usr/local/bin/wraith

# 4. Verify installation:
wraith --version
wraith --help
```

### Method 3: Systemd Daemon Deployment

For permanent gateway operation that boots automatically:

```bash
# Interactive setup wizard
sudo ./install-daemon.sh

# Or non-interactive installation
sudo ./install-daemon.sh --non-interactive --boot-mode standard --profile stealth --doh quad9
```

---

## 🛡️ Your First Session in 3 Steps

### Step 1: Arm the Gateway
```bash
sudo wraith -s
```
*Wraith spins up an isolated Tor instance, redirects all TCP egress to port 9040, sets up local DNSSEC validation on port 5354, applies fail-closed netfilter DROP policies, and masks cleartext HTTP on port 9055.*

### Step 2: Inspect Active Telemetry
```bash
sudo wraith -i
```
*Displays your new public exit IP, geolocation, active Tor circuits, lock state, and network adapter.*

### Step 3: Clean Teardown
```bash
sudo wraith -x
```
*Gracefully terminates Tor, flushes netfilter tables, restores `/etc/resolv.conf`, and wipes temporary state.*
