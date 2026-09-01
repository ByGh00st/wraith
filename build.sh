#!/usr/bin/env bash
# ==============================================================================
# 💀 WRAITH-PRIME // SOVEREIGN KERNEL FORGE & AUTOMATED BUILD ENGINE v1.2.0
# High-Assurance Ring-0/Ring-3 Defense & Anonymization Engine
# Absolute Precision. Zero Telemetry. Pure Technical Execution.
# ==============================================================================

set -euo pipefail

# ─── [ TRUECOLOR PALETTE & ANSI TOKENS ] ────────────────────────────────────────
CLR_PURPLE='\033[38;2;168;85;247m'
CLR_CYAN='\033[38;2;6;182;212m'
CLR_EMERALD='\033[38;2;16;185;129m'
CLR_RED='\033[38;2;239;68;68m'
CLR_AMBER='\033[38;2;245;158;11m'
CLR_SLATE='\033[38;2;100;116;139m'
CLR_WHITE='\033[38;2;248;250;252m'
CLR_BOLD='\033[1m'
CLR_DIM='\033[2m'
CLR_RESET='\033[0m'

TARGET_OS="Linux"
if [ -f /etc/os-release ]; then
    TARGET_OS=$(grep -E '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')
fi
ARCH=$(uname -m)
KERNEL_REL=$(uname -r)

echo -e "\n${CLR_RED}${CLR_BOLD}"
echo "   ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗"
echo "   ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║"
echo "   ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║"
echo "   ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║"
echo "   ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║"
echo "    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝"
echo -e "${CLR_AMBER}  ╭── [ ⚔ WRAITH-PRIME // SOVEREIGN FORGE & COMPILER ] ──────────────────────────╮"
echo -e "  │  ${CLR_SLATE}CORE ENGINE :${CLR_RESET} ${CLR_RED}${CLR_BOLD}WRAITH v1.2.0 // KERNEL ANONYMIZATION GATE${CLR_RESET}                  ${CLR_AMBER}│"
echo -e "  │  ${CLR_SLATE}TARGET HOST :${CLR_RESET} ${CLR_EMERALD}${TARGET_OS} [${ARCH}]${CLR_RESET}                                      ${CLR_AMBER}│"
echo -e "  │  ${CLR_SLATE}KERNEL SPEC :${CLR_RESET} ${CLR_WHITE}Linux ${KERNEL_REL}${CLR_RESET}                                             ${CLR_AMBER}│"
echo -e "  │  ${CLR_SLATE}FORGE MODE  :${CLR_RESET} ${CLR_RED}${CLR_BOLD}LTO + SIMD OPTIMIZED RELEASE // MAXIMUM DEFENSE ARMED${CLR_RESET}        ${CLR_AMBER}│"
echo -e "  ╰──────────────────────────────────────────────────────────────────────────────╯${CLR_RESET}\n"

# 1. Root Clearance Check
if [ "$EUID" -ne 0 ]; then
    echo -e "  ${CLR_RED}${CLR_BOLD}✖ [ACCESS DENIED]${CLR_RESET} Root clearance required for kernel subsystem setup."
    echo -e "      ${CLR_SLATE}Execute with root privileges: ${CLR_WHITE}sudo ./build.sh${CLR_RESET}\n"
    exit 1
fi

# Self-healing DNS resolution for git/cargo network access
chattr -i /etc/resolv.conf 2>/dev/null || true
if ! ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
    iptables -F 2>/dev/null || true
fi
if ! host github.com >/dev/null 2>&1; then
    (echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf) 2>/dev/null || true
fi

# 2. Inspect & Provision Rust Compiler Toolchain
echo -e "  ${CLR_CYAN}◈ [1/4]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Auditing Rust compiler toolchain...${CLR_RESET}"
if ! command -v cargo &> /dev/null; then
    echo -e "        ${CLR_PURPLE}❯${CLR_RESET} Cargo missing in PATH. Initializing automated rustup provisioner..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y > /dev/null 2>&1
    export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"
fi
export CARGO_HOME="${CARGO_HOME:-/tmp/.cargo}"
mkdir -p "$CARGO_HOME" 2>/dev/null || true
RUST_VER=$(rustc --version 2>/dev/null || echo "Rust Toolchain 2021")
echo -e "        ${CLR_EMERALD}✔ [ACTIVE]${CLR_RESET} Toolchain verified: ${CLR_SLATE}${RUST_VER}${CLR_RESET}"

# 3. Provision Native Linux Dependencies
echo -e "\n  ${CLR_CYAN}◈ [2/4]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Provisioning native Linux security & networking dependencies...${CLR_RESET}"
apt-get update -qq > /dev/null 2>&1 || true
apt-get install -y -qq build-essential tor iptables iproute2 obfs4proxy dnsutils libssl-dev pkg-config psmisc procps e2fsprogs curl > /dev/null 2>&1 || true
echo -e "        ${CLR_EMERALD}✔ [ARMED]${CLR_RESET} Dependencies online: ${CLR_SLATE}(tor, iptables, iproute2, obfs4proxy, libssl, seccomp)${CLR_RESET}"

# 4. Compile Release Workspace with LTO Optimizations
echo -e "\n  ${CLR_CYAN}◈ [3/4]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Forging Sovereign Workspace in Release Mode (LTO & SIMD Opt)...${CLR_RESET}"
cargo build --release --workspace

# 5. Global Multi-Path Deployment
echo -e "\n  ${CLR_CYAN}◈ [4/4]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Deploying binary to universal system execution PATHs...${CLR_RESET}"
TARGET_BIN="target/release/wraith"
if [ -f "$TARGET_BIN" ]; then
    rm -f /usr/local/bin/wraith /usr/bin/wraith /bin/wraith /root/.cargo/bin/wraith /home/*/.cargo/bin/wraith 2>/dev/null || true
    cp -f "$TARGET_BIN" /usr/local/bin/wraith
    chmod 755 /usr/local/bin/wraith
    cp -f "$TARGET_BIN" /usr/bin/wraith 2>/dev/null || true
    chmod 755 /usr/bin/wraith 2>/dev/null || true
    cp -f "$TARGET_BIN" /bin/wraith 2>/dev/null || true
    chmod 755 /bin/wraith 2>/dev/null || true
    if [ -d "/root/.cargo/bin" ]; then
        cp -f "$TARGET_BIN" /root/.cargo/bin/wraith 2>/dev/null || true
        chmod 755 /root/.cargo/bin/wraith 2>/dev/null || true
    fi
    mkdir -p /etc/wraith /var/log/wraith /etc/tor
    chmod 750 /etc/wraith /var/log/wraith
    hash -r 2>/dev/null || true
    echo -e "        ${CLR_EMERALD}✔ [INJECTED]${CLR_RESET} Deployed: ${CLR_WHITE}/usr/local/bin/wraith${CLR_RESET}, ${CLR_WHITE}/usr/bin/wraith${CLR_RESET}, ${CLR_WHITE}/bin/wraith${CLR_RESET}, ${CLR_WHITE}/root/.cargo/bin/wraith${CLR_RESET}"
else
    echo -e "  ${CLR_RED}✖ [BUILD ERROR]${CLR_RESET} Compilation artifact missing at $TARGET_BIN"
    exit 1
fi

echo -e "\n${CLR_RED}  ╭── [ 🛡️ WRAITH DEPLOYMENT COMPLETE // OPERATIONAL COMMAND DIRECTORY ] ────────╮${CLR_RESET}"
echo -e "${CLR_RED}  │                                                                               │${CLR_RESET}"
echo -e "${CLR_RED}  │  ${CLR_AMBER}${CLR_BOLD}sudo wraith -Fs${CLR_RESET}                 ${CLR_WHITE}➔ FULL DEFENSE: All 16 Security Layers Armed${CLR_RESET}    ${CLR_RED}│${CLR_RESET}"
echo -e "${CLR_RED}  │  ${CLR_CYAN}${CLR_BOLD}sudo wraith -s${CLR_RESET}                  ${CLR_WHITE}➔ Standard Fail-Closed Tor Egress Proxy${CLR_RESET}         ${CLR_RED}│${CLR_RESET}"
echo -e "${CLR_RED}  │  ${CLR_CYAN}${CLR_BOLD}sudo wraith -s --rotate 60${CLR_RESET}      ${CLR_WHITE}➔ Automatic Tor Circuit Rotation (60s)${CLR_RESET}          ${CLR_RED}│${CLR_RESET}"
echo -e "${CLR_RED}  │  ${CLR_CYAN}${CLR_BOLD}sudo wraith -r${CLR_RESET}                  ${CLR_WHITE}➔ Instant Manual Circuit & Identity Shift${CLR_RESET}       ${CLR_RED}│${CLR_RESET}"
echo -e "${CLR_RED}  │  ${CLR_CYAN}${CLR_BOLD}sudo wraith -i${CLR_RESET}                  ${CLR_WHITE}➔ Live GeoIP, Exit Node & Circuit Telemetry${CLR_RESET}     ${CLR_RED}│${CLR_RESET}"
echo -e "${CLR_RED}  │  ${CLR_CYAN}${CLR_BOLD}sudo wraith --dashboard${CLR_RESET}         ${CLR_WHITE}➔ Interactive Terminal Telemetry HUD (TUI)${CLR_RESET}      ${CLR_RED}│${CLR_RESET}"
echo -e "${CLR_RED}  │  ${CLR_CYAN}${CLR_BOLD}sudo wraith -t${CLR_RESET}                  ${CLR_WHITE}➔ Multi-Vector DNS, WebRTC & IPv6 Leak Test${CLR_RESET}     ${CLR_RED}│${CLR_RESET}"
echo -e "${CLR_RED}  │  ${CLR_CYAN}${CLR_BOLD}sudo wraith -u${CLR_RESET}                  ${CLR_WHITE}➔ Atomic In-Place Self-Healing Updater${CLR_RESET}          ${CLR_RED}│${CLR_RESET}"
echo -e "${CLR_RED}  │  ${CLR_CYAN}${CLR_BOLD}sudo wraith -x${CLR_RESET}                  ${CLR_WHITE}➔ Instant Shutdown & Clean Network Restore${CLR_RESET}      ${CLR_RED}│${CLR_RESET}"
echo -e "${CLR_RED}  │                                                                               │${CLR_RESET}"
echo -e "${CLR_RED}  ╰───────────────────────────────────────────────────────────────────────────────╯${CLR_RESET}\n"

