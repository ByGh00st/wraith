#!/usr/bin/env bash
# ==============================================================================
# WRAITH v1.0.0 — KALI LINUX AUTOMATED FORGE & COMPILER SCRIPT
# Sovereign Kernel Anonymization Framework
# Built by WRAITH-PRIME / ByGhost // Sovereign Core Engine
# ==============================================================================

set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m'

echo -e "${PURPLE}"
echo "   ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗"
echo "   ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║"
echo "   ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║"
echo "   ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║"
echo "   ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║"
echo "    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝"
echo -e "   ${CYAN}Kernel-Grade Network Anonymization Engine for Kali Linux${NC}\n"

# 1. Check Root / Sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Root privileges required for system installation. Run: sudo ./build.sh${NC}"
    exit 1
fi

# 2. Check & Install Rust toolchain
echo -e "${CYAN}[1/4] Inspecting Rust toolchain...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "${PURPLE}[INFO] Cargo not found. Installing rustup...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env" || export PATH="$HOME/.cargo/bin:$PATH"
fi
echo -e "${GREEN}[OK] Rust compiler ready: $(rustc --version)${NC}"

# 3. Install Kali System Dependencies
echo -e "\n${CYAN}[2/4] Installing system dependencies (tor, iptables, obfs4proxy)...${NC}"
apt-get update -qq
apt-get install -y -qq tor iptables iproute2 obfs4proxy dnsutils libssl-dev pkg-config > /dev/null 2>&1
echo -e "${GREEN}[OK] Native network dependencies installed${NC}"

# 4. Build Release Binary
echo -e "\n${CYAN}[3/4] Compiling Wraith in Release Mode (Optimized LTO)...${NC}"
cargo build --release --workspace

# 5. Install to System Path
echo -e "\n${CYAN}[4/4] Deploying binary to /usr/local/bin/wraith...${NC}"
TARGET_BIN="target/release/wraith"
if [ -f "$TARGET_BIN" ]; then
    cp "$TARGET_BIN" /usr/local/bin/wraith
    chmod 755 /usr/local/bin/wraith
    mkdir -p /etc/wraith /var/log/wraith /etc/tor
    chmod 750 /etc/wraith /var/log/wraith
    echo -e "${GREEN}[SUCCESS] Wraith successfully deployed to /usr/local/bin/wraith${NC}"
else
    echo -e "${RED}[ERROR] Compilation artifact not found at $TARGET_BIN${NC}"
    exit 1
fi

echo -e "\n${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}[DEPLOYMENT COMPLETE] You can now execute:${NC}"
echo -e "${CYAN}  sudo wraith -s                  # Standard Tor Fail-Closed Anonymization"
echo -e "  sudo wraith --gen4              # GEN-4 SOVEREIGN: Seccomp-BPF + eBPF/TC + JA4 Camouflage + DMA Shield"
echo -e "  sudo wraith --black-level       # BLACK-LEVEL: Max vectors (Shield + NetNS + MAC + TCP-Mask + Jitter)"
echo -e "  sudo wraith --gen4 -d           # Self-Destruct: Shred all traces and binary from disk/RAM on exit"
echo -e "  sudo wraith -s -p stealth       # Five Eyes Exclusion exit routing"
echo -e "  sudo wraith -t                  # Multi-vector leak test (DNS, IPv6, WebRTC)"
echo -e "  sudo wraith -i                  # Real-time telemetry dashboard & circuits"
echo -e "  sudo wraith -x                  # Clean stop & restore original network"
echo -e "  sudo wraith -c --cleanup-full   # Anti-forensic RAM/Swap/Log cryptographic wipe${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
