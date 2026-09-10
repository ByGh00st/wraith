#!/usr/bin/env bash
# ==============================================================================
# WRAITH-PRIME // SOVEREIGN KERNEL FORGE & AUTOMATED BUILD ENGINE v1.3.0
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
echo -e "  │  ${CLR_SLATE}CORE ENGINE :${CLR_RESET} ${CLR_RED}${CLR_BOLD}WRAITH v1.3.0 // KERNEL ANONYMIZATION GATE${CLR_RESET}                  ${CLR_AMBER}│"
echo -e "  │  ${CLR_SLATE}TARGET HOST :${CLR_RESET} ${CLR_EMERALD}${TARGET_OS} [${ARCH}]${CLR_RESET}                                      ${CLR_AMBER}│"
echo -e "  │  ${CLR_SLATE}KERNEL SPEC :${CLR_RESET} ${CLR_WHITE}Linux ${KERNEL_REL}${CLR_RESET}                                             ${CLR_AMBER}│"
echo -e "  │  ${CLR_SLATE}FORGE MODE  :${CLR_RESET} ${CLR_RED}${CLR_BOLD}LOCKED RELEASE BUILD // USER-PRIVILEGE COMPILATION${CLR_RESET}          ${CLR_AMBER}│"
echo -e "  ╰──────────────────────────────────────────────────────────────────────────────╯${CLR_RESET}\n"

# Build as the invoking user; root is used only for packages and deployment.
[[ $(uname -s) == Linux ]] || { echo "This installer requires Linux." >&2; exit 1; }
[[ $EUID -eq 0 && ${SUDO_UID:-0} -ne 0 ]] || {
    echo "Install Rust as your normal user, then run: sudo ./build.sh" >&2; exit 1;
}
BUILD_USER=$(getent passwd "$SUDO_UID" | cut -d: -f1)
BUILD_HOME=$(getent passwd "$SUDO_UID" | cut -d: -f6)
[[ -n $BUILD_USER && -d $BUILD_HOME ]] || { echo "Cannot resolve invoking user." >&2; exit 1; }
REPO_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
BUILD_PATH="$BUILD_HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
as_builder() {
    sudo -H -u "$BUILD_USER" -- env -i HOME="$BUILD_HOME" USER="$BUILD_USER" \
        PATH="$BUILD_PATH" CARGO_HOME="$BUILD_HOME/.cargo" "$@"
}
as_builder cargo --version
as_builder rustc --version
command -v apt-get >/dev/null || {
    echo "Automatic dependency installation supports Debian/Ubuntu/Parrot/Kali. See README for manual builds." >&2
    exit 1
}
echo -e "${CLR_CYAN}[1/3] Installing build and runtime dependencies${CLR_RESET}"
apt-get update
apt-get install -y build-essential cmake perl libclang-dev pkg-config git tor iptables \
    iproute2 obfs4proxy dnsutils libssl-dev psmisc procps e2fsprogs curl fontconfig

echo -e "${CLR_CYAN}[2/3] Building locked release as $BUILD_USER${CLR_RESET}"
cd -- "$REPO_DIR"
TARGET_TRIPLE=$(as_builder rustc -vV | sed -n 's/^host: //p')
[[ $TARGET_TRIPLE == x86_64-unknown-linux-gnu ]] || {
    echo "Supported installed target is x86_64-unknown-linux-gnu." >&2; exit 1;
}
BUILD_DIR=$(as_builder mktemp -d /var/tmp/wraith-build.XXXXXXXXXX)
INSTALL_TMP=''
cleanup() {
    [[ -z $INSTALL_TMP ]] || rm -f -- "$INSTALL_TMP"
    # mktemp creates this absolute, owned build directory; never delete a supplied path.
    [[ $BUILD_DIR == /var/tmp/wraith-build.* ]] && as_builder rm -rf -- "$BUILD_DIR"
}
trap cleanup EXIT
as_builder cargo build --release --workspace --locked --target "$TARGET_TRIPLE" --target-dir "$BUILD_DIR"

echo -e "${CLR_CYAN}[3/3] Installing /usr/local/bin/wraith${CLR_RESET}"
install -d -m 755 /usr/local/bin
INSTALL_TMP=$(mktemp /usr/local/bin/.wraith-install.XXXXXXXXXX)
install -m 755 -- "$BUILD_DIR/$TARGET_TRIPLE/release/wraith" "$INSTALL_TMP"
mv -fT -- "$INSTALL_TMP" /usr/local/bin/wraith
INSTALL_TMP=''
echo -e "${CLR_EMERALD}Installed. Existing sessions keep running their current executable.${CLR_RESET}"
echo "Run wraith --help. Start a new session after stopping any existing session normally."
