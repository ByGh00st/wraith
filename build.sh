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
echo -e "${CLR_AMBER}  ╭── [ ⚔ WRAITH-PRIME // SOVEREIGN FORGE & COMPILER ] ──────────────────────────╮${CLR_RESET}"

print_box_line() {
    local prefix="$1"
    local value="$2"
    local color="$3"
    local val_len=${#value}
    local pad_len=$(( 60 - val_len ))
    local pad=""
    if [ $pad_len -gt 0 ]; then
        pad=$(printf '%*s' $pad_len "")
    fi
    echo -e "  ${CLR_AMBER}│${CLR_RESET}  ${CLR_SLATE}${prefix}${CLR_RESET} ${color}${value}${CLR_RESET}${pad} ${CLR_AMBER}│${CLR_RESET}"
}

print_box_line "CORE ENGINE :" "WRAITH v1.3.0 // KERNEL ANONYMIZATION GATE" "${CLR_RED}${CLR_BOLD}"
print_box_line "TARGET HOST :" "${TARGET_OS} [${ARCH}]" "${CLR_EMERALD}"
print_box_line "KERNEL SPEC :" "Linux ${KERNEL_REL}" "${CLR_WHITE}"
print_box_line "FORGE MODE  :" "LOCKED RELEASE BUILD // SYSTEM COMPILATION" "${CLR_RED}${CLR_BOLD}"

echo -e "${CLR_AMBER}  ╰──────────────────────────────────────────────────────────────────────────────╯${CLR_RESET}\n"

# Build as the invoking user; root is used only for packages and deployment.
[[ $(uname -s) == Linux ]] || { echo "This installer requires Linux." >&2; exit 1; }

if [[ $EUID -eq 0 && ${SUDO_UID:-0} -ne 0 ]]; then
    BUILD_USER=$(getent passwd "$SUDO_UID" | cut -d: -f1)
    BUILD_HOME=$(getent passwd "$SUDO_UID" | cut -d: -f6)
elif [[ $EUID -eq 0 && ${SUDO_UID:-0} -eq 0 ]]; then
    BUILD_USER="root"
    BUILD_HOME="/root"
else
    echo "Please run: sudo ./build.sh" >&2; exit 1;
fi

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
