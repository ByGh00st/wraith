#!/usr/bin/env bash
# ==============================================================================
# WRAITH-PRIME // KERNEL SOURCE SYNCHRONIZATION
# ==============================================================================

set -euo pipefail

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

echo -e "\n${CLR_CYAN}${CLR_BOLD}"
echo "   ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗"
echo "   ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║"
echo "   ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║"
echo "   ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║"
echo "   ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║"
echo "    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝"
echo -e "${CLR_AMBER}  ╭── [ ⚔ WRAITH-PRIME // KERNEL SOURCE SYNCHRONIZATION ] ───────────────╮${CLR_RESET}"

print_box_line() {
    local prefix="$1"
    local value="$2"
    local color="$3"
    local val_len=${#value}
    local pad_len=$(( 58 - val_len ))
    local pad=""
    if [ $pad_len -gt 0 ]; then
        pad=$(printf '%*s' $pad_len "")
    fi
    echo -e "  ${CLR_AMBER}│${CLR_RESET}  ${CLR_SLATE}${prefix}${CLR_RESET} ${color}${value}${CLR_RESET}${pad} ${CLR_AMBER}│${CLR_RESET}"
}

print_box_line "MODULE    :" "GIT FETCH & SYNC GATE" "${CLR_CYAN}${CLR_BOLD}"
print_box_line "PROTOCOL  :" "OOM-BYPASS SOURCE UPDATE" "${CLR_PURPLE}"

echo -e "${CLR_AMBER}  ╰──────────────────────────────────────────────────────────────────────╯${CLR_RESET}\n"

spin() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\'
    while ps -p $pid > /dev/null 2>&1; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

if [ -d ".git" ]; then
    echo -ne "${CLR_CYAN}[~]${CLR_RESET} Synchronizing local repository with upstream (origin/main)... "
    (git fetch --all >/dev/null 2>&1 && git reset --hard origin/main >/dev/null 2>&1 && git pull origin main >/dev/null 2>&1) & spin
    echo -e "\n${CLR_EMERALD}[✓] Kernel source arrays successfully aligned.${CLR_RESET}\n"
else
    echo -ne "${CLR_CYAN}[~]${CLR_RESET} Git repository not found locally. Cloning fresh source... "
    sudo rm -rf wraith-source-update >/dev/null 2>&1
    git clone https://github.com/ByGh00st/wraith.git wraith-source-update >/dev/null 2>&1 & spin
    echo -e "\n${CLR_EMERALD}[✓] Master source downloaded to 'wraith-source-update'.${CLR_RESET}\n"
    echo -e "${CLR_AMBER}[!] ACTION REQUIRED:${CLR_RESET}"
    echo -e "    ${CLR_WHITE}cd wraith-source-update && sudo ./build.sh${CLR_RESET}\n"
    exit 0
fi

echo -e "${CLR_AMBER}[!] ACTION REQUIRED (OOM PREVENTION):${CLR_RESET}"
echo -e "    ${CLR_WHITE}To compile safely and avoid Error 101, manually execute:${CLR_RESET}"
echo -e "    ${CLR_RED}${CLR_BOLD}sudo ./build.sh${CLR_RESET}\n"
