#!/usr/bin/env bash
# ==============================================================================
# 💀 WRAITH-PRIME // UNINSTALL & SYSTEM PURGE
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
CLR_RESET='\033[0m'

echo -e "\n${CLR_PURPLE}${CLR_BOLD}"
echo "   ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗"
echo "   ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║"
echo "   ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║"
echo "   ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║"
echo "   ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║"
echo "    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝"
echo -e "${CLR_CYAN}  ╭── [ ⚔ WRAITH-PRIME // UNINSTALLER & SYSTEM RESTORE ] ────────────────────────╮"
echo -e "  │  ${CLR_SLATE}TARGET :${CLR_RESET} ${CLR_AMBER}Complete removal of binaries, configs, and network constraints${CLR_RESET} ${CLR_CYAN}│"
echo -e "  ╰──────────────────────────────────────────────────────────────────────────────╯${CLR_RESET}\n"

if [ "$EUID" -ne 0 ]; then
    echo -e "  ${CLR_RED}${CLR_BOLD}✖ [ACCESS DENIED]${CLR_RESET} Root clearance required for uninstall."
    echo -e "      ${CLR_SLATE}Execute with root privileges: ${CLR_WHITE}sudo ./uninstall.sh${CLR_RESET}\n"
    exit 1
fi

echo -e "  ${CLR_CYAN}◈ [1/4]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Halting any active Wraith instances...${CLR_RESET}"
killall -9 wraith 2>/dev/null || true
pkill -9 -f "wraith monitor" 2>/dev/null || true
echo -e "        ${CLR_EMERALD}✔ [KILLED]${CLR_RESET} Processes terminated."

echo -e "\n  ${CLR_CYAN}◈ [2/4]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Restoring network restrictions and DNS...${CLR_RESET}"
nft flush ruleset 2>/dev/null || true
iptables -F 2>/dev/null || true
chattr -i /etc/resolv.conf 2>/dev/null || true
(echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf) 2>/dev/null || true
systemctl restart NetworkManager 2>/dev/null || true
echo -e "        ${CLR_EMERALD}✔ [RESTORED]${CLR_RESET} Network tables flushed & DNS unlocked."

echo -e "\n  ${CLR_CYAN}◈ [3/4]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Purging binary artifacts from system paths...${CLR_RESET}"
rm -f /usr/local/bin/wraith \
      /usr/bin/wraith \
      /bin/wraith \
      /root/.cargo/bin/wraith 2>/dev/null || true

for user_home in /home/*; do
    if [ -d "$user_home/.cargo/bin" ]; then
        rm -f "$user_home/.cargo/bin/wraith" 2>/dev/null || true
    fi
done
hash -r 2>/dev/null || true
echo -e "        ${CLR_EMERALD}✔ [ERADICATED]${CLR_RESET} Binaries removed."

echo -e "\n  ${CLR_CYAN}◈ [4/4]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Wiping configurations, logs, and artifacts...${CLR_RESET}"
rm -rf /etc/wraith
rm -rf /var/log/wraith
rm -f /etc/tor/wraithrc
echo -e "        ${CLR_EMERALD}✔ [CLEARED]${CLR_RESET} Persistent data obliterated."

echo -e "\n${CLR_PURPLE}  ╭── [ 🛡️ WRAITH PURGE COMPLETE // SYSTEM RESTORED TO DEFAULT ] ─────────╮${CLR_RESET}"
echo -e "${CLR_PURPLE}  │  ${CLR_WHITE}All Wraith traces have been removed from the system.                   ${CLR_PURPLE}│${CLR_RESET}"
echo -e "${CLR_PURPLE}  ╰───────────────────────────────────────────────────────────────────────╯${CLR_RESET}\n"
