#!/usr/bin/env bash
# ==============================================================================
# ⚔️ WRAITH-PRIME // SOVEREIGN UNINSTALL & TEARDOWN ENGINE v1.3.0
# High-Assurance Ring-0/Ring-3 Defense & Complete Sanitization
# Absolute Precision. Zero Residue. Pure Technical Execution.
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

BANNER() {
    echo -e "\n${CLR_RED}${CLR_BOLD}"
    echo "   ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗"
    echo "   ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║"
    echo "   ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║"
    echo "   ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║"
    echo "   ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║"
    echo "    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝"
    echo -e "${CLR_AMBER}  ╭── [ 💀 WRAITH-PRIME // SYSTEM UNINSTALL & PURGE ] ────────────────────────────╮"
    echo -e "  │  ${CLR_SLATE}MODULE      :${CLR_RESET} ${CLR_RED}${CLR_BOLD}COMPLETE ENGINE TEARDOWN & RESIDUE PURGE${CLR_RESET}                 ${CLR_AMBER}│"
    echo -e "  │  ${CLR_SLATE}SECURITY    :${CLR_RESET} ${CLR_EMERALD}${CLR_BOLD}DNS & FIREWALL RESTORATION // CLEARNET RESTORE${CLR_RESET}          ${CLR_AMBER}│"
    echo -e "  │  ${CLR_SLATE}AUTHORITY   :${CLR_RESET} ${CLR_WHITE}THE ARCHITECT (MİMAR) // NYX-PRIME v8.0${CLR_RESET}                   ${CLR_AMBER}│"
    echo -e "  ╰──────────────────────────────────────────────────────────────────────────────╯${CLR_RESET}\n"
}

BANNER

# 1. Root Clearance Check
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo -e "  ${CLR_RED}${CLR_BOLD}✖ [ACCESS DENIED]${CLR_RESET} Root clearance required for uninstallation."
    echo -e "      ${CLR_SLATE}Execute with root privileges: ${CLR_WHITE}sudo ./uninstall.sh${CLR_RESET}\n"
    exit 1
fi

echo -e "  ${CLR_CYAN}◈ [ADIM 1/6]${CLR_RESET} ${CLR_WHITE}Aktif Oturumlar ve Servisler Denetleniyor...${CLR_RESET}"

# 2. Stop systemd services (from install-daemon.sh)
if systemctl is-active --quiet wraith.service 2>/dev/null; then
    echo -e "      ${CLR_AMBER}[~]${CLR_RESET} Aktif Wraith systemd servisi durduruluyor..."
    systemctl stop wraith.service 2>/dev/null || true
fi
systemctl disable wraith.service 2>/dev/null || true
systemctl disable wraith-early.service 2>/dev/null || true

# 3. Graceful session teardown via wraith binary if active
if [[ -e /var/run/wraith.state ]]; then
    echo -e "      ${CLR_AMBER}[~]${CLR_RESET} Aktif Wraith geçici oturumu algılandı, kurallar sıfırlanıyor..."
    if [[ -x /usr/local/bin/wraith ]]; then
        /usr/local/bin/wraith -x 2>/dev/null || true
    elif [[ -x /usr/bin/wraith ]]; then
        /usr/bin/wraith -x 2>/dev/null || true
    fi
fi

# 4. Terminate any lingering background workers or Tor processes
echo -e "  ${CLR_CYAN}◈ [ADIM 2/6]${CLR_RESET} ${CLR_WHITE}Arka Plan Süreçleri ve Tor Ağ Geçidi Temizleniyor...${CLR_RESET}"
pkill -f "wraith.*--daemon-worker" 2>/dev/null || true
pkill -f "wraithrc" 2>/dev/null || true
pkill -x wraith 2>/dev/null || true

# 5. Network, DNS & Firewall Restoration Safeguard
echo -e "  ${CLR_CYAN}◈ [ADIM 3/6]${CLR_RESET} ${CLR_WHITE}Ağ Bağlantısı, DNS ve Güvenlik Duvarı Fabrika Ayarlarına Döndürülüyor...${CLR_RESET}"

# Unlock and restore /etc/resolv.conf
chattr -i /etc/resolv.conf 2>/dev/null || true

if [[ -f /etc/resolv.conf.wraith.backup ]]; then
    echo -e "      ${CLR_EMERALD}✔${CLR_RESET} DNS yedeği (/etc/resolv.conf.wraith.backup) geri yükleniyor..."
    cp -f /etc/resolv.conf.wraith.backup /etc/resolv.conf
    rm -f /etc/resolv.conf.wraith.backup
elif grep -q "127.0.0.1" /etc/resolv.conf 2>/dev/null; then
    echo -e "      ${CLR_AMBER}[!]${CLR_RESET} DNS hala yerel Tor ağ geçidinde (127.0.0.1). Güvenli Clearnet DNS yazılıyor..."
    cat <<EOF > /etc/resolv.conf
# Clearnet DNS - Restored by Wraith Uninstaller
nameserver 1.1.1.1
nameserver 9.9.9.9
nameserver 8.8.8.8
EOF
fi

# Flush Wraith iptables transparent proxy & redirection rules if lingering
if iptables -t nat -S 2>/dev/null | grep -qE '9040|5353'; then
    echo -e "      ${CLR_AMBER}[!]${CLR_RESET} Kalan Tor netfilter yönlendirme kuralları sıfırlanıyor..."
    iptables -t nat -F WRAITH 2>/dev/null || true
    iptables -t nat -D OUTPUT -j WRAITH 2>/dev/null || true
    iptables -t nat -D PREROUTING -j WRAITH 2>/dev/null || true
    iptables -t nat -X WRAITH 2>/dev/null || true
fi

# Unblock IPv6 if blocked by Wraith
ip6tables -D OUTPUT -j DROP 2>/dev/null || true

# Reset any Traffic Shaper tc qdisc rules
for iface in $(ls /sys/class/net/ 2>/dev/null || true); do
    tc qdisc del dev "$iface" root 2>/dev/null || true
done

# 6. Remove Systemd Service Units (install-daemon.sh artifacts)
echo -e "  ${CLR_CYAN}◈ [ADIM 4/6]${CLR_RESET} ${CLR_WHITE}Systemd Servis Dosyaları Siliniyor...${CLR_RESET}"
rm -f -- /etc/systemd/system/wraith.service /etc/systemd/system/wraith-early.service
systemctl daemon-reload 2>/dev/null || true

# 7. Remove Binaries and Shell Autocompletions
echo -e "  ${CLR_CYAN}◈ [ADIM 5/6]${CLR_RESET} ${CLR_WHITE}Çalıştırılabilir Binary Dosyaları ve Shell Tamamlamaları Kaldırılıyor...${CLR_RESET}"
rm -f -- /usr/local/bin/wraith /usr/bin/wraith
rm -f -- /etc/bash_completion.d/wraith \
         /usr/share/bash-completion/completions/wraith \
         /usr/share/zsh/vendor-completions/_wraith \
         /usr/share/zsh/site-functions/_wraith \
         /usr/share/fish/vendor_completions.d/wraith.fish 2>/dev/null || true

# 8. Clean Runtime State, Cache & Configurations
echo -e "  ${CLR_CYAN}◈ [ADIM 6/6]${CLR_RESET} ${CLR_WHITE}Durum Dosyaları, Torrc ve Geçici Kayıtlar Temizleniyor...${CLR_RESET}"
rm -f -- /var/run/wraith.state
rm -f -- /etc/tor/wraithrc
rm -rf -- /var/log/wraith
rm -f -- /etc/wraith/daemon.conf

# Restart NetworkManager if available to ensure pristine network stack
if systemctl is-active --quiet NetworkManager 2>/dev/null; then
    echo -e "      ${CLR_EMERALD}✔${CLR_RESET} NetworkManager servisi yenileniyor..."
    systemctl restart NetworkManager 2>/dev/null || true
fi

echo -e "\n${CLR_EMERALD}${CLR_BOLD}  ✔ [BAŞARILI] WRAITH SİSTEMDEN TAMAMEN KALDIRILDI!${CLR_RESET}"
echo -e "  ${CLR_WHITE}• Kalıcı systemd servisleri ve geçici arka plan süreçleri sonlandırıldı.${CLR_RESET}"
echo -e "  ${CLR_WHITE}• Binary dosyaları, shell eklentileri ve durum kütükleri temizlendi.${CLR_RESET}"
echo -e "  ${CLR_WHITE}• Ağ geçidi, DNS ve güvenlik duvarı fabrika standartlarına getirildi.${CLR_RESET}\n"
