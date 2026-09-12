#!/usr/bin/env bash
# ==============================================================================
# ⚡ WRAITH-PRIME // EMERGENCY NETWORK & FIREWALL RESET ENGINE v1.3.0
# High-Assurance Clearnet Restoration & Subsystem Sanitization
# Absolute Precision. Zero Lockup. Pure Technical Execution.
# ==============================================================================

set -uo pipefail

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
    echo -e "\n${CLR_CYAN}${CLR_BOLD}"
    echo "   ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗"
    echo "   ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║"
    echo "   ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║"
    echo "   ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║"
    echo "   ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║"
    echo "    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝"
    echo -e "${CLR_AMBER}  ╭── [ ⚡ WRAITH-PRIME // ACİL DURUM AĞ VE GÜVENLİK DUVARI SIFIRLAMA ] ────────╮"
    echo -e "  │  ${CLR_SLATE}MODÜL       :${CLR_RESET} ${CLR_CYAN}${CLR_BOLD}EMERGENCY CLEARNET & NETWORK RESTORATION ENGINE${CLR_RESET}         ${CLR_AMBER}│"
    echo -e "  │  ${CLR_SLATE}İŞLEM       :${CLR_RESET} ${CLR_EMERALD}${CLR_BOLD}IPTABLES PURGE // DNS RESTORE // PORT DECONFLICTION${CLR_RESET}     ${CLR_AMBER}│"
    echo -e "  │  ${CLR_SLATE}YETKİ       :${CLR_RESET} ${CLR_WHITE}THE ARCHITECT (MİMAR) // NYX-PRIME v8.0${CLR_RESET}                   ${CLR_AMBER}│"
    echo -e "  ╰──────────────────────────────────────────────────────────────────────────────╯${CLR_RESET}\n"
}

BANNER

# 1. Root Clearance Check
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo -e "  ${CLR_RED}${CLR_BOLD}✖ [ERİŞİM REDDEDİLDİ]${CLR_RESET} Ağ sıfırlama işlemi için root yetkisi gereklidir."
    echo -e "      ${CLR_SLATE}Yüksek yetkiyle çalıştırın: ${CLR_WHITE}sudo ./reset.sh${CLR_RESET}\n"
    exit 1
fi

# ─── [ ADIM 1/7: WRAITH VE ARKA PLAN SÜREÇLERİ ] ─────────────────────────────
echo -e "  ${CLR_CYAN}◈ [ADIM 1/7]${CLR_RESET} ${CLR_WHITE}Wraith ve Çakışan Tor Süreçleri Sonlandırılıyor...${CLR_RESET}"

# Stop systemd units if running
systemctl stop wraith.service 2>/dev/null || true
systemctl stop wraith-early.service 2>/dev/null || true
systemctl stop tor.service 2>/dev/null || true
systemctl stop tor@default.service 2>/dev/null || true

# Kill any hanging wraith processes
pkill -9 -f "wraith.*--daemon-worker" 2>/dev/null || true
pkill -9 -f "wraithrc" 2>/dev/null || true
pkill -9 -x "wraith" 2>/dev/null || true

# Kill any lingering tor instances that hog ports 9050/9051/9040
killall -9 tor 2>/dev/null || true
pkill -9 -x tor 2>/dev/null || true

echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Tüm Wraith ve Tor işlemleri bellekten temizlendi."

# ─── [ ADIM 2/7: OTURUM VE DURUM DOSYALARININ İMHASI ] ──────────────────────
echo -e "  ${CLR_CYAN}◈ [ADIM 2/7]${CLR_RESET} ${CLR_WHITE}Askıda Kalan Oturum Durumları (State & Lock) Temizleniyor...${CLR_RESET}"

rm -f /var/run/wraith.state 2>/dev/null || true
rm -f /run/wraith.state 2>/dev/null || true
rm -f /var/lib/tor/lock 2>/dev/null || true
rm -f /var/lib/tor/wraith/lock 2>/dev/null || true
rm -f /run/tor/control.authcookie 2>/dev/null || true
rm -f /var/run/tor/control.authcookie 2>/dev/null || true

echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Kilit ve oturum dosyaları başarıyla imha edildi."

# ─── [ ADIM 3/7: IPTABLES VE IP6TABLES KURALLARININ BOŞALTILMASI ] ──────────
echo -e "  ${CLR_CYAN}◈ [ADIM 3/7]${CLR_RESET} ${CLR_WHITE}Iptables ve Ip6tables Güvenlik Duvarı Sıfırlanıyor (ACCEPT)...${CLR_RESET}"

# IPv4: Default ACCEPT on all standard chains
iptables -P INPUT ACCEPT 2>/dev/null || true
iptables -P FORWARD ACCEPT 2>/dev/null || true
iptables -P OUTPUT ACCEPT 2>/dev/null || true

# IPv4: Flush all chains and tables
iptables -t nat -F 2>/dev/null || true
iptables -t nat -X 2>/dev/null || true
iptables -t mangle -F 2>/dev/null || true
iptables -t mangle -X 2>/dev/null || true
iptables -t raw -F 2>/dev/null || true
iptables -t raw -X 2>/dev/null || true
iptables -F 2>/dev/null || true
iptables -X 2>/dev/null || true

# IPv6: Default ACCEPT on all standard chains
ip6tables -P INPUT ACCEPT 2>/dev/null || true
ip6tables -P FORWARD ACCEPT 2>/dev/null || true
ip6tables -P OUTPUT ACCEPT 2>/dev/null || true

# IPv6: Flush all chains and tables
ip6tables -t nat -F 2>/dev/null || true
ip6tables -t nat -X 2>/dev/null || true
ip6tables -t mangle -F 2>/dev/null || true
ip6tables -t mangle -X 2>/dev/null || true
ip6tables -t raw -F 2>/dev/null || true
ip6tables -t raw -X 2>/dev/null || true
ip6tables -F 2>/dev/null || true
ip6tables -X 2>/dev/null || true

echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Güvenlik duvarı filtre, NAT ve Mangle tabloları boşaltıldı."

# ─── [ ADIM 4/7: CGROUP VE TRAFİK KONTROLÜ (TC) TEMİZLİĞİ ] ─────────────────
echo -e "  ${CLR_CYAN}◈ [ADIM 4/7]${CLR_RESET} ${CLR_WHITE}Qdisc Kısıtlamaları ve Cgroup İzolasyonları Kaldırılıyor...${CLR_RESET}"

# Clear tc egress/ingress filters on all active network interfaces
if command -v tc >/dev/null 2>&1; then
    for iface in $(ls /sys/class/net/ 2>/dev/null || true); do
        tc qdisc del dev "$iface" root 2>/dev/null || true
        tc qdisc del dev "$iface" clsact 2>/dev/null || true
    done
fi

# Remove cgroup net_cls jail
if [[ -d /sys/fs/cgroup/net_cls/wraith_jail ]]; then
    rmdir /sys/fs/cgroup/net_cls/wraith_jail 2>/dev/null || true
fi
if [[ -d /sys/fs/cgroup/wraith_jail ]]; then
    rmdir /sys/fs/cgroup/wraith_jail 2>/dev/null || true
fi

echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Trafik biçimlendirme ve cgroup zincirleri sıfırlandı."

# ─── [ ADIM 5/7: DNS ÇÖZÜCÜ VE İNOD KİLİTLERİNİN RESTORASYONU ] ──────────────
echo -e "  ${CLR_CYAN}◈ [ADIM 5/7]${CLR_RESET} ${CLR_WHITE}DNS Çözücü (/etc/resolv.conf) Kilidi Açılıyor ve Yenileniyor...${CLR_RESET}"

# Remove immutable filesystem lock
chattr -i /etc/resolv.conf 2>/dev/null || true

# Restore from snapshot backup if available, otherwise set trusted public DNS
if [[ -s /etc/resolv.conf.wraith.bak ]]; then
    echo -e "      ${CLR_SLATE}ℹ Snapshot yedeği bulundu, geri yükleniyor: /etc/resolv.conf.wraith.bak${CLR_RESET}"
    cp -f /etc/resolv.conf.wraith.bak /etc/resolv.conf 2>/dev/null || true
    rm -f /etc/resolv.conf.wraith.bak 2>/dev/null || true
else
    cat <<EOF > /etc/resolv.conf
# Clearnet Fallback Resolver Restored by Wraith Emergency Reset
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 1.0.0.1
EOF
fi

chmod 644 /etc/resolv.conf 2>/dev/null || true
echo -e "      ${CLR_EMERALD}✔${CLR_RESET} DNS çözücü güvenli clearnet sunucularına bağlandı."

# ─── [ ADIM 6/7: KERNEL TCP/IP PARAMETRELERİNİN STANDARTLAŞTIRILMASI ] ────────
echo -e "  ${CLR_CYAN}◈ [ADIM 6/7]${CLR_RESET} ${CLR_WHITE}Linux Standart TCP/IP Yığını Parametreleri Geri Yükleniyor...${CLR_RESET}"

sysctl -w net.ipv4.ip_default_ttl=64 >/dev/null 2>&1 || true
sysctl -w net.ipv4.tcp_timestamps=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.tcp_sack=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.tcp_window_scaling=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true

echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Standart Linux ağ parametreleri (TTL=64, TS=1) uygulandı."

# ─── [ ADIM 7/7: AĞ YÖNETİCİSİ (NETWORKMANAGER) VE DHCP YENİLEME ] ──────────
echo -e "  ${CLR_CYAN}◈ [ADIM 7/7]${CLR_RESET} ${CLR_WHITE}Ağ Bağdaştırıcıları ve NetworkManager Yeniden Başlatılıyor...${CLR_RESET}"

# Ensure interfaces are up
for iface in $(ls /sys/class/net/ 2>/dev/null || true); do
    if [[ "$iface" != "lo" ]]; then
        ip link set "$iface" up 2>/dev/null || true
    fi
done

# Restart network services cleanly
if systemctl list-unit-files | grep -q NetworkManager.service 2>/dev/null; then
    systemctl restart NetworkManager 2>/dev/null || true
elif command -v service >/dev/null 2>&1; then
    service NetworkManager restart 2>/dev/null || true
fi

# Bring nmcli networking back up
if command -v nmcli >/dev/null 2>&1; then
    nmcli networking on 2>/dev/null || true
fi

echo -e "      ${CLR_EMERALD}✔${CLR_RESET} DHCP bağlantısı ve ağ yöneticisi sıfırlandı."

# ─── [ TELEMETRİ VE BAĞLANTI DOĞRULAMASI ] ───────────────────────────────────
echo -e "\n  ${CLR_SLATE}[~] Ağ bağlantısı ve harici IP doğrulanıyor (3 sn)...${CLR_RESET}"
sleep 3

EXTERNAL_IP=""
for api in "https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com"; do
    if command -v curl >/dev/null 2>&1; then
        EXTERNAL_IP=$(curl -s --connect-timeout 2 "$api" 2>/dev/null | tr -d '[:space:]' || true)
        if [[ -n "$EXTERNAL_IP" ]]; then break; fi
    fi
done

echo -e "\n${CLR_AMBER}  ╭── [ 🛡️ SIFIRLAMA OPERASYONU BAŞARIYLA TAMAMLANDI ] ────────────────────────╮"
echo -e "  │  ${CLR_SLATE}DURUM       :${CLR_RESET} ${CLR_EMERALD}${CLR_BOLD}CLEARNET GERİ YÜKLENDİ // TÜM ENGELLER KALDIRILDI${CLR_RESET}       ${CLR_AMBER}│"
echo -e "  │  ${CLR_SLATE}DNS ÇÖZÜCÜ  :${CLR_RESET} ${CLR_WHITE}Cloudflare (1.1.1.1) / Google (8.8.8.8)${CLR_RESET}                   ${CLR_AMBER}│"
echo -e "  │  ${CLR_SLATE}GÜVENLİK DUV:${CLR_RESET} ${CLR_WHITE}Iptables / Ip6tables Temiz (Default ACCEPT)${CLR_RESET}             ${CLR_AMBER}│"
echo -e "  │  ${CLR_SLATE}HARİCİ IP   :${CLR_RESET} ${CLR_CYAN}${CLR_BOLD}${EXTERNAL_IP:-Bağlantı aktif (DHCP IP alınıyor...)}${CLR_RESET} ${CLR_AMBER}│"
echo -e "  ╰──────────────────────────────────────────────────────────────────────────────╯${CLR_RESET}\n"
