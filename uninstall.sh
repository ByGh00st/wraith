#!/usr/bin/env bash
# ==============================================================================
# ⚔️ WRAITH-PRIME // SOVEREIGN UNINSTALL & ZERO-RESIDUE PURGE ENGINE v1.4.0
# High-Assurance Ring-0/Ring-3 Sanitization & Absolute Teardown
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
    echo -e "${CLR_AMBER}  ╭── [ 💀 WRAITH-PRIME // SOVEREIGN SYSTEM PURGE & UNINSTALLER ] ────────────────╮"
    echo -e "  │  ${CLR_SLATE}OPERATION   :${CLR_RESET} ${CLR_RED}${CLR_BOLD}TOTAL RESIDUE PURGE // ZERO-TRACE SANITIZATION${CLR_RESET}          ${CLR_AMBER}│"
    echo -e "  │  ${CLR_SLATE}TARGETS     :${CLR_RESET} ${CLR_WHITE}BINARIES, SERVICES, SHORTCUTS, COMPLETIONS, CONFIGS${CLR_RESET}     ${CLR_AMBER}│"
    echo -e "  │  ${CLR_SLATE}SECURITY    :${CLR_RESET} ${CLR_EMERALD}${CLR_BOLD}DNS & FIREWALL RESTORATION // CLEARNET RESTORE${CLR_RESET}          ${CLR_AMBER}│"
    echo -e "  │  ${CLR_SLATE}AUTHORITY   :${CLR_RESET} ${CLR_WHITE}THE ARCHITECT (MİMAR) // NYX-PRIME v8.0${CLR_RESET}                   ${CLR_AMBER}│"
    echo -e "  ╰──────────────────────────────────────────────────────────────────────────────╯${CLR_RESET}\n"
}

BANNER

# ─── [ ADIM 1: YETKİ KONTROLÜ ] ────────────────────────────────────────────────
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo -e "  ${CLR_RED}${CLR_BOLD}✖ [ACCESS DENIED]${CLR_RESET} Wraith kaldırma işlemi için Root (EUID=0) yetkisi şarttır."
    echo -e "      ${CLR_SLATE}Komutu root haklarıyla çalıştırın: ${CLR_WHITE}sudo ./uninstall.sh${CLR_RESET}\n"
    exit 1
fi

# Sistemdeki tüm kullanıcı dizinlerini tespit et (Root + /home altındaki tüm hesaplar)
USER_HOMES=("/root")
for h in /home/*; do
    if [[ -d "$h" ]]; then
        USER_HOMES+=("$h")
    fi
done

# ─── [ ADIM 2: AKTİF OTURUMLAR VE SÜREÇLERİN SONLANDIRILMASI ] ─────────────────
echo -e "  ${CLR_CYAN}◈ [ADIM 1/9]${CLR_RESET} ${CLR_WHITE}Aktif Oturumlar ve Arka Plan Süreçleri Donduruluyor...${CLR_RESET}"

# 1. Graceful session stop via wraith binary if executable
if [[ -e /var/run/wraith.state ]] || [[ -e /run/wraith.state ]]; then
    echo -e "      ${CLR_AMBER}[~]${CLR_RESET} Aktif Wraith oturumu tespit edildi, zararsız kapatma çağrılıyor..."
    for b in /usr/local/bin/wraith /usr/bin/wraith /bin/wraith; do
        if [[ -x "$b" ]]; then
            "$b" -x 2>/dev/null || true
            break
        fi
    done
fi

# 2. Kill all daemon workers, background tor instances and lingering processes
echo -e "      ${CLR_AMBER}[~]${CLR_RESET} Kalan Wraith ve Tor daemon süreçleri sonlandırılıyor..."
pkill -9 -f "wraith.*--daemon-worker" 2>/dev/null || true
pkill -9 -f "wraithrc" 2>/dev/null || true
pkill -9 -f "tor.*wraithrc" 2>/dev/null || true
pkill -9 -x wraith 2>/dev/null || true

# ─── [ ADIM 3: SYSTEMD SERVİSLERİ VE BİRİMLERİNİN İMHASI ] ─────────────────────
echo -e "  ${CLR_CYAN}◈ [ADIM 2/9]${CLR_RESET} ${CLR_WHITE}Systemd Servisleri ve Daemon Birimleri Kaldırılıyor...${CLR_RESET}"

if systemctl is-active --quiet wraith.service 2>/dev/null; then
    systemctl stop wraith.service 2>/dev/null || true
fi
if systemctl is-active --quiet wraith-early.service 2>/dev/null; then
    systemctl stop wraith-early.service 2>/dev/null || true
fi

systemctl disable wraith.service 2>/dev/null || true
systemctl disable wraith-early.service 2>/dev/null || true

# Remove unit files and target drop-ins
rm -f -- /etc/systemd/system/wraith.service \
         /etc/systemd/system/wraith-early.service \
         /etc/systemd/system/multi-user.target.wants/wraith.service \
         /etc/systemd/system/multi-user.target.wants/wraith-early.service \
         /lib/systemd/system/wraith.service \
         /lib/systemd/system/wraith-early.service \
         /usr/lib/systemd/system/wraith.service \
         /usr/lib/systemd/system/wraith-early.service 2>/dev/null || true
rm -rf -- /etc/systemd/system/wraith.service.d 2>/dev/null || true

# Restore system Tor service if it was disabled/masked by install-daemon.sh
systemctl unmask tor.service 2>/dev/null || true
systemctl unmask tor@default.service 2>/dev/null || true
systemctl enable tor.service 2>/dev/null || true

systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed 2>/dev/null || true
echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Systemd servis birimleri tamamen silindi, ana Tor servisi açıldı."

# ─── [ ADIM 4: AĞ GEÇİDİ, NAMESPACE, DNS VE GÜVENLİK DUVARI RESTORASYONU ] ────
echo -e "  ${CLR_CYAN}◈ [ADIM 3/9]${CLR_RESET} ${CLR_WHITE}Ağ Bağlantısı, Namespace, DNS ve Netfilter Sıfırlanıyor...${CLR_RESET}"

# 1. Network namespace destruction
if ip netns list 2>/dev/null | grep -q "wraith_ns"; then
    echo -e "      ${CLR_AMBER}[~]${CLR_RESET} Wraith network namespace (wraith_ns) siliniyor..."
    ip netns delete wraith_ns 2>/dev/null || true
fi
ip link delete veth_host 2>/dev/null || true
rm -rf -- /etc/netns/wraith_ns 2>/dev/null || true

# 2. DNS unlock and restore
chattr -i /etc/resolv.conf 2>/dev/null || true
if [[ -f /etc/resolv.conf.wraith.backup ]]; then
    echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Orijinal DNS yapılandırması (/etc/resolv.conf.wraith.backup) geri yüklendi."
    cp -f /etc/resolv.conf.wraith.backup /etc/resolv.conf
    rm -f /etc/resolv.conf.wraith.backup
elif grep -qE "127.0.0.1|10.200.|wraith" /etc/resolv.conf 2>/dev/null; then
    echo -e "      ${CLR_AMBER}[!]${CLR_RESET} DNS Tor döngüsünde kaldı. Güvenilir Clearnet DNS yazılıyor..."
    cat <<EOF > /etc/resolv.conf
# Clearnet DNS - Restored by Wraith Uninstaller
nameserver 1.1.1.1
nameserver 9.9.9.9
nameserver 8.8.8.8
EOF
fi
rm -f -- /etc/resolv.conf.wraith* 2>/dev/null || true

# 3. Netfilter (iptables & ip6tables) custom chain eradication
for tbl in nat filter mangle raw security; do
    iptables -t "$tbl" -D OUTPUT -j WRAITH 2>/dev/null || true
    iptables -t "$tbl" -D PREROUTING -j WRAITH 2>/dev/null || true
    iptables -t "$tbl" -D INPUT -j WRAITH 2>/dev/null || true
    iptables -t "$tbl" -D FORWARD -j WRAITH 2>/dev/null || true
    iptables -t "$tbl" -F WRAITH 2>/dev/null || true
    iptables -t "$tbl" -X WRAITH 2>/dev/null || true

    ip6tables -t "$tbl" -D OUTPUT -j WRAITH 2>/dev/null || true
    ip6tables -t "$tbl" -D PREROUTING -j WRAITH 2>/dev/null || true
    ip6tables -t "$tbl" -D INPUT -j WRAITH 2>/dev/null || true
    ip6tables -t "$tbl" -D FORWARD -j WRAITH 2>/dev/null || true
    ip6tables -t "$tbl" -F WRAITH 2>/dev/null || true
    ip6tables -t "$tbl" -X WRAITH 2>/dev/null || true
done

# Remove IPv6 drop rule
ip6tables -D OUTPUT -j DROP 2>/dev/null || true

# Remove nftables wraith tables if any
if command -v nft >/dev/null 2>&1; then
    nft delete table ip wraith 2>/dev/null || true
    nft delete table inet wraith 2>/dev/null || true
    nft delete table ip6 wraith 2>/dev/null || true
fi

# 4. Remove Cgroups
rmdir /sys/fs/cgroup/net_cls/wraith_jail 2>/dev/null || true
rmdir /sys/fs/cgroup/wraith 2>/dev/null || true

# 5. Reset Traffic Shaper tc qdisc rules
for iface in $(ls /sys/class/net/ 2>/dev/null || true); do
    tc qdisc del dev "$iface" root 2>/dev/null || true
done

# 6. Restart NetworkManager / systemd-resolved to guarantee pristine network
if systemctl is-active --quiet NetworkManager 2>/dev/null; then
    echo -e "      ${CLR_EMERALD}✔${CLR_RESET} NetworkManager servisi tazeleniyor..."
    systemctl restart NetworkManager 2>/dev/null || true
elif systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    systemctl restart systemd-resolved 2>/dev/null || true
fi

# ─── [ ADIM 5: ÇALIŞTIRILABİLİR BİNARY VE ÇALIŞMA YOLLARI ] ────────────────────
echo -e "  ${CLR_CYAN}◈ [ADIM 4/9]${CLR_RESET} ${CLR_WHITE}Çalıştırılabilir Binary ve Kütüphane Sembolik Bağları Siliniyor...${CLR_RESET}"

rm -f -- /usr/local/bin/wraith \
         /usr/bin/wraith \
         /bin/wraith \
         /usr/local/sbin/wraith \
         /usr/sbin/wraith 2>/dev/null || true
rm -rf -- /opt/wraith /usr/share/wraith /usr/local/share/wraith 2>/dev/null || true

# Check if any binary still answers on path
while IFS= read -r lingering_bin; do
    if [[ -n "$lingering_bin" && -f "$lingering_bin" ]]; then
        echo -e "      ${CLR_AMBER}[!]${CLR_RESET} Ek binary konumu temizleniyor: ${lingering_bin}"
        rm -f -- "$lingering_bin"
    fi
done < <(which -a wraith 2>/dev/null || true)

# ─── [ ADIM 6: TAB TAMAMLAMALARI (BASH, ZSH, FISH, ELVISH) İMHASI ] ───────────
echo -e "  ${CLR_CYAN}◈ [ADIM 5/9]${CLR_RESET} ${CLR_WHITE}Shell Otomatik Tab Tamamlamaları (Completions) Temizleniyor...${CLR_RESET}"

# 1. System-wide Bash Completions
rm -f -- /etc/bash_completion.d/wraith \
         /etc/bash_completion.d/*wraith* \
         /usr/share/bash-completion/completions/wraith \
         /usr/share/bash-completion/completions/*wraith* \
         /usr/local/share/bash-completion/completions/wraith \
         /usr/local/share/bash-completion/completions/*wraith* 2>/dev/null || true

# 2. System-wide Zsh Completions
rm -f -- /usr/share/zsh/vendor-completions/_wraith \
         /usr/share/zsh/vendor-completions/*_wraith* \
         /usr/share/zsh/site-functions/_wraith \
         /usr/share/zsh/site-functions/*_wraith* \
         /usr/local/share/zsh/vendor-completions/_wraith \
         /usr/local/share/zsh/vendor-completions/*_wraith* \
         /usr/local/share/zsh/site-functions/_wraith \
         /usr/local/share/zsh/site-functions/*_wraith* 2>/dev/null || true

# 3. System-wide Fish Completions
rm -f -- /usr/share/fish/vendor_completions.d/wraith.fish \
         /usr/share/fish/vendor_completions.d/*wraith*.fish \
         /usr/local/share/fish/vendor_completions.d/wraith.fish \
         /usr/local/share/fish/vendor_completions.d/*wraith*.fish 2>/dev/null || true

# 4. Per-User Completions & Invalidate Zsh Completion Caches
for h in "${USER_HOMES[@]}"; do
    # Bash
    rm -f -- "$h/.local/share/bash-completion/completions/wraith" \
             "$h/.local/share/bash-completion/completions/"*wraith* \
             "$h/.bash_completion.d/"*wraith* 2>/dev/null || true
    # Zsh
    rm -f -- "$h/.zsh/completions/_wraith" \
             "$h/.zsh/completions/"*_wraith* \
             "$h/.zfunc/_wraith" \
             "$h/.zfunc/"*_wraith* \
             "$h/.local/share/zsh/site-functions/_wraith" \
             "$h/.local/share/zsh/site-functions/"*_wraith* 2>/dev/null || true
    # Invalidate zcompdump so zsh forgets wraith completion rules immediately
    rm -f -- "$h/.zcompdump"* 2>/dev/null || true
    # Fish
    rm -f -- "$h/.config/fish/completions/wraith.fish" \
             "$h/.config/fish/completions/"*wraith*.fish 2>/dev/null || true
    # Elvish
    rm -f -- "$h/.elvish/lib/wraith.elv" \
             "$h/.elvish/lib/"*wraith*.elv 2>/dev/null || true
done
echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Bash, Zsh, Fish ve Elvish için tüm tab tamamlama kütükleri temizlendi."

# ─── [ ADIM 7: MASAÜSTÜ KISAYOLLARI, DESKTOP GİRİŞLERİ VE İKONLAR ] ────────────
echo -e "  ${CLR_CYAN}◈ [ADIM 6/9]${CLR_RESET} ${CLR_WHITE}Masaüstü Kısayolları (.desktop) ve İkon Dosyaları Siliniyor...${CLR_RESET}"

# 1. System Applications Menu entries
rm -f -- /usr/share/applications/wraith.desktop \
         /usr/share/applications/*wraith*.desktop \
         /usr/local/share/applications/wraith.desktop \
         /usr/local/share/applications/*wraith*.desktop 2>/dev/null || true

# 2. System Icons and Pixmaps
rm -f -- /usr/share/pixmaps/wraith.png \
         /usr/share/pixmaps/wraith.svg \
         /usr/share/pixmaps/*wraith* \
         /usr/local/share/pixmaps/*wraith* \
         /usr/share/icons/hicolor/*/apps/*wraith* \
         /usr/local/share/icons/hicolor/*/apps/*wraith* 2>/dev/null || true

# 3. Per-User Desktop Files, Launchers & Icons
for h in "${USER_HOMES[@]}"; do
    rm -f -- "$h/.local/share/applications/wraith.desktop" \
             "$h/.local/share/applications/"*wraith*.desktop \
             "$h/.local/share/icons/"*wraith* \
             "$h/.icons/"*wraith* 2>/dev/null || true

    # User Desktop shortcuts (standard 'Desktop' and localized 'Masaüstü')
    for d in "$h/Desktop" "$h/Masaüstü"; do
        if [[ -d "$d" ]]; then
            rm -f -- "$d/wraith.desktop" \
                     "$d/"*wraith*.desktop \
                     "$d/"*wraith* 2>/dev/null || true
        fi
    done
done

# Refresh desktop & icon databases
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
fi
echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Uygulama menüsü, masaüstü kısayolları ve ikon kayıtları arındırıldı."

# ─── [ ADIM 8: SHELL PROFİL KÜTÜKLERİ, ALIASLAR VE RC DOSYALARI ] ─────────────
echo -e "  ${CLR_CYAN}◈ [ADIM 7/9]${CLR_RESET} ${CLR_WHITE}Shell Profilleri (.bashrc, .zshrc, config.fish) ve Aliaslar Taranıyor...${CLR_RESET}"

# Remove /etc/profile.d/wraith scripts
rm -f -- /etc/profile.d/*wraith*.sh 2>/dev/null || true

# Sanitize RC files across system and users
RC_FILES=(
    "/etc/bash.bashrc"
    "/etc/bashrc"
    "/etc/zsh/zshrc"
    "/etc/zshrc"
    "/etc/profile"
)

for h in "${USER_HOMES[@]}"; do
    RC_FILES+=(
        "$h/.bashrc"
        "$h/.zshrc"
        "$h/.profile"
        "$h/.bash_profile"
        "$h/.bash_login"
        "$h/.config/fish/config.fish"
    )
done

for rc in "${RC_FILES[@]}"; do
    if [[ -f "$rc" ]]; then
        # Cerrahi temizlik: Yalnızca Wraith completion, alias veya wrapper satırlarını sil
        if grep -qE "wraith|WRAITH" "$rc" 2>/dev/null; then
            echo -e "      ${CLR_AMBER}[~]${CLR_RESET} Shell konfigürasyonundan Wraith satırları çıkarılıyor: ${rc}"
            sed -i -E '/(wraith --completions|complete .*\bwraith\b|alias (wraith|w-)|source .*\bwraith\b|eval .*wraith|# (Wraith|WRAITH))/d' "$rc" 2>/dev/null || true
        fi
    fi
done

# ─── [ ADIM 9: YAPILANDIRMA, GÜNLÜKLER, CACHE VE ÇALIŞMA KÜTÜKLERİ ] ──────────
echo -e "  ${CLR_CYAN}◈ [ADIM 8/9]${CLR_RESET} ${CLR_WHITE}Yapılandırma, Günlük, Önbellek ve Durum Kütükleri Kazınıyor...${CLR_RESET}"

# System configs & tor files
rm -rf -- /etc/wraith
rm -f -- /etc/tor/wraithrc
rm -rf -- /var/log/wraith /var/log/specternet
rm -rf -- /var/lib/wraith
rm -rf -- /var/lib/tor/wraith_hidden_service
rm -f -- /var/run/wraith* /run/wraith* /run/wraith.state /var/run/wraith.state
rm -f -- /var/lib/tor/lock /var/lib/tor/data/lock 2>/dev/null || true

# User configs, local share & cache
for h in "${USER_HOMES[@]}"; do
    rm -rf -- "$h/.config/wraith" \
              "$h/.cache/wraith" \
              "$h/.local/share/wraith" 2>/dev/null || true
done

# Temp & build artifacts
rm -rf -- /tmp/wraith* /tmp/.wraith* /var/tmp/wraith* /var/tmp/wraith-build.* 2>/dev/null || true

# Man pages
rm -f -- /usr/share/man/man1/wraith.1* /usr/local/share/man/man1/wraith.1* 2>/dev/null || true
if command -v mandb >/dev/null 2>&1; then
    mandb -q 2>/dev/null || true
fi

# ─── [ ADIM 10: SİSTEM KİMLİĞİ, FONTLAR VE HOSTNAME RESTORASYONU ] ─────────────
echo -e "  ${CLR_CYAN}◈ [ADIM 9/9]${CLR_RESET} ${CLR_WHITE}Machine-ID, Yazı Tipi Sandbox ve Donanım Maskeleri Eski Haline Getiriliyor...${CLR_RESET}"

# 1. Restore Machine-ID
if [[ -f /etc/machine-id.wraith.bak ]]; then
    echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Orijinal /etc/machine-id geri yüklendi."
    cp -f /etc/machine-id.wraith.bak /etc/machine-id
    rm -f /etc/machine-id.wraith.bak
fi
if [[ -f /var/lib/dbus/machine-id.wraith.bak ]]; then
    echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Orijinal /var/lib/dbus/machine-id geri yüklendi."
    cp -f /var/lib/dbus/machine-id.wraith.bak /var/lib/dbus/machine-id
    rm -f /var/lib/dbus/machine-id.wraith.bak
fi

# 2. Restore Font Sandbox
if [[ -f /etc/fonts/local.conf.wraith.bak ]]; then
    echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Yazı tipi yapılandırması (/etc/fonts/local.conf) geri yüklendi."
    cp -f /etc/fonts/local.conf.wraith.bak /etc/fonts/local.conf
    rm -f /etc/fonts/local.conf.wraith.bak
    fc-cache -f 2>/dev/null || true
elif [[ -f /etc/fonts/local.conf ]] && grep -qE "WRAITH|Wraith" /etc/fonts/local.conf 2>/dev/null; then
    echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Wraith yazı tipi izolasyon kütüğü kaldırıldı."
    rm -f /etc/fonts/local.conf
    fc-cache -f 2>/dev/null || true
fi

# 3. Restore Hostname
if [[ -f /etc/hostname.wraith.bak ]]; then
    echo -e "      ${CLR_EMERALD}✔${CLR_RESET} Orijinal Hostname (/etc/hostname) geri yüklendi."
    cp -f /etc/hostname.wraith.bak /etc/hostname
    hostname -F /etc/hostname 2>/dev/null || true
    rm -f /etc/hostname.wraith.bak
fi

# 4. Remove custom sysctl files if generated
rm -f -- /etc/sysctl.d/99-wraith.conf /etc/sysctl.d/*wraith*.conf 2>/dev/null || true
if command -v sysctl >/dev/null 2>&1; then
    sysctl --system 2>/dev/null || true
fi

echo -e "\n${CLR_EMERALD}${CLR_BOLD}  ✔ [MUTLAK İMHA TAMAMLANDI] WRAITH SİSTEMDEN %100 ARINDIRILDI!${CLR_RESET}"
echo -e "  ${CLR_WHITE}• Tüm binary dosyaları, kütüphane bağları ve servisler silindi.${CLR_RESET}"
echo -e "  ${CLR_WHITE}• Masaüstü kısayolları (.desktop), simgeler ve menü girişleri kaldırıldı.${CLR_RESET}"
echo -e "  ${CLR_WHITE}• Bash, Zsh, Fish ve Elvish için tüm tab tamamlamaları (completions) imha edildi.${CLR_RESET}"
echo -e "  ${CLR_WHITE}• .bashrc, .zshrc, config.fish ve sistem profillerindeki tüm alias/wraith girdileri temizlendi.${CLR_RESET}"
echo -e "  ${CLR_WHITE}• /etc/wraith, /etc/tor/wraithrc, loglar, önbellekler ve geçici durum dosyaları yok edildi.${CLR_RESET}"
echo -e "  ${CLR_WHITE}• Ağ geçidi, DNS, IP yönlendirmeleri ve firewall netfilter kuralları fabrika ayarlarına döndürüldü.${CLR_RESET}\n"
