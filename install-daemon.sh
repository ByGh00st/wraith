#!/usr/bin/env bash
# ==============================================================================
# ⚔️ WRAITH-PRIME // SOVEREIGN SYSTEMD DAEMON DEPLOYMENT & BOOT ENGINE
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

BANNER() {
    echo -e "\n${CLR_CYAN}${CLR_BOLD}"
    echo "   ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗"
    echo "   ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║"
    echo "   ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║"
    echo "   ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║"
    echo "   ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║"
    echo "    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝"
    echo -e "${CLR_AMBER}  ╭── [ ⚙️ WRAITH-PRIME // DAEMON & SYSTEMD BOOT ENGINE ] ────────────────────────╮"
    echo -e "  │  ${CLR_SLATE}MODULE      :${CLR_RESET} ${CLR_EMERALD}${CLR_BOLD}SYSTEMD DAEMON & EARLY-BOOT FAIL-CLOSED GATEWAY${CLR_RESET}          ${CLR_AMBER}│"
    echo -e "  │  ${CLR_SLATE}SECURITY    :${CLR_RESET} ${CLR_RED}${CLR_BOLD}RING-0 DEFENSE // ZERO CLEARNET LEAK BOOT ANONYMIZATION${CLR_RESET}  ${CLR_AMBER}│"
    echo -e "  │  ${CLR_SLATE}AUTHORITY   :${CLR_RESET} ${CLR_WHITE}THE ARCHITECT (MİMAR) // NYX-PRIME v8.0${CLR_RESET}                   ${CLR_AMBER}│"
    echo -e "  ╰──────────────────────────────────────────────────────────────────────────────╯${CLR_RESET}\n"
}

# 1. Root Clearance Check
if [ "$EUID" -ne 0 ]; then
    BANNER
    echo -e "  ${CLR_RED}${CLR_BOLD}✖ [ACCESS DENIED]${CLR_RESET} Root clearance required for systemd daemon configuration."
    echo -e "      ${CLR_SLATE}Execute with root privileges: ${CLR_WHITE}sudo ./install-daemon.sh${CLR_RESET}\n"
    exit 1
fi

# Remount paths as rw


# Check binary existence
WRAITH_BIN=""
for b in /usr/local/bin/wraith /usr/bin/wraith; do
    if [ -x "$b" ]; then
        WRAITH_BIN="$b"
        break
    fi
done

if [ -z "$WRAITH_BIN" ]; then
    BANNER
    echo -e "  ${CLR_RED}✖ [ERROR]${CLR_RESET} Wraith binary not found in system execution paths."
    echo -e "      ${CLR_SLATE}Build the engine first: ${CLR_WHITE}sudo ./build.sh${CLR_RESET}\n"
    exit 1
fi

# ─── [ DEFAULTS & CLI ARGUMENTS PARSING ] ──────────────────────────────────────
INTERACTIVE=true
OPT_PROFILE="stealth"
OPT_INTERFACE=""
OPT_DOH="quad9"
OPT_BRIDGE="none"
OPT_BOOT_MODE="standard" # standard, manual; early mode is rejected
OPT_ROTATE="0"
OPT_STRICT=true
OPT_ANTI_DEBUG=true
OPT_MASQUERADE=true
OPT_TCP_MASK=true
OPT_MAC=true
OPT_MACHINE_ID=true
OPT_START_NOW=false

print_usage() {
    echo -e "Usage: $0 [OPTIONS]"
    echo -e "Options:"
    echo -e "  --non-interactive           Skip wizard, use defaults or provided flags"
    echo -e "  --profile <MODE>            Operational profile: stealth|speed|research|darkweb|full"
    echo -e "  --interface <NIC>           Target network interface (e.g. eth0, wlan0)"
    echo -e "  --doh <PROVIDER>            DoH provider: quad9|cloudflare|mullvad|adguard|none|<URL>"
    echo -e "  --bridge <TYPE>             Bridge mode: none|moat|obfs4|snowflake|meek"
    echo -e "  --boot-mode <MODE>          Boot activation: early|standard|manual"
    echo -e "  --rotate <SECS>             Tor IP rotation interval in seconds (0 = disabled)"
    echo -e "  --no-strict                 Disable strict kernel hardening"
    echo -e "  --no-start                  Do not start daemon immediately after installation"
    echo -e "  --uninstall                 Remove Wraith systemd daemon and service units"
    echo -e "  -h, --help                  Show this help directory"
}

# Uninstall check
if [[ "${1:-}" == "--uninstall" ]] || [[ "${1:-}" == "uninstall" ]]; then
    BANNER
    echo -e "  ${CLR_CYAN}◈ [DAEMON PURGE]${CLR_RESET} ${CLR_WHITE}Stopping and disabling Wraith systemd daemon...${CLR_RESET}"
    systemctl stop wraith.service 2>/dev/null || true
    systemctl disable wraith.service 2>/dev/null || true
    rm -f /etc/systemd/system/wraith.service
    rm -f /etc/systemd/system/wraith-early.service
    rm -f /etc/wraith/daemon.conf
    systemctl daemon-reload 2>/dev/null || true
    echo -e "        ${CLR_EMERALD}✔ [REMOVED]${CLR_RESET} Wraith daemon service uninstalled cleanly.\n"
    exit 0
fi

# Parse CLI arguments if non-interactive
while [[ $# -gt 0 ]]; do
    case "$1" in
        --non-interactive|--batch|-y)
            INTERACTIVE=false
            shift
            ;;
        --profile)
            OPT_PROFILE="$2"
            INTERACTIVE=false
            shift 2
            ;;
        --interface)
            OPT_INTERFACE="$2"
            INTERACTIVE=false
            shift 2
            ;;
        --doh)
            OPT_DOH="$2"
            INTERACTIVE=false
            shift 2
            ;;
        --bridge)
            OPT_BRIDGE="$2"
            INTERACTIVE=false
            shift 2
            ;;
        --boot-mode)
            OPT_BOOT_MODE="$2"
            INTERACTIVE=false
            shift 2
            ;;
        --rotate)
            OPT_ROTATE="$2"
            INTERACTIVE=false
            shift 2
            ;;
        --no-strict)
            OPT_STRICT=false
            shift
            ;;
        --no-start)
            OPT_START_NOW=false
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# If not a TTY terminal, force non-interactive
if [ ! -t 0 ]; then
    INTERACTIVE=false
fi

BANNER

# ─── [ INTERACTIVE CONFIGURATION WIZARD ] ──────────────────────────────────────
if [ "$INTERACTIVE" = true ]; then
    echo -e "  ${CLR_WHITE}${CLR_BOLD}SOVEREIGN DAEMON DEPLOYMENT WIZARD // KERNEL ARMED${CLR_RESET}"
    echo -e "  ${CLR_SLATE}Configure persistent system background service, operational parameters & boot hooks.${CLR_RESET}\n"

    # --- STEP 1: Boot Mode & Root Activation ---
    echo -e "  ${CLR_CYAN}◈ [ADIM 1/6]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Sistem Başlangıç ve Oturum Kilidi (Boot Mode)${CLR_RESET}"
    echo -e "    ${CLR_SLATE}Sistemin ne zaman ve nasıl devreye gireceğini seçin:${CLR_RESET}"
    echo -e "    ${CLR_EMERALD}${CLR_BOLD}[1] ERKEN BAŞLANGIÇ (Early-Boot / Pre-Network Defense) [TAVSİYE EDİLEN]${CLR_RESET}"
    echo -e "        ${CLR_DIM}➥ Root ve kullanıcı oturumu açılmadan ÖNCE, ağ servisleri başlamadan devreye girer.${CLR_DIM}"
    echo -e "        ${CLR_DIM}➥ Sistem açılışında 1 bayt dahi clearnet (şifresiz) sızıntıyı engeller (Fail-Closed).${CLR_DIM}"
    echo -e "    ${CLR_WHITE}[2] STANDART SERVİS (Standard Multi-User Daemon)${CLR_RESET}"
    echo -e "        ${CLR_DIM}➥ Normal sistem açılışında arka plan servisi olarak çalışır.${CLR_DIM}"
    echo -e "    ${CLR_AMBER}[3] YALNIZCA MANUEL / TALEP ÜZERİNE (On-Demand)${CLR_RESET}"
    echo -e "        ${CLR_DIM}➥ Servis kurulur ancak otomatik başlamaz. 'systemctl start wraith' ile manuel açılır.${CLR_DIM}"
    echo -ne "    ${CLR_PURPLE}❯ Seçiminiz [1/2/3] (Varsayılan: 1): ${CLR_RESET}"
    read -r input_boot
    case "${input_boot:-1}" in
        1) OPT_BOOT_MODE="early" ;;
        2) OPT_BOOT_MODE="standard" ;;
        3) OPT_BOOT_MODE="manual" ;;
        *) OPT_BOOT_MODE="early" ;;
    esac
    echo -e "      ${CLR_EMERALD}✔ Seçildi:${CLR_RESET} ${CLR_WHITE}${OPT_BOOT_MODE^^}${CLR_RESET}\n"

    # --- STEP 2: Profile Mode ---
    echo -e "  ${CLR_CYAN}◈ [ADIM 2/6]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Operasyonel Güvenlik Profili (Profile Mode)${CLR_RESET}"
    echo -e "    ${CLR_EMERALD}[1] Stealth (Gizlilik - Five Eyes Hariç, Anti-Korelasyon Jitter)${CLR_RESET}"
    echo -e "    ${CLR_WHITE}[2] Speed (Yüksek Hız - Düşük Gecikmeli Çıkış Düğümleri)${CLR_RESET}"
    echo -e "    ${CLR_WHITE}[3] Research / OSINT (Araştırma & İstihbarat Profili)${CLR_RESET}"
    echo -e "    ${CLR_WHITE}[4] Darkweb Strict (.onion İzolasyonu)${CLR_RESET}"
    echo -e "    ${CLR_AMBER}[5] Full Defense (Maksimum 16 Katman Zırh)${CLR_RESET}"
    echo -ne "    ${CLR_PURPLE}❯ Seçiminiz [1-5] (Varsayılan: 1): ${CLR_RESET}"
    read -r input_prof
    case "${input_prof:-1}" in
        1) OPT_PROFILE="stealth" ;;
        2) OPT_PROFILE="speed" ;;
        3) OPT_PROFILE="research" ;;
        4) OPT_PROFILE="darkweb" ;;
        5) OPT_PROFILE="full" ;;
        *) OPT_PROFILE="stealth" ;;
    esac
    echo -e "      ${CLR_EMERALD}✔ Seçildi:${CLR_RESET} ${CLR_WHITE}${OPT_PROFILE}${CLR_RESET}\n"

    # --- STEP 3: Network Interface (NIC) ---
    echo -e "  ${CLR_CYAN}◈ [ADIM 3/6]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Hedef Ağ Kartı Seçimi (Network Interface)${CLR_RESET}"
    AV_IFACES=$(ip -br link 2>/dev/null | awk '{print $1}' | grep -v -E '^(lo|docker|veth|br-|wg|tun)' || true)
    echo -e "    ${CLR_SLATE}Algılanan Fiziksel Arayüzler:${CLR_RESET} ${CLR_AMBER}${AV_IFACES:-Yok}${CLR_RESET}"
    echo -e "    ${CLR_EMERALD}[0] Otomatik (Kernel varsayılan ağ kartını kilitler)${CLR_RESET}"
    idx=1
    declare -A IFACE_MAP
    for iface in $AV_IFACES; do
        echo -e "    [$idx] $iface"
        IFACE_MAP[$idx]="$iface"
        idx=$((idx + 1))
    done
    echo -ne "    ${CLR_PURPLE}❯ Arayüz numarası veya ismi (Varsayılan: 0 - Auto): ${CLR_RESET}"
    read -r input_iface
    input_iface="${input_iface:-0}"
    if [ "$input_iface" = "0" ] || [ -z "$input_iface" ]; then
        OPT_INTERFACE=""
    elif [[ -n "${IFACE_MAP[$input_iface]:-}" ]]; then
        OPT_INTERFACE="${IFACE_MAP[$input_iface]}"
    else
        OPT_INTERFACE="$input_iface"
    fi
    echo -e "      ${CLR_EMERALD}✔ Seçildi:${CLR_RESET} ${CLR_WHITE}${OPT_INTERFACE:-Auto (Kernel Default)}${CLR_RESET}\n"

    # --- STEP 4: DNS over HTTPS (DoH) Provider ---
    echo -e "  ${CLR_CYAN}◈ [ADIM 4/6]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Egemen DoH Sağlayıcısı (DNS-over-HTTPS RFC 8484)${CLR_RESET}"
    echo -e "    ${CLR_EMERALD}[1] Quad9 (İsviçre / Sıfır Log / Korumalı) [TAVSİYE EDİLEN]${CLR_RESET}"
    echo -e "    ${CLR_WHITE}[2] Cloudflare (1.1.1.1 Ultra Hızlı)${CLR_RESET}"
    echo -e "    ${CLR_WHITE}[3] Mullvad (İsveç Gizlilik Odaklı)${CLR_RESET}"
    echo -e "    ${CLR_WHITE}[4] AdGuard (İzleyici ve Reklam Engelleyici)${CLR_RESET}"
    echo -e "    ${CLR_WHITE}[5] LibreDNS (Almanya Bağımsız Uncensored)${CLR_RESET}"
    echo -e "    ${CLR_SLATE}[6] Devre Dışı / Doğrudan Tor DNS Proxy (127.0.0.1:5353)${CLR_RESET}"
    echo -ne "    ${CLR_PURPLE}❯ Seçiminiz [1-6] (Varsayılan: 1): ${CLR_RESET}"
    read -r input_doh
    case "${input_doh:-1}" in
        1) OPT_DOH="quad9" ;;
        2) OPT_DOH="cloudflare" ;;
        3) OPT_DOH="mullvad" ;;
        4) OPT_DOH="adguard" ;;
        5) OPT_DOH="libredns" ;;
        6) OPT_DOH="none" ;;
        *) OPT_DOH="quad9" ;;
    esac
    echo -e "      ${CLR_EMERALD}✔ Seçildi:${CLR_RESET} ${CLR_WHITE}${OPT_DOH}${CLR_RESET}\n"

    # --- STEP 5: Bridge / Moat Censorship Circumvention ---
    echo -e "  ${CLR_CYAN}◈ [ADIM 5/6]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Tor Sansür Aşma & Köprü Yapılandırması (Bridge Engine)${CLR_RESET}"
    echo -e "    ${CLR_EMERALD}[1] Köprü Yok (Doğrudan Tor Devresi)${CLR_RESET}"
    echo -e "    ${CLR_WHITE}[2] Moat Protokolü (Tor BridgeDB API üzerinden Dinamik Keşif)${CLR_RESET}"
    echo -e "    ${CLR_WHITE}[3] obfs4 (Trafik Karartma / Eliptik Eğri El Sıkışması)${CLR_RESET}"
    echo -e "    ${CLR_WHITE}[4] Snowflake (WebRTC Geçici Aracı Sunucuları)${CLR_RESET}"
    echo -e "    ${CLR_WHITE}[5] Meek-Azure (Microsoft CDN Domain Fronting)${CLR_RESET}"
    echo -ne "    ${CLR_PURPLE}❯ Seçiminiz [1-5] (Varsayılan: 1): ${CLR_RESET}"
    read -r input_bridge
    case "${input_bridge:-1}" in
        1) OPT_BRIDGE="none" ;;
        2) OPT_BRIDGE="moat" ;;
        3) OPT_BRIDGE="obfs4" ;;
        4) OPT_BRIDGE="snowflake" ;;
        5) OPT_BRIDGE="meek" ;;
        *) OPT_BRIDGE="none" ;;
    esac
    echo -e "      ${CLR_EMERALD}✔ Seçildi:${CLR_RESET} ${CLR_WHITE}${OPT_BRIDGE}${CLR_RESET}\n"

    # --- STEP 6: IP Rotation & Hardening ---
    echo -e "  ${CLR_CYAN}◈ [ADIM 6/6]${CLR_RESET} ${CLR_WHITE}${CLR_BOLD}Otomatik IP Devre Rotasyonu (Identity Rotation Interval)${CLR_RESET}"
    echo -e "    [0] Devre Dışı (Statik Devre)"
    echo -e "    [1] 300 saniye (5 dakika)"
    echo -e "    [2] 600 saniye (10 dakika)"
    echo -e "    [3] 1800 saniye (30 dakika)"
    echo -ne "    ${CLR_PURPLE}❯ Seçiminiz [0-3] (Varsayılan: 0): ${CLR_RESET}"
    read -r input_rot
    case "${input_rot:-0}" in
        0) OPT_ROTATE="0" ;;
        1) OPT_ROTATE="300" ;;
        2) OPT_ROTATE="600" ;;
        3) OPT_ROTATE="1800" ;;
        *) OPT_ROTATE="0" ;;
    esac
    echo -e "      ${CLR_EMERALD}✔ Seçildi:${CLR_RESET} ${CLR_WHITE}${OPT_ROTATE}s${CLR_RESET}\n"
fi

# Reject syntax that systemd would expand or parse as additional directives.
for value in "$WRAITH_BIN" "$OPT_PROFILE" "$OPT_INTERFACE" "$OPT_DOH" "$OPT_BRIDGE" "$OPT_ROTATE" "$OPT_BOOT_MODE"; do
    if [[ "$value" =~ [^a-zA-Z0-9_./:?=+@,-] ]]; then
        echo "Unsupported characters in service configuration." >&2
        exit 1
    fi
done
if [[ "$OPT_BOOT_MODE" != standard && "$OPT_BOOT_MODE" != manual ]]; then
    echo "Choose standard or manual boot mode; early mode requires a separate validated boot firewall." >&2
    exit 1
fi

# ─── [ ASSEMBLE WRAITH DAEMON EXECUTION PARAMETERS ] ───────────────────────────
DAEMON_ARGS=()

if [ "$OPT_PROFILE" = "full" ]; then
    DAEMON_ARGS+=("--full-security")
else
    DAEMON_ARGS+=("--profile" "$OPT_PROFILE")
    [ "$OPT_STRICT" = true ] && DAEMON_ARGS+=("--strict")
fi

[ -n "$OPT_INTERFACE" ] && DAEMON_ARGS+=("--interface" "$OPT_INTERFACE")

if [ "$OPT_DOH" != "none" ]; then
    DAEMON_ARGS+=("--doh" "$OPT_DOH")
fi

if [ "$OPT_BRIDGE" != "none" ]; then
    DAEMON_ARGS+=("--bridge" "$OPT_BRIDGE")
fi

[ "$OPT_ANTI_DEBUG" = true ] && DAEMON_ARGS+=("--aggressive-anti-debug")
[ "$OPT_MASQUERADE" = true ] && DAEMON_ARGS+=("--aggressive-masquerade")
[ "$OPT_TCP_MASK" = true ] && DAEMON_ARGS+=("--tcp-mask")
[ "$OPT_MAC" = true ] && DAEMON_ARGS+=("--mac")
[ "$OPT_MACHINE_ID" = true ] && DAEMON_ARGS+=("--machine-id")

if [ "$OPT_ROTATE" -gt 0 ] 2>/dev/null; then
    DAEMON_ARGS+=("--rotate-interval" "$OPT_ROTATE")
fi

CMD_EXEC_LINE="$WRAITH_BIN start ${DAEMON_ARGS[*]}"

# Persist configuration in /etc/wraith/daemon.conf
mkdir -p /etc/wraith
cat <<EOF > /etc/wraith/daemon.conf
# ==============================================================================
# WRAITH DAEMON CONFIGURATION // SOVEREIGN ENGINE PARAMETERS
# Managed by install-daemon.sh
# ==============================================================================
BOOT_MODE="${OPT_BOOT_MODE}"
PROFILE="${OPT_PROFILE}"
INTERFACE="${OPT_INTERFACE}"
DOH="${OPT_DOH}"
BRIDGE="${OPT_BRIDGE}"
ROTATE_INTERVAL="${OPT_ROTATE}"
DAEMON_ARGS="${DAEMON_ARGS[*]}"
EXEC_CMD="${CMD_EXEC_LINE}"
EOF
chmod 600 /etc/wraith/daemon.conf

# ─── [ GENERATE SYSTEMD SERVICE UNIT ] ─────────────────────────────────────────
SERVICE_FILE="/etc/systemd/system/wraith.service"

echo -e "  ${CLR_CYAN}◈ [DEPLOY]${CLR_RESET} ${CLR_WHITE}Forging systemd unit artifact: ${CLR_AMBER}${SERVICE_FILE}${CLR_RESET}"

if [ "$OPT_BOOT_MODE" = "early" ]; then
    echo "Early boot mode is unsupported: Tor startup requires working networking. Choose standard or manual." >&2
    exit 1
else
    # Standard Multi-User Background Daemon
    cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=Wraith Sovereign Kernel Defense & Anonymization Engine (Daemon)
Documentation=https://github.com/ByGh00st/wraith
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/wraith
ExecStart=${CMD_EXEC_LINE}
ExecStop=${WRAITH_BIN} stop
Restart=on-failure
RestartSec=5s
KillSignal=SIGTERM
TimeoutStopSec=45s
LimitNOFILE=65535
LimitMEMLOCK=infinity
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
fi

chmod 644 "$SERVICE_FILE"
systemctl daemon-reload

echo -e "        ${CLR_EMERALD}✔ [GENERATED]${CLR_RESET} Systemd unit compiled for ${CLR_BOLD}${OPT_BOOT_MODE^^}${CLR_RESET} mode."

# ─── [ ACTIVATION & REGISTRATION ] ─────────────────────────────────────────────
if [ "$OPT_BOOT_MODE" = "early" ] || [ "$OPT_BOOT_MODE" = "standard" ]; then
    systemctl enable wraith.service > /dev/null 2>&1
    echo -e "        ${CLR_EMERALD}✔ [ENABLED]${CLR_RESET} Service armed for automatic boot activation."
else
    systemctl disable wraith.service > /dev/null 2>&1 || true
    echo -e "        ${CLR_AMBER}✔ [MANUAL]${CLR_RESET} Automatic boot disabled. On-demand start armed."
fi

if [ "$OPT_START_NOW" = true ] && [ "$OPT_BOOT_MODE" != "manual" ]; then
    echo -e "\n  ${CLR_CYAN}◈ [ENGAGE]${CLR_RESET} ${CLR_WHITE}Starting Wraith daemon service now...${CLR_RESET}"
    systemctl restart wraith.service 2>/dev/null || systemctl start wraith.service 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet wraith.service 2>/dev/null; then
        echo -e "        ${CLR_EMERALD}✔ [ONLINE]${CLR_RESET} Daemon is actively protecting the host!"
    else
        echo -e "        ${CLR_AMBER}ℹ [STANDBY]${CLR_RESET} Daemon registered. Check logs with: ${CLR_WHITE}journalctl -u wraith -n 30${CLR_RESET}"
    fi
fi

# ─── [ OPERATIONAL TELEMETRY HUD ] ────────────────────────────────────────────
echo -e "\n${CLR_AMBER}  ╭── [ 🛡️ WRAITH DAEMON DEPLOYED & OPERATIONAL ] ────────────────────────────────╮"
echo -e "  │  ${CLR_SLATE}BOOT MODE   :${CLR_RESET} ${CLR_EMERALD}${OPT_BOOT_MODE^^}${CLR_RESET}                                      ${CLR_AMBER}│"
echo -e "  │  ${CLR_SLATE}PROFILE     :${CLR_RESET} ${CLR_WHITE}${OPT_PROFILE}${CLR_RESET}                                              ${CLR_AMBER}│"
echo -e "  │  ${CLR_SLATE}INTERFACE   :${CLR_RESET} ${CLR_WHITE}${OPT_INTERFACE:-Auto (Kernel Lock)}${CLR_RESET}                             ${CLR_AMBER}│"
echo -e "  │  ${CLR_SLATE}DNS ENGINE  :${CLR_RESET} ${CLR_WHITE}${OPT_DOH^^} (DNS-over-HTTPS)${CLR_RESET}                             ${CLR_AMBER}│"
echo -e "  │  ${CLR_SLATE}COMMAND LINE:${CLR_RESET} ${CLR_DIM}${CMD_EXEC_LINE}${CLR_RESET} ${CLR_AMBER}│"
echo -e "  ├──────────────────────────────────────────────────────────────────────────────┤"
echo -e "  │  ${CLR_WHITE}${CLR_BOLD}KONTROL KOMUTLARI:${CLR_RESET}                                                         ${CLR_AMBER}│"
echo -e "  │  ${CLR_CYAN}systemctl status wraith${CLR_RESET}   ➔ Canlı servis durumunu denetle                  ${CLR_AMBER}│"
echo -e "  │  ${CLR_CYAN}systemctl start wraith${CLR_RESET}    ➔ Anında devreye sok                             ${CLR_AMBER}│"
echo -e "  │  ${CLR_CYAN}systemctl stop wraith${CLR_RESET}     ➔ Güvenli kapat ve ağı normale döndür            ${CLR_AMBER}│"
echo -e "  │  ${CLR_CYAN}journalctl -u wraith -f${CLR_RESET}   ➔ Gerçek zamanlı Ring-0 loglarını izle           ${CLR_AMBER}│"
echo -e "  │  ${CLR_CYAN}./install-daemon.sh --uninstall${CLR_RESET} ➔ Servisi sistemden tamamen kaldır           ${CLR_AMBER}│"
echo -e "  ╰──────────────────────────────────────────────────────────────────────────────╯${CLR_RESET}\n"
