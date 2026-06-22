#!/bin/bash
################################################################################
# SCRIPT: install.sh
# DESCRIZIONE: Installazione e aggiornamento di tutte le dipendenze
#              necessarie per recognize.sh e analyze.sh.
#
# AUTORE: Scotti Davide - Università Statale degli Studi di Milano
# VERSIONE: 1.4
# DATA: 2026-06-08
#
# USO: sudo ./install.sh [--update-only] [--check-only]
################################################################################

set -u

# ============================================================================
# CONFIGURAZIONE
# ============================================================================
TESTSSL_URL="https://github.com/drwetter/testssl.sh/releases/latest/download/testssl.sh"
TESTSSL_DEST="/usr/local/bin/testssl.sh"
INSTALL_LOG="/var/log/recon_install.log"
MIN_DISK_MB=500

RED='\e[31m'; YEL='\e[33m'; GRN='\e[32m'; CYN='\e[36m'; RST='\e[0m'; BLD='\e[1m'

# ============================================================================
# FUNZIONI DI SUPPORTO
# ============================================================================
log() {
    local level="$1" msg="$2"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] [$level] $msg" >> "$INSTALL_LOG" 2>/dev/null || true
    case "$level" in
        OK)    echo -e "${GRN}   [✓] $msg${RST}" ;;
        INFO)  echo -e "${CYN}   [*] $msg${RST}" ;;
        WARN)  echo -e "${YEL}   [!] $msg${RST}" ;;
        ERROR) echo -e "${RED}   [-] $msg${RST}" >&2 ;;
        SKIP)  echo -e "\e[90m   [~] $msg${RST}" ;;
    esac
}

section() {
    echo -e "\n${CYN}┌─────────────────────────────────────────────────────────────┐${RST}"
    echo -e "${CYN}│  $1${RST}"
    echo -e "${CYN}└─────────────────────────────────────────────────────────────┘${RST}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[-] Questo script richiede i privilegi root.${RST}"
        echo -e "    Riesegui con: ${BLD}sudo $0 $*${RST}"
        exit 1
    fi
}

check_os() {
    if ! command -v apt-get &>/dev/null; then
        echo -e "${RED}[-] Sistema non Debian/Ubuntu/Kali. Questo script usa apt.${RST}"
        exit 1
    fi
    log "OK" "Sistema basato su apt rilevato"
}

check_internet() {
    log "INFO" "Verifica connessione internet..."
    if ! ping -c 1 -W 3 8.8.8.8 &>/dev/null 2>&1; then
        log "WARN" "Nessuna connessione internet. Solo installazione locale disponibile."
        return 1
    fi
    log "OK" "Connessione internet disponibile"
    return 0
}

check_disk_space() {
    local available_mb
    available_mb=$(df /usr | awk 'NR==2 {print int($4/1024)}')
    if (( available_mb < MIN_DISK_MB )); then
        log "ERROR" "Spazio insufficiente: ${available_mb}MB disponibili, ${MIN_DISK_MB}MB richiesti"
        exit 1
    fi
    log "OK" "Spazio disco: ${available_mb}MB disponibili"
}

# ============================================================================
# LISTA PACCHETTI (solo quelli realmente necessari)
# ============================================================================
REQUIRED_PKGS=(
    nmap curl bind9-dnsutils netcat-openbsd graphviz iputils-ping python3
)
OPTIONAL_PKGS=(
    nikto enum4linux snmp whois hydra
)

# ============================================================================
# INSTALLA PACCHETTI
# ============================================================================
install_packages() {
    local pkg_list=("$@")
    local to_install=()
    local already_installed=()
    local failed=()

    for pkg in "${pkg_list[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            already_installed+=("$pkg")
        else
            to_install+=("$pkg")
        fi
    done

    [ ${#already_installed[@]} -gt 0 ] && log "SKIP" "Già installati: ${already_installed[*]}"
    [ ${#to_install[@]} -eq 0 ] && { log "OK" "Tutti i pacchetti sono già presenti"; return 0; }

    log "INFO" "Installazione: ${to_install[*]}"
    for pkg in "${to_install[@]}"; do
        echo -ne "${CYN}      → $pkg...${RST} "
        if apt-get install -y -q "$pkg" >> "$INSTALL_LOG" 2>&1; then
            echo -e "${GRN}OK${RST}"
        else
            echo -e "${RED}FALLITO${RST}"
            failed+=("$pkg")
            log "WARN" "Installazione fallita: $pkg"
        fi
    done

    [ ${#failed[@]} -gt 0 ] && log "WARN" "Pacchetti non installati: ${failed[*]}" && return 1
    return 0
}

# ============================================================================
# INSTALLA TESTSSL.SH
# ============================================================================
install_testssl() {
    section "testssl.sh (SSL/TLS analyzer)"
    if [ -f "$TESTSSL_DEST" ]; then
        log "SKIP" "testssl.sh già presente in $TESTSSL_DEST"
        return 0
    fi
    log "INFO" "Download testssl.sh da GitHub..."
    if timeout 30 wget -q "$TESTSSL_URL" -O "$TESTSSL_DEST" 2>/dev/null; then
        chmod +x "$TESTSSL_DEST"
        log "OK" "testssl.sh installato in $TESTSSL_DEST"
    else
        log "WARN" "Download testssl.sh fallito (rete o URL non raggiungibile)"
    fi
}

# ============================================================================
# CHECK-ONLY
# ============================================================================
check_only() {
    section "Verifica stato installazione"
    local all_ok=true

    echo -e "\n  ${BLD}Dipendenze obbligatorie:${RST}"
    for pkg in "${REQUIRED_PKGS[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            printf "    ${GRN}✅  %-25s${RST}\n" "$pkg"
        else
            printf "    ${RED}❌  %-25s${RST}  ← MANCANTE\n" "$pkg"
            all_ok=false
        fi
    done

    echo -e "\n  ${BLD}Dipendenze opzionali (analyze.sh):${RST}"
    for pkg in "${OPTIONAL_PKGS[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            printf "    ${GRN}✅  %-25s${RST}\n" "$pkg"
        else
            printf "    ${YEL}⚠️   %-25s${RST}  (opzionale)\n" "$pkg"
        fi
    done

    if [ -f "$TESTSSL_DEST" ]; then
        printf "    ${GRN}✅  %-25s${RST}\n" "testssl.sh"
    else
        printf "    ${YEL}⚠️   %-25s${RST}  (opzionale)\n" "testssl.sh"
    fi

    echo ""
    if [ "$all_ok" = true ]; then
        log "OK" "Tutte le dipendenze obbligatorie sono soddisfatte"
    else
        log "WARN" "Alcune dipendenze obbligatorie mancanti — esegui: sudo ./install.sh"
    fi
}

# ============================================================================
# AGGIORNAMENTO PACCHETTI
# ============================================================================
update_packages() {
    section "Aggiornamento pacchetti"
    log "INFO" "apt-get update..."
    apt-get update -q >> "$INSTALL_LOG" 2>&1
    log "INFO" "Aggiornamento pacchetti installati..."
    apt-get upgrade -y -q >> "$INSTALL_LOG" 2>&1
    log "OK" "Sistema aggiornato"

    if [ -f "$TESTSSL_DEST" ]; then
        log "INFO" "Aggiornamento testssl.sh..."
        if timeout 30 wget -q "$TESTSSL_URL" -O "${TESTSSL_DEST}.new" 2>/dev/null; then
            mv "${TESTSSL_DEST}.new" "$TESTSSL_DEST"
            chmod +x "$TESTSSL_DEST"
            log "OK" "testssl.sh aggiornato"
        else
            rm -f "${TESTSSL_DEST}.new"
            log "WARN" "Aggiornamento testssl.sh fallito"
        fi
    fi

    log "INFO" "Aggiornamento nmap scripts..."
    nmap --script-updatedb >> "$INSTALL_LOG" 2>&1 || true
    log "OK" "nmap scripts aggiornati"

    if [ -d /usr/share/nmap/scripts ]; then
        log "INFO" "Verifica vulners.nse..."
        if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
            wget -q "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse" \
                -O /usr/share/nmap/scripts/vulners.nse >> "$INSTALL_LOG" 2>&1 && \
                log "OK" "vulners.nse installato" || \
                log "WARN" "Download vulners.nse fallito"
            nmap --script-updatedb >> "$INSTALL_LOG" 2>&1 || true
        else
            log "SKIP" "vulners.nse già presente"
        fi
    fi
}

# ============================================================================
# CONFIGURAZIONE POST-INSTALLAZIONE
# ============================================================================
post_install_config() {
    section "Configurazione post-installazione"

    if [ -f /etc/snmp/snmp.conf ]; then
        if grep -q "^mibs" /etc/snmp/snmp.conf; then
            sed -i 's/^mibs/#mibs/' /etc/snmp/snmp.conf
            log "OK" "SNMP MIBs abilitati"
        fi
    fi

    local cache_dir
    if [ -n "${SUDO_USER:-}" ]; then
        cache_dir="/home/$SUDO_USER/.cache/recognize_nvd"
        mkdir -p "$cache_dir"
        echo '{}' > "$cache_dir/cvss_cache.json"
        # Determina il gruppo primario dell'utente (non assume sudo_user=same group)
        local user_group
        user_group=$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")
        chown -R "$SUDO_USER:$user_group" "$cache_dir"
    else
        cache_dir="$HOME/.cache/recognize_nvd"
        mkdir -p "$cache_dir"
        echo '{}' > "$cache_dir/cvss_cache.json"
    fi
    log "OK" "Cache NVD inizializzata in $cache_dir"

    for script in recognize.sh analyze.sh manager.sh; do
        [ -f "$script" ] && chmod +x "$script" && log "OK" "$script → chmod +x"
    done
}

# ============================================================================
# MAIN
# ============================================================================
clear
echo -e "${CYN}╔═══════════════════════════════════════════════════════════════╗${RST}"
echo -e "${CYN}║  install.sh — Setup dipendenze recognize/analyze             ║${RST}"
echo -e "${CYN}║  Autore: Scotti Davide — UniMi                               ║${RST}"
echo -e "${CYN}╚═══════════════════════════════════════════════════════════════╝${RST}"
echo ""

MODE="install"
for arg in "$@"; do
    case "$arg" in
        --update-only) MODE="update" ;;
        --check-only)  MODE="check"  ;;
        --help|-h)
            echo "Uso: sudo $0 [--update-only] [--check-only]"
            exit 0 ;;
    esac
done

if [ "$MODE" = "check" ]; then
    check_only
    exit 0
fi

check_root "$@"
check_os
check_disk_space
touch "$INSTALL_LOG" 2>/dev/null || INSTALL_LOG="/tmp/recon_install.log"
log "INFO" "Log: $INSTALL_LOG"

INTERNET_OK=true
check_internet || INTERNET_OK=false

if [ "$MODE" = "update" ]; then
    if [ "$INTERNET_OK" = false ]; then
        log "ERROR" "Aggiornamento richiede connessione internet"
        exit 1
    fi
    update_packages
    post_install_config
    log "OK" "Aggiornamento completato"
    exit 0
fi

section "Aggiornamento indice apt"
apt-get update -q >> "$INSTALL_LOG" 2>&1
log "OK" "Indice aggiornato"

section "Dipendenze obbligatorie"
install_packages "${REQUIRED_PKGS[@]}"

section "Dipendenze opzionali (analyze.sh)"
install_packages "${OPTIONAL_PKGS[@]}" || true

[ "$INTERNET_OK" = true ] && install_testssl
[ "$INTERNET_OK" = true ] && update_packages

post_install_config

echo ""
echo -e "${GRN}╔═══════════════════════════════════════════════════════════════╗${RST}"
echo -e "${GRN}║  ✓ Installazione completata!                                  ║${RST}"
echo -e "${GRN}╚═══════════════════════════════════════════════════════════════╝${RST}"
echo -e "${CYN}   Log completo: $INSTALL_LOG${RST}"
echo -e "${CYN}   Prossimo passo: ./manager.sh${RST}"
echo ""
check_only