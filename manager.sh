#!/bin/bash
################################################################################
# SCRIPT: manager.sh
# DESCRIZIONE: Manager interattivo per recognize.sh e analyze.sh.
#              Gestisce avvio, aggiornamenti, storico sessioni e dipendenze.
#
# AUTORE: Scotti Davide - Università Statale degli Studi di Milano
# VERSIONE: 2.1
# DATA: 2026-06-22
#
# USO: ./manager.sh
################################################################################

# NOTA: NON usiamo set -e per garantire resilienza.
set -uo pipefail

# Error handler non-bloccante
error_handler() {
    local line=$1
    local cmd=$2
    local rc=$3
    echo -e "\e[31m[!] ERRORE RECUPERATO (linea $line): comando '$cmd' terminato con codice $rc\e[0m" >&2
}
trap 'error_handler $LINENO "$BASH_COMMAND" $?' ERR

# ============================================================================
# CONFIGURAZIONE
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECOGNIZE="$SCRIPT_DIR/recognize.sh"
ANALYZE="$SCRIPT_DIR/analyze.sh"
INSTALL="$SCRIPT_DIR/install.sh"
SESSIONS_DIR="$SCRIPT_DIR/sessioni"
MANAGER_LOG="$SCRIPT_DIR/manager.log"
NVD_CACHE="$HOME/.cache/recognize_nvd/cvss_cache.json"
RECON_CONF="$SCRIPT_DIR/recon.conf"
MAX_LOG_SIZE_MB=10

# Colori
RED='\e[31m'; YEL='\e[33m'; GRN='\e[32m'; CYN='\e[36m'
BLU='\e[34m'; RST='\e[0m';  BLD='\e[1m';  GRY='\e[90m'

mkdir -p "$SESSIONS_DIR"

# ============================================================================
# LOGGING CON ROTAZIONE AUTOMATICA
# ============================================================================
log() {
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] $*" >> "$MANAGER_LOG" 2>/dev/null || true
    # Rotazione automatica se il log supera MAX_LOG_SIZE_MB
    if [ -f "$MANAGER_LOG" ]; then
        local size_mb
        size_mb=$(($(stat -c%s "$MANAGER_LOG" 2>/dev/null || echo 0) / 1048576)) 2>/dev/null || size_mb=0
        if [ "$size_mb" -gt "$MAX_LOG_SIZE_MB" ] 2>/dev/null; then
            mv "$MANAGER_LOG" "${MANAGER_LOG}.1" 2>/dev/null || true
            touch "$MANAGER_LOG" 2>/dev/null || true
            # Mantieni solo gli ultimi 3 log ruotati
            rm -f "${MANAGER_LOG}.3" 2>/dev/null || true
            mv "${MANAGER_LOG}.2" "${MANAGER_LOG}.3" 2>/dev/null || true
            mv "${MANAGER_LOG}.1" "${MANAGER_LOG}.2" 2>/dev/null || true
        fi
    fi
}

# ============================================================================
# PARSING CONFIGURAZIONE YAML (via Python/pyyaml)
# ============================================================================
load_config() {
    if [ -f "$RECON_CONF" ]; then
        if python3 -c "import yaml" 2>/dev/null; then
            python3 - "$RECON_CONF" << 'PYEOF' 2>/dev/null || true
import sys, os, yaml
try:
    with open(sys.argv[1]) as f:
        cfg = yaml.safe_load(f)
    if cfg:
        for section, values in cfg.items():
            if isinstance(values, dict):
                for key, val in values.items():
                    env_key = f"RECON_{section.upper()}_{key.upper()}"
                    os.environ[env_key] = str(val)
except Exception as e:
    print(f"[CONFIG] Warning: {e}", file=sys.stderr)
PYEOF
        fi
    fi
}

# Carica configurazione all'avvio
load_config

# ============================================================================
# FUNZIONI UI
# ============================================================================
clear_screen() { clear; }

header() {
    clear_screen
    echo -e "${BLU}╔═══════════════════════════════════════════════════════════════════╗${RST}"
    echo -e "${BLU}║                                                                   ║${RST}"
    echo -e "${BLU}║   ${BLD}⚡ RECON MANAGER${RST}${BLU}  —  Scotti Davide  —  UniMi              ║${RST}"
    echo -e "${BLU}║                                                                   ║${RST}"
    echo -e "${BLU}╚═══════════════════════════════════════════════════════════════════╝${RST}"
    echo -e "${GRY}   $(date '+%A %d %B %Y — %H:%M:%S') | $(hostname)${RST}"
    echo ""
}

divider() {
    echo -e "${BLU}───────────────────────────────────────────────────────────────────${RST}"
}

press_enter() {
    echo ""
    read -rp "  Premi INVIO per continuare..." _
}

confirm() {
    local msg="$1"
    read -rp "  $msg [si/no]: " ans
    [[ "$ans" == "si" ]]
}

# ============================================================================
# FUNZIONE: Esecuzione script in subshell per isolamento directory
# ============================================================================
run_script_in_sessions() {
    local script_path="$1"
    shift
    local args=("$@")

    # Usa subshell per non alterare la directory corrente
    (
        cd "$SESSIONS_DIR" || {
            echo -e "${RED}Errore accesso $SESSIONS_DIR${RST}" >&2
            return 1
        }
        if [ "$EUID" -ne 0 ]; then
            sudo bash "$script_path" "${args[@]}" || true
        else
            bash "$script_path" "${args[@]}" || true
        fi
    )
    return $?
}

# ============================================================================
# FUNZIONE: Stato dipendenze (barra di stato nel menu)
# ============================================================================
status_bar() {
    local recognize_ok analyze_ok install_ok
    recognize_ok="${GRN}OK${RST}";  [ ! -x "$RECOGNIZE" ] && recognize_ok="${RED}MANCANTE${RST}"
    analyze_ok="${GRN}OK${RST}";    [ ! -x "$ANALYZE"   ] && analyze_ok="${RED}MANCANTE${RST}"
    install_ok="${GRN}OK${RST}";    [ ! -x "$INSTALL"   ] && install_ok="${YEL}NON TROVATO${RST}"

    local nmap_ok python_ok
    nmap_ok="${GRN}✓${RST}";   command -v nmap   &>/dev/null || nmap_ok="${RED}✗${RST}"
    python_ok="${GRN}✓${RST}"; command -v python3 &>/dev/null || python_ok="${RED}✗${RST}"

    echo -e "  ${GRY}Script:${RST}  recognize[$recognize_ok]  analyze[$analyze_ok]  install[$install_ok]"
    echo -e "  ${GRY}Tool:${RST}    nmap[$nmap_ok]  python3[$python_ok]"
    echo ""
}

# ============================================================================
# FUNZIONE: Conta sessioni salvate
# ============================================================================
count_sessions() {
    find "$SESSIONS_DIR" -maxdepth 1 -name "ricognizione_*" -type d 2>/dev/null | wc -l || echo 0
}

count_json_reports() {
    find "$SESSIONS_DIR" -maxdepth 2 -name "report.json" 2>/dev/null | wc -l || echo 0
}

# ============================================================================
# FUNZIONE: Validazione IP rapida (IPv4 + hostname)
# ============================================================================
validate_ip_quick() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r a b c d <<< "$ip"
        for oct in $a $b $c $d; do
            (( oct > 255 )) && return 1
        done
        return 0
    fi
    # Hostname: caratteri validi
    [[ "$ip" =~ ^[a-zA-Z0-9._-]+$ ]] && return 0
    return 1
}

# ============================================================================
# FUNZIONE: Verifica whitelist target (da recon.conf)
# ============================================================================
check_target_allowed() {
    local target="$1"
    local allowed="${RECON_SECURITY_ALLOWED_TARGETS:-}"
    [ -z "$allowed" ] || [ "$allowed" = "[]" ] && return 0
    # Parsing semplice: supporta CIDR e IP singoli
    IFS=',' read -ra ALLOWED_LIST <<< "$(echo "$allowed" | tr -d '[]" ')" 2>/dev/null || true
    for entry in "${ALLOWED_LIST[@]}"; do
        [ -z "$entry" ] && continue
        # CIDR match
        if [[ "$entry" == */* ]]; then
            if command -v python3 &>/dev/null; then
                python3 -c "
import ipaddress
try:
    net = ipaddress.ip_network('$entry', strict=False)
    ip = ipaddress.ip_address('$target')
    print(ip in net)
except:
    print('False')
" 2>/dev/null | grep -q "True" && return 0
            fi
        else
            [ "$target" = "$entry" ] && return 0
        fi
    done
    echo -e "${RED}[-] Target $target non consentito dalla whitelist (allowed_targets in recon.conf)${RST}"
    return 1
}

# ============================================================================
# OPZIONE 1: Avvia nuova ricognizione (recognize.sh)
# ============================================================================
menu_recognize() {
    header
    echo -e "  ${BLD}[1] NUOVA RICOGNIZIONE${RST}"
    divider
    echo ""

    # Controlla script
    if [ ! -f "$RECOGNIZE" ]; then
        echo -e "  ${RED}[-] recognize.sh non trovato in: $SCRIPT_DIR${RST}"
        echo -e "      Assicurati che tutti gli script siano nella stessa directory."
        press_enter; return
    fi

    # Controlla root
    if [ "$EUID" -ne 0 ]; then
        echo -e "  ${YEL}[!] nmap SYN scan (-sS) richiede root.${RST}"
        echo -e "      Il sistema potrebbe richiedere la password sudo."
        echo ""
    fi

    # Richiedi target
    while true; do
        read -rp "  ➤ Inserisci IP o hostname target: " TARGET_INPUT
        TARGET_INPUT="${TARGET_INPUT// /}"  # rimuovi spazi
        if [ -z "$TARGET_INPUT" ]; then
            echo -e "  ${RED}Input vuoto.${RST}"; continue
        fi
        if ! validate_ip_quick "$TARGET_INPUT"; then
            echo -e "  ${RED}Formato non valido. Inserisci un IP (es. 192.168.1.1) o hostname.${RST}"
            continue
        fi
        # Verifica whitelist
        if ! check_target_allowed "$TARGET_INPUT"; then
            press_enter; return
        fi
        break
    done

    echo ""
    echo -e "  ${CYN}Target:${RST} $TARGET_INPUT"
    echo ""

    log "Avvio recognize.sh — target: $TARGET_INPUT"

    run_script_in_sessions "$RECOGNIZE" "$TARGET_INPUT" || true
    STATUS=$?

    echo ""
    if [ "$STATUS" -eq 0 ]; then
        log "recognize.sh completato con successo — target: $TARGET_INPUT"
        echo -e "  ${GRN}[✓] Ricognizione completata. Output salvato in: $SESSIONS_DIR${RST}"
        echo ""

        # Proponi fase 2 — trova l'ultimo report per timestamp
        local last_json
        last_json=$(find "$SESSIONS_DIR" -name "report.json" -printf '%T@ %p\0' 2>/dev/null \
                    | sort -rnz | head -zn1 | cut -zd' ' -f2-)
        if [ -n "$last_json" ] && confirm "Vuoi avviare subito la Fase 2 (analyze.sh) su questo report?"; then
            run_analyze "$last_json"
        fi
    else
        log "recognize.sh terminato con codice $STATUS — target: $TARGET_INPUT"
        echo -e "  ${YEL}[!] Script terminato (codice $STATUS). Controlla i log.${RST}"
    fi
    press_enter
}

# ============================================================================
# FUNZIONE: Esegui analyze.sh su un JSON
# ============================================================================
run_analyze() {
    local json_file="$1"

    if [ ! -f "$ANALYZE" ]; then
        echo -e "  ${RED}[-] analyze.sh non trovato in: $SCRIPT_DIR${RST}"
        return
    fi

    log "Avvio analyze.sh — input: $json_file"
    run_script_in_sessions "$ANALYZE" "$json_file" || true
    STATUS=$?

    if [ "$STATUS" -eq 0 ]; then
        log "analyze.sh completato — input: $json_file"
        echo -e "\n  ${GRN}[✓] Analisi Fase 2 completata.${RST}"
    else
        log "analyze.sh terminato con codice $STATUS"
        echo -e "\n  ${YEL}[!] Analisi terminata (codice $STATUS).${RST}"
    fi
}

# ============================================================================
# OPZIONE 2: Analisi Fase 2 da JSON esistente
# ============================================================================
menu_analyze() {
    header
    echo -e "  ${BLD}[2] ANALISI FASE 2 — da report.json esistente${RST}"
    divider
    echo ""

    # Cerca tutti i report.json nelle sessioni
    mapfile -t JSON_FILES < <(find "$SESSIONS_DIR" -name "report.json" 2>/dev/null | sort -r)

    if [ ${#JSON_FILES[@]} -eq 0 ]; then
        echo -e "  ${YEL}[!] Nessun report.json trovato in $SESSIONS_DIR${RST}"
        echo -e "      Esegui prima una ricognizione (opzione 1)."
        press_enter; return
    fi

    echo -e "  ${CYN}Report disponibili:${RST}"
    echo ""
    local i=1
    for jf in "${JSON_FILES[@]}"; do
        local session_dir; session_dir=$(dirname "$jf")
        local session_name; session_name=$(basename "$session_dir")
        # Estrai metadata dal JSON
        local target mode
        target=$(python3 -c "import json; d=json.load(open('$jf')); print(d['meta']['target'])" 2>/dev/null || echo "?")
        mode=$(python3 -c "import json; d=json.load(open('$jf')); print(d['meta']['mode'])" 2>/dev/null || echo "?")
        local n_hosts
        n_hosts=$(python3 -c "import json; d=json.load(open('$jf')); print(len(d['hosts']))" 2>/dev/null || echo "?")
        local n_cves
        n_cves=$(python3 -c "import json; d=json.load(open('$jf')); print(sum(len(h['cves']) for h in d['hosts']))" 2>/dev/null || echo "?")

        printf "  ${CYN}%2d)${RST}  %-35s  target=${YEL}%-15s${RST}  host=${GRN}%s${RST}  CVE=${RED}%s${RST}  mode=%s\n" \
            "$i" "$session_name" "$target" "$n_hosts" "$n_cves" "$mode"
        ((i++)) || true
    done

    echo ""
    echo -e "  ${GRY}0) Annulla${RST}"
    echo ""
    read -rp "  ➤ Scegli report [0-$((i-1))]: " CHOICE

    [[ "$CHOICE" == "0" || -z "$CHOICE" ]] && return
    if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || (( CHOICE < 1 || CHOICE >= i )); then
        echo -e "  ${RED}Scelta non valida.${RST}"; press_enter; return
    fi

    local selected_json="${JSON_FILES[$((CHOICE-1))]}"
    echo ""
    echo -e "  ${CYN}Avvio analyze.sh su: $selected_json${RST}"
    echo ""
    run_analyze "$selected_json"
    press_enter
}

# ============================================================================
# OPZIONE 3: Batch scanning (multi-target da file)
# ============================================================================
menu_batch() {
    header
    echo -e "  ${BLD}[3] BATCH SCANNING — target multipli da file${RST}"
    divider
    echo ""
    echo -e "  ${CYN}Batch scanning permette di scansionare più IP/hostname in una volta sola.${RST}"
    echo -e "  ${GRY}Il file deve contenere un target per riga. Righe vuote e commenti (#) vengono ignorati.${RST}"
    echo ""

    # Controlla script
    if [ ! -f "$RECOGNIZE" ]; then
        echo -e "  ${RED}[-] recognize.sh non trovato in: $SCRIPT_DIR${RST}"
        press_enter; return
    fi

    read -rp "  ➤ Percorso file targets (es. /home/user/targets.txt): " BATCH_FILE
    BATCH_FILE="${BATCH_FILE// /}"

    if [ -z "$BATCH_FILE" ]; then
        echo -e "  ${RED}Nessun file specificato.${RST}"
        press_enter; return
    fi

    if [ ! -f "$BATCH_FILE" ]; then
        echo -e "  ${RED}[-] File non trovato: $BATCH_FILE${RST}"
        press_enter; return
    fi

    # Conta target
    local n_targets
    n_targets=$(grep -cvE '^\s*(#|$)' "$BATCH_FILE" || echo 0)
    echo ""
    echo -e "  ${CYN}File:${RST} $BATCH_FILE"
    echo -e "  ${CYN}Target trovati:${RST} $n_targets"
    echo ""

    if [ "$n_targets" -eq 0 ]; then
        echo -e "  ${YEL}[!] Nessun target valido nel file.${RST}"
        press_enter; return
    fi

    echo -e "  ${GRY}Anteprima primi 5 target:${RST}"
    grep -vE '^\s*(#|$)' "$BATCH_FILE" | head -5 | while read -r line; do
        echo -e "    ${GRY}→${RST} $(echo "$line" | sed 's/#.*//' | tr -d '[:space:]')"
    done
    echo ""

    if ! confirm "Avviare batch scanning su $n_targets target?"; then
        echo -e "  ${YEL}Operazione annullata.${RST}"
        press_enter; return
    fi

    echo ""
    log "Avvio batch scanning — file: $BATCH_FILE ($n_targets target)"

    run_script_in_sessions "$RECOGNIZE" --batch "$BATCH_FILE" || true
    STATUS=$?

    if [ "$STATUS" -eq 0 ]; then
        log "Batch completato con successo — file: $BATCH_FILE"
        echo -e "\n  ${GRN}[✓] Batch completato. Output in sessioni/.${RST}"
    else
        log "Batch terminato con codice $STATUS"
        echo -e "\n  ${YEL}[!] Batch terminato (codice $STATUS).${RST}"
    fi
    press_enter
}

# ============================================================================
# OPZIONE 4: Storico sessioni
# ============================================================================
menu_sessions() {
    header
    echo -e "  ${BLD}[4] STORICO SESSIONI${RST}"
    divider
    echo ""

    mapfile -t SESSIONS < <(find "$SESSIONS_DIR" -maxdepth 1 -name "ricognizione_*" -type d 2>/dev/null | sort -r)
    mapfile -t ANALYSES < <(find "$SESSIONS_DIR" -maxdepth 1 -name "analisi_*"      -type d 2>/dev/null | sort -r)

    if [ ${#SESSIONS[@]} -eq 0 ] && [ ${#ANALYSES[@]} -eq 0 ]; then
        echo -e "  ${YEL}Nessuna sessione trovata.${RST}"
        press_enter; return
    fi

    if [ ${#SESSIONS[@]} -gt 0 ]; then
        echo -e "  ${CYN}Sessioni recognize.sh:${RST}"
        for s in "${SESSIONS[@]}"; do
            local name; name=$(basename "$s")
            local n_files; n_files=$(find "$s" -type f | wc -l)
            local size; size=$(du -sh "$s" 2>/dev/null | cut -f1)
            local has_json=""
            [ -f "$s/report.json" ] && has_json="${GRN}[JSON✓]${RST}"
            local n_cves=""
            [ -f "$s/macchine_vulnerabili.txt" ] && \
                n_cves="CVE=$(grep -c 'CVE-' "$s/macchine_vulnerabili.txt" 2>/dev/null || echo 0)"
            printf "    ${GRY}%-40s${RST}  ${YEL}%-6s${RST}  %s file  %s %s\n" \
                "$name" "$size" "$n_files" "$n_cves" "$has_json"
        done
        echo ""
    fi

    if [ ${#ANALYSES[@]} -gt 0 ]; then
        echo -e "  ${CYN}Sessioni analyze.sh:${RST}"
        for s in "${ANALYSES[@]}"; do
            local name; name=$(basename "$s")
            local size; size=$(du -sh "$s" 2>/dev/null | cut -f1)
            printf "    ${GRY}%-40s${RST}  ${YEL}%-6s${RST}\n" "$name" "$size"
        done
        echo ""
    fi

    divider
    echo -e "  ${GRY}Totale sessioni: ${#SESSIONS[@]} ricognizioni, ${#ANALYSES[@]} analisi${RST}"
    echo ""
    echo -e "  ${YEL}a) Apri cartella sessioni in file manager${RST}"
    echo -e "  ${RED}b) Elimina sessioni vecchie (> 30 giorni)${RST}"
    echo -e "  ${GRY}0) Torna al menu${RST}"
    echo ""
    read -rp "  ➤ Scelta: " SCELTA

    case "$SCELTA" in
        a)
            if command -v xdg-open &>/dev/null; then
                xdg-open "$SESSIONS_DIR" &
            else
                echo -e "  ${YEL}Percorso: $SESSIONS_DIR${RST}"
            fi
            ;;
        b)
            if confirm "Eliminare definitivamente le sessioni più vecchie di 30 giorni?"; then
                find "$SESSIONS_DIR" -maxdepth 1 \
                    \( -name "ricognizione_*" -o -name "analisi_*" \) \
                    -type d -mtime +30 -exec rm -rf {} + 2>/dev/null
                log "Pulizia sessioni >30gg eseguita"
                echo -e "  ${GRN}[✓] Sessioni vecchie eliminate${RST}"
            fi
            ;;
    esac
    press_enter
}

# ============================================================================
# OPZIONE 5: Installazione / Aggiornamento
# ============================================================================
menu_install() {
    header
    echo -e "  ${BLD}[5] INSTALLAZIONE / AGGIORNAMENTO${RST}"
    divider
    echo ""
    echo -e "  ${CYN}1)${RST} Installazione completa (prima volta)"
    echo -e "  ${CYN}2)${RST} Aggiornamento pacchetti + nmap scripts + testssl"
    echo -e "  ${CYN}3)${RST} Verifica stato dipendenze (solo check, nessuna modifica)"
    echo -e "  ${GRY}0)${RST} Torna al menu"
    echo ""
    read -rp "  ➤ Scelta: " SCELTA

    case "$SCELTA" in
        1)
            if [ ! -f "$INSTALL" ]; then
                echo -e "  ${RED}install.sh non trovato in $SCRIPT_DIR${RST}"; press_enter; return
            fi
            echo ""
            log "Avvio installazione completa"
            sudo bash "$INSTALL" || true
            log "Installazione completata"
            ;;
        2)
            if [ ! -f "$INSTALL" ]; then
                echo -e "  ${RED}install.sh non trovato${RST}"; press_enter; return
            fi
            echo ""
            log "Avvio aggiornamento pacchetti"
            sudo bash "$INSTALL" --update-only || true
            log "Aggiornamento completato"
            ;;
        3)
            echo ""
            bash "$INSTALL" --check-only 2>/dev/null || {
                # Fallback se install.sh non c'è
                echo -e "  ${CYN}Verifica tool:${RST}"
                for tool in nmap curl python3 nikto enum4linux snmpwalk \
                            hydra whois testssl testssl.sh graphviz; do
                    if command -v "$tool" &>/dev/null; then
                        printf "    ${GRN}✅  %-20s${RST}\n" "$tool"
                    else
                        printf "    ${RED}❌  %-20s${RST}\n" "$tool"
                    fi
                done
            }
            ;;
        0) return ;;
        *) echo -e "  ${RED}Scelta non valida.${RST}" ;;
    esac
    press_enter
}

# ============================================================================
# OPZIONE 6: Gestione cache NVD
# ============================================================================
menu_cache() {
    header
    echo -e "  ${BLD}[6] GESTIONE CACHE NVD${RST}"
    divider
    echo ""

    if [ ! -f "$NVD_CACHE" ]; then
        echo -e "  ${YEL}Cache non trovata: $NVD_CACHE${RST}"
        echo -e "  Verrà creata automaticamente al primo utilizzo di recognize.sh"
        press_enter; return
    fi

    # Statistiche cache
    local n_entries size_kb
    n_entries=$(python3 -c "import json; d=json.load(open('$NVD_CACHE')); print(len(d))" 2>/dev/null || echo "?")
    size_kb=$(du -k "$NVD_CACHE" 2>/dev/null | cut -f1)

    echo -e "  ${CYN}File:${RST}     $NVD_CACHE"
    echo -e "  ${CYN}Voci:${RST}     $n_entries CVE in cache"
    echo -e "  ${CYN}Dimensione:${RST} ${size_kb}KB"
    echo ""

    if [ "$n_entries" != "?" ] && (( n_entries > 0 )); then
        echo -e "  ${CYN}CVE in cache:${RST}"
        python3 - "$NVD_CACHE" << 'PYEOF' 2>/dev/null || true
import json, sys
data = json.load(open(sys.argv[1]))
for cve, info in sorted(data.items()):
    print(f"    {cve:<20}  AV={info.get('av','?'):<20}  Score={info.get('score','?')}")
PYEOF
    fi

    echo ""
    divider
    echo -e "  ${RED}1) Svuota cache (forza re-fetch NVD al prossimo run)${RST}"
    echo -e "  ${GRY}0) Torna al menu${RST}"
    echo ""
    read -rp "  ➤ Scelta: " SCELTA

    case "$SCELTA" in
        1)
            if confirm "Svuotare la cache NVD?"; then
                echo '{}' > "$NVD_CACHE"
                log "Cache NVD svuotata"
                echo -e "  ${GRN}[✓] Cache svuotata${RST}"
            fi
            ;;
    esac
    press_enter
}

# ============================================================================
# OPZIONE 7: Visualizza log manager
# ============================================================================
menu_log() {
    header
    echo -e "  ${BLD}[7] LOG MANAGER${RST}"
    divider
    echo ""

    if [ ! -f "$MANAGER_LOG" ]; then
        echo -e "  ${YEL}Log non ancora disponibile.${RST}"
        press_enter; return
    fi

    local lines
    lines=$(wc -l < "$MANAGER_LOG")
    echo -e "  ${CYN}$MANAGER_LOG${RST} (${lines} righe)"
    echo ""
    tail -40 "$MANAGER_LOG"
    echo ""
    divider
    echo -e "  ${RED}1) Cancella log${RST}  ${GRY}0) Torna al menu${RST}"
    echo ""
    read -rp "  ➤ Scelta: " SCELTA
    [[ "$SCELTA" == "1" ]] && confirm "Cancellare il log?" && \
        { > "$MANAGER_LOG"; echo -e "  ${GRN}[✓] Log cancellato${RST}"; }
    press_enter
}

# ============================================================================
# OPZIONE 8: Genera report PDF da report.json esistente
# ============================================================================
menu_pdf() {
    header
    echo -e "  ${BLD}[8] GENERA REPORT PDF${RST}"
    divider
    echo ""

    local pdf_script="$SCRIPT_DIR/report_pdf.sh"
    if [ ! -f "$pdf_script" ]; then
        echo -e "  ${RED}[-] report_pdf.sh non trovato in: $SCRIPT_DIR${RST}"
        echo -e "      Assicurati che lo script sia nella stessa directory."
        press_enter; return
    fi

    # Verifica reportlab
    python3 -c "import reportlab" 2>/dev/null || {
        echo -e "  ${YEL}[!] reportlab non installato. Installa con: pip3 install --user reportlab${RST}"
        echo ""
        if confirm "Installare reportlab ora?"; then
            pip3 install --user reportlab 2>/dev/null && echo -e "  ${GRN}[✓] reportlab installato${RST}" || \
                echo -e "  ${RED}[-] Installazione fallita${RST}"
        fi
    }

    # Cerca tutti i report.json
    mapfile -t JSON_FILES < <(find "$SESSIONS_DIR" -name "report.json" 2>/dev/null | sort -r)

    if [ ${#JSON_FILES[@]} -eq 0 ]; then
        echo -e "  ${YEL}[!] Nessun report.json trovato in $SESSIONS_DIR${RST}"
        echo -e "      Esegui prima una ricognizione (opzione 1)."
        press_enter; return
    fi

    echo -e "  ${CYN}Report disponibili:${RST}"
    echo ""
    local i=1
    for jf in "${JSON_FILES[@]}"; do
        local session_dir; session_dir=$(dirname "$jf")
        local session_name; session_name=$(basename "$session_dir")
        local target
        target=$(python3 -c "import json; d=json.load(open('$jf')); print(d['meta']['target'])" 2>/dev/null || echo "?")
        printf "  ${CYN}%2d)${RST}  %-35s  target=${YEL}%-15s${RST}\n" \
            "$i" "$session_name" "$target"
        ((i++)) || true
    done

    echo ""
    echo -e "  ${GRY}0) Annulla${RST}"
    echo ""
    read -rp "  ➤ Scegli report [0-$((i-1))]: " CHOICE

    [[ "$CHOICE" == "0" || -z "$CHOICE" ]] && return
    if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || (( CHOICE < 1 || CHOICE >= i )); then
        echo -e "  ${RED}Scelta non valida.${RST}"; press_enter; return
    fi

    local selected_json="${JSON_FILES[$((CHOICE-1))]}"
    local output_pdf="${selected_json%.json}_report.pdf"

    echo ""
    echo -e "  ${CYN}Generazione PDF da: $selected_json${RST}"
    echo -e "  ${CYN}Output: $output_pdf${RST}"
    echo ""

    bash "$pdf_script" "$selected_json" "$output_pdf" || true
    if [ $? -eq 0 ]; then
        log "PDF generato: $output_pdf"
        echo -e "\n  ${GRN}[✓] PDF generato con successo${RST}"
    else
        log "Generazione PDF fallita"
        echo -e "\n  ${YEL}[!] Generazione PDF fallita${RST}"
    fi
    press_enter
}

# ============================================================================
# OPZIONE 9: Verifica checksum integrità script
# ============================================================================
menu_checksum() {
    header
    echo -e "  ${BLD}[9] VERIFICA INTEGRITÀ SCRIPT${RST}"
    divider
    echo ""

    if [ ! -f "$SCRIPT_DIR/checksums.sha256" ]; then
        echo -e "  ${YEL}[!] checksums.sha256 non trovato.${RST}"
        echo -e "      Genera con: cd $SCRIPT_DIR && sha256sum *.sh > checksums.sha256"
        echo ""
        if confirm "Generare checksum ora?"; then
            (cd "$SCRIPT_DIR" && sha256sum *.sh > checksums.sha256 2>/dev/null) || true
            echo -e "  ${GRN}[✓] checksums.sha256 generato${RST}"
            log "Checksum generato"
        fi
        press_enter; return
    fi

    echo -e "  ${CYN}Verifica checksum SHA256...${RST}"
    echo ""
    (cd "$SCRIPT_DIR" && sha256sum -c checksums.sha256 --quiet 2>/dev/null) || true
    local rc=$?

    if [ $rc -eq 0 ]; then
        echo -e "  ${GRN}[✓] Tutti i checksum corrispondono — integrità verificata${RST}"
        log "Checksum: OK"
    else
        echo -e "  ${RED}[-] Attenzione: alcuni file sono stati modificati!${RST}"
        echo -e "      Esegui 'sha256sum -c checksums.sha256' per dettagli."
        log "Checksum: FALLITO — file modificati"
    fi
    press_enter
}

# ============================================================================
# OPZIONE 10: Info / Guida rapida
# ============================================================================
menu_info() {
    header
    echo -e "  ${BLD}[10] GUIDA RAPIDA${RST}"
    divider
    cat << 'EOF'

  ┌─ FLUSSO DI LAVORO ─────────────────────────────────────────────────────┐
  │                                                                         │
  │   1. Prima volta?  →  Opzione [5] Installazione completa                │
  │                                                                         │
  │   2. Ricognizione  →  Opzione [1] Inserisci IP target                  │
  │      • Scegli modalità (SILENT / FAST / FAST&MASSIVE / SILENT&MASSIVE) │
  │      • Output salvato in: sessioni/ricognizione_YYYYMMDD_HHMMSS/       │
  │      • Genera: scan TCP+UDP, CVE analysis, mappa PNG, report.json      │
  │                                                                         │
  │   3. Analisi Fase 2 →  Opzione [2] Scegli report.json                  │
  │      • Esegue: nikto, testssl, enum4linux, snmpwalk, whois, hydra      │
  │      • Output in: sessioni/analisi_YYYYMMDD_HHMMSS/                    │
  │                                                                         │
  │   4. Report PDF    →  Opzione [8] Genera report PDF professionale      │
  │                                                                         │
  │   5. Storico       →  Opzione [4] Sessioni passate + pulizia           │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘

  ┌─ MODALITÀ DI SCANSIONE ────────────────────────────────────────────────┐
  │  SILENT          T2, top 100 porte,  no script, stealth massima       │
  │  FAST            T4, top 1000 porte, vulners, no decoy                │
  │  FAST & MASSIVE  T5, tutte le porte, vulners, molto rumorosa          │
  │  SILENT&MASSIVE  T2, tutte le porte, vulners, decoy+spoof             │
  └─────────────────────────────────────────────────────────────────────────┘

  ┌─ SCORING CVE (3 livelli) ──────────────────────────────────────────────┐
  │  1. OS Backporting  → distro patcha o usa vaniglia?                    │
  │  2. CVSS AV         → NETWORK/LOCAL/PHYSICAL (da NVD o cache)         │
  │  3. Config reale    → SSH algo, HSTS, server-status...                 │
  │  ─────────────────────────────────────────────────────                 │
  │  ≥70 → 🔴 VULNERABILITÀ CONCRETA   36-69 → 🟡 GRIGIA   ≤35 → 🟢 FP  │
  └─────────────────────────────────────────────────────────────────────────┘

  ┌─ STRUTTURA FILE ────────────────────────────────────────────────────────┐
  │  recognize.sh        Fase 1: ricognizione TCP+UDP+CVE                  │
  │  analyze.sh          Fase 2: nikto/testssl/enum4linux/snmpwalk/hydra   │
  │  install.sh          Setup dipendenze + aggiornamento                  │
  │  report_pdf.sh       Generazione report PDF                            │
  │  manager.sh          Questo script                                     │
  │  recon.conf          Configurazione YAML                               │
  │  Makefile            Comandi rapidi (build, scan, batch, pdf)          │
  │  Dockerfile          Containerizzazione                                │
  │  sessioni/           Tutte le directory di output                      │
  │  ~/.cache/recognize_nvd/cvss_cache.json    Cache NVD persistente      │
  └─────────────────────────────────────────────────────────────────────────┘

EOF
    press_enter
}

# ============================================================================
# MENU PRINCIPALE
# ============================================================================
main_menu() {
    while true; do
        header
        status_bar

        local n_sess n_json
        n_sess=$(count_sessions)
        n_json=$(count_json_reports)

        echo -e "  ${BLD}MENU PRINCIPALE${RST}"
        divider
        echo ""
        echo -e "  ${CYN}1)${RST}  ${BLD}Nuova ricognizione${RST}          (recognize.sh)"
        echo -e "  ${CYN}2)${RST}  ${BLD}Analisi Fase 2${RST}              (analyze.sh)   ${GRY}[$n_json report disponibili]${RST}"
        echo -e "  ${CYN}3)${RST}  ${BLD}Batch scanning${RST}              (multi-target da file)"
        echo -e "  ${CYN}4)${RST}  ${BLD}Storico sessioni${RST}                           ${GRY}[$n_sess sessioni]${RST}"
        echo -e "  ${CYN}5)${RST}  ${BLD}Installazione / Aggiornamento${RST}"
        echo -e "  ${CYN}6)${RST}  ${BLD}Cache NVD${RST}"
        echo -e "  ${CYN}7)${RST}  ${BLD}Log manager${RST}"
        echo -e "  ${CYN}8)${RST}  ${BLD}Report PDF${RST}                  (report_pdf.sh) ${GRY}[$n_json report disponibili]${RST}"
        echo -e "  ${CYN}9)${RST}  ${BLD}Verifica integrità${RST}          (checksum SHA256)"
        echo -e "  ${CYN}10)${RST} ${BLD}Guida rapida${RST}"
        echo ""
        echo -e "  ${RED}0)  Esci${RST}"
        echo ""
        divider
        read -rp "  ➤ Scelta: " CHOICE

        case "$CHOICE" in
            1) menu_recognize  ;;
            2) menu_analyze    ;;
            3) menu_batch      ;;
            4) menu_sessions   ;;
            5) menu_install    ;;
            6) menu_cache      ;;
            7) menu_log        ;;
            8) menu_pdf        ;;
            9) menu_checksum   ;;
            10) menu_info       ;;
            0)
                log "Manager chiuso"
                echo -e "\n  ${GRN}Arrivederci.${RST}\n"
                exit 0
                ;;
            *)
                echo -e "  ${RED}Scelta non valida.${RST}"
                sleep 1
                ;;
        esac
    done
}

# ============================================================================
# AVVIO
# ============================================================================
log "Manager avviato — utente: $(whoami) — dir: $SCRIPT_DIR"
main_menu