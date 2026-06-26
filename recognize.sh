#!/bin/bash
################################################################################
# SCRIPT: recognize.sh
# DESCRIZIONE: Strumento di ricognizione stealth per pentesting etico.
#              Esegue scansioni nmap TCP+UDP, analisi CVE a 3 livelli,
#              validazione falsi positivi, cache NVD persistente,
#              parallelizzazione host, output JSON e mappa di rete.
#
# AUTORE: Scotti Davide - Università Statale degli Studi di Milano
# VERSIONE: 3.4
# DATA: 2026-06-22
#
# USO: ./recognize.sh <IP_TARGET>
#       ./recognize.sh --batch <file_targets.txt>
#       ./recognize.sh --single-target <IP> [--output-dir DIR] [--nmap-timing T]
#                      [--top-ports N] [--max-parallel N] [--mode M] [--log-level L]
#
# OUTPUT: Directory con report testuali, JSON, log, mappa PNG e priorità.
################################################################################

# NOTA: NON usiamo set -e per garantire resilienza.
# Lo script deve sopravvivere a errori parziali (nmap che fallisce, CVE non trovate, etc.)
# e continuare fino al completamento di tutte le fasi.
set -uo pipefail

# ============================================================================
# CONFIGURAZIONE DEFAULT (sovrascritta da select_mode)
# ============================================================================
NMAP_TIMING="-T2"
NMAP_TOP_PORTS_INITIAL="1000"
NMAP_TOP_PORTS_DETAIL="500"
NMAP_VERSION_INTENSITY="1"
NMAP_SCRIPTS="vulners"
TIMEOUT_NVD_API=5
TIMEOUT_CURL=3
TIMEOUT_NC=3
TIMEOUT_NMAP_WEAK=5
LOG_LEVEL="INFO"
ENABLE_DEBUG_LOG=true
SPOOF_MAC="apple"
DECOY_HOSTS="RND:10"
USE_ALL_PORTS=false
USE_FRAGMENT=true
USE_DECOYS=true
USE_SPOOF=true
MAX_PARALLEL_JOBS=2
# NVD API rate limiting (5 req / 30s senza API key, 50 req/s con API key)
NVD_API_KEY="${NVD_API_KEY:-${RECON_NVD_API_KEY:-}}"
NVD_RATE_LIMIT_WINDOW=30
NVD_RATE_LIMIT_MAX=4
NVD_RATE_LIMIT_COUNTER=0
NVD_RATE_LIMIT_START=0
NVD_API_RETRIES=3

# Cache NVD persistente tra run
NVD_CACHE_DIR="$HOME/.cache/recognize_nvd"
NVD_CACHE_FILE="$NVD_CACHE_DIR/cvss_cache.json"

# Cache CVE locale (Attack Vector mapping) — sempre disponibile
declare -A CVE_AV_MAP=(
    ["CVE-2021-44228"]="NETWORK"
    ["CVE-2017-5638"]="NETWORK"
    ["CVE-2022-22965"]="NETWORK"
    ["CVE-2020-0041"]="PHYSICAL"
    ["CVE-2019-2215"]="LOCAL"
    ["CVE-2014-0160"]="NETWORK"
    ["CVE-2017-0144"]="NETWORK"
    ["CVE-2019-0708"]="NETWORK"
)

# ============================================================================
# FUNZIONE: Error handler non-bloccante — logga ma NON esce
# ============================================================================
error_handler() {
    local line=$1
    local cmd=$2
    local rc=$3
    echo -e "\e[31m[!] ERRORE RECUPERATO (linea $line): comando '$cmd' terminato con codice $rc\e[0m" >&2
    # Logga l'errore se LOG_FILE è definito
    if [ -n "${LOG_FILE:-}" ]; then
        local ts
        ts=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$ts] [ERROR] Errore recuperato linea $line: $cmd (exit=$rc)" >> "$LOG_FILE" 2>/dev/null || true
    fi
}
trap 'error_handler $LINENO "$BASH_COMMAND" $?' ERR

# ============================================================================
# FUNZIONE: Disclaimer etico — chiamata PRIMA di tutto
# ============================================================================
show_disclaimer() {
    clear
    echo -e "\e[33m"
    cat << 'EOF'
  ╔══════════════════════════════════════════════════════════════════╗
  ║                    ⚠️  AVVISO LEGALE                              ║
  ║                                                                  ║
  ║  Questo strumento è destinato ESCLUSIVAMENTE a:                  ║
  ║   • Attività di pentesting su reti di cui si è proprietari       ║
  ║   • Ambienti di laboratorio / test autorizzati                   ║
  ║   • Ricerca accademica con consenso esplicito                    ║
  ║                                                                  ║
  ║  L'uso non autorizzato viola l'art. 615-ter c.p. (Italia)        ║
  ║  e normative equivalenti internazionali.                         ║
  ║                                                                  ║
  ║  L'autore declina ogni responsabilità per usi impropri.          ║
  ╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "\e[0m"
    if [ "${NON_INTERACTIVE:-false}" = "true" ]; then
        echo -e "\e[33m  [--yes] Disclaimer accettato automaticamente (modalità non interattiva)\e[0m"
        echo ""
        return 0
    fi
    read -rp "  Ho letto e accetto. Confermo di operare su rete autorizzata [si/no]: " accept
    [[ "$accept" != "si" ]] && { echo -e "\e[31m  Uscita.\e[0m"; exit 1; }
    echo ""
}

# ============================================================================
# FUNZIONE: Validazione target (formato + RFC1918 + raggiungibilità)
# ============================================================================
validate_target() {
    local target="$1"
    local retarget="$target"
    echo -e "\e[34m╔═══════════════════════════════════════════════════════════════╗\e[0m" >&2
    echo -e "\e[34m║  [0/7] VALIDAZIONE TARGET                                ║\e[0m" >&2
    echo -e "\e[34m╚═══════════════════════════════════════════════════════════════╝\e[0m" >&2

    # A) Formato IP o hostname risolvibile
    if [[ "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r a b c d <<< "$target"
        for oct in "$a" "$b" "$c" "$d"; do
            if (( oct > 255 )); then
                echo -e "\e[31m[-] IP non valido: ottetto $oct fuori range (0-255)\e[0m" >&2
                return 1
            fi
        done
        echo -e "\e[32m   [✓] Formato IP valido\e[0m" >&2
    else
        echo -ne "\e[36m   [*] Risoluzione hostname '$target'...\e[0m" >&2
        if ! command -v host &>/dev/null; then
            echo -e "\e[33m\n   [!] 'host' non disponibile, skip risoluzione\e[0m" >&2
        else
            local resolved
            resolved=$(host "$target" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}') || true
            if [ -z "$resolved" ]; then
                echo -e "\e[31m\n[-] '$target' non è un IP valido né un hostname risolvibile\e[0m" >&2
                return 1
            fi
            retarget="$resolved"
            echo -e "\r\e[32m   [✓] Hostname risolto a: $retarget                    \e[0m" >&2
        fi
    fi

    # B) Guardia RFC 1918 — avvisa se target è pubblico
    IFS='.' read -r a b c d <<< "$retarget"
    local is_private=false
    [[ $a -eq 10 ]] && is_private=true
    [[ $a -eq 172 && $b -ge 16 && $b -le 31 ]] && is_private=true
    [[ $a -eq 192 && $b -eq 168 ]] && is_private=true
    [[ $a -eq 127 ]] && is_private=true

    if [ "$is_private" = false ]; then
        echo -e "\e[31m" >&2
        echo "  ╔══════════════════════════════════════════════════════╗" >&2
        echo "  ║  ⚠️  ATTENZIONE: IP PUBBLICO RILEVATO             ║" >&2
        printf "  ║  %-48s║\n" "  $retarget non appartiene a RFC 1918" >&2
        echo "  ║  Scansionare host non autorizzati è REATO        ║" >&2
        echo "  ╚══════════════════════════════════════════════════════╝" >&2
        echo -e "\e[0m" >&2
        read -rp "  Confermi di avere AUTORIZZAZIONE SCRITTA per $retarget? [si/no]: " confirm
        [[ "$confirm" != "si" ]] && { echo "  Uscita."; exit 0; }
    else
        echo -e "\e[32m   [✓] Target in range RFC 1918 (rete privata)\e[0m" >&2
    fi

    # C) Raggiungibilità
    echo -ne "\e[36m   [*] Verifica raggiungibilità $retarget...\e[0m" >&2
    if ! ping -c 1 -W 2 "$retarget" &>/dev/null 2>&1; then
        echo -e "\r\e[33m   [!] $retarget non risponde al ping (host down o ICMP bloccato)\e[0m" >&2
        read -rp "      Continuare comunque con -Pn? [si/no]: " cont
        [[ "$cont" != "si" ]] && exit 0
    else
        echo -e "\r\e[32m   [✓] Host raggiungibile                              \e[0m" >&2
    fi

    # Scrivi risultato su stdout per la funzione chiamante (SOLO questa riga)
    echo "$retarget"
}

# ============================================================================
# FUNZIONE: Menu modalità
# ============================================================================
select_mode() {
    clear
    echo -e "\e[34m═══════════════════════════════════════════════════════════════\e[0m"
    echo -e "\e[34m         SCEGLI LA MODALITÀ DI ESECUZIONE\e[0m"
    echo -e "\e[34m═══════════════════════════════════════════════════════════════\e[0m"
    echo ""
    echo -e "  \e[36m1)\e[0m \e[1mSILENT\e[0m           - Lenta, nascosta, superficiale"
    echo -e "  \e[36m2)\e[0m \e[1mFAST\e[0m             - Veloce, timing aggressivo, porte limitate"
    echo -e "  \e[36m3)\e[0m \e[1mFAST & MASSIVE\e[0m   - Veloce, tutte le porte, molto rumorosa"
    echo -e "  \e[36m4)\e[0m \e[1mSILENT & MASSIVE\e[0m - Nascosta, lenta, tutte le porte"
    echo ""
    echo -e "\e[34m───────────────────────────────────────────────────────────────\e[0m"
    # Se non interattivo, usa modalità FAST (2) come default
    if [ "${NON_INTERACTIVE:-false}" = "true" ]; then
        MODE_CHOICE=2
        echo -e "\e[33m  [--yes] Modalità FAST selezionata automaticamente (non interattivo)\e[0m"
        echo ""
        # Imposta parametri modalità FAST
        NMAP_TIMING="-T4"; NMAP_TOP_PORTS_INITIAL="1000"; NMAP_TOP_PORTS_DETAIL="500"
        NMAP_VERSION_INTENSITY="5"; NMAP_SCRIPTS="vulners"
        USE_ALL_PORTS=false; USE_FRAGMENT=false; USE_DECOYS=false; USE_SPOOF=false
        SPOOF_MAC="0"; DECOY_HOSTS=""; LOG_LEVEL="WARN"; MAX_PARALLEL_JOBS=4
        return
    fi
    read -rp "  ➤ Inserisci il numero della modalità [1-4]: " MODE_CHOICE

    case $MODE_CHOICE in
        1)
            NMAP_TIMING="-T2"; NMAP_TOP_PORTS_INITIAL="100"; NMAP_TOP_PORTS_DETAIL="100"
            NMAP_VERSION_INTENSITY="0"; NMAP_SCRIPTS=""
            USE_ALL_PORTS=false; USE_FRAGMENT=true; USE_DECOYS=true; USE_SPOOF=true
            SPOOF_MAC="apple"; DECOY_HOSTS="RND:5"; LOG_LEVEL="INFO"; MAX_PARALLEL_JOBS=2
            ;;
        2)
            NMAP_TIMING="-T4"; NMAP_TOP_PORTS_INITIAL="1000"; NMAP_TOP_PORTS_DETAIL="500"
            NMAP_VERSION_INTENSITY="5"; NMAP_SCRIPTS="vulners"
            USE_ALL_PORTS=false; USE_FRAGMENT=false; USE_DECOYS=false; USE_SPOOF=false
            SPOOF_MAC="0"; DECOY_HOSTS=""; LOG_LEVEL="WARN"; MAX_PARALLEL_JOBS=4
            ;;
        3)
            NMAP_TIMING="-T5"; NMAP_VERSION_INTENSITY="9"; NMAP_SCRIPTS="vulners"
            USE_ALL_PORTS=true; USE_FRAGMENT=false; USE_DECOYS=false; USE_SPOOF=false
            SPOOF_MAC="0"; DECOY_HOSTS=""; LOG_LEVEL="ERROR"; MAX_PARALLEL_JOBS=8
            ;;
        4)
            NMAP_TIMING="-T2"; NMAP_VERSION_INTENSITY="5"; NMAP_SCRIPTS="vulners"
            USE_ALL_PORTS=true; USE_FRAGMENT=true; USE_DECOYS=true; USE_SPOOF=true
            SPOOF_MAC="apple"; DECOY_HOSTS="RND:10"; LOG_LEVEL="INFO"; MAX_PARALLEL_JOBS=2
            ;;
        *)
            echo -e "\e[31m  Scelta non valida. Uscita.\e[0m"; exit 1 ;;
    esac

    echo ""
    read -rp "  Premi INVIO per avviare con le impostazioni scelte..."
}

# ============================================================================
# FUNZIONE: Gestione segnali (CTRL+C)
# ============================================================================
cleanup_and_exit() {
    echo -e "\n\n\e[31m[!] Interrotto dall'utente. Pulizia in corso...\e[0m"
    # Kill tutti i processi figli ricorsivamente
    pkill -P $$ 2>/dev/null || true
    wait 2>/dev/null || true
    rm -f "$OUTPUT_DIR"/*_raw.txt 2>/dev/null || true
    rm -f "$OUTPUT_DIR"/*.gnmap 2>/dev/null || true
    find "$OUTPUT_DIR" -name "web_header_*.txt" -size 0 -delete 2>/dev/null || true
    # Pulisci temp file
    rm -f /tmp/recon_nvd_av_*.tmp 2>/dev/null || true
    echo -e "\e[32m[+] Pulizia completata. Uscita.\e[0m"
    exit 130
}
trap cleanup_and_exit SIGINT SIGTERM

# ============================================================================
# FUNZIONE: Logging
# ============================================================================
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local level_upper
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local always_log=false

    case "$LOG_LEVEL" in
        DEBUG) always_log=true ;;
        INFO)  [[ "$level_upper" =~ ^(INFO|WARN|ERROR)$ ]] && always_log=true ;;
        WARN)  [[ "$level_upper" =~ ^(WARN|ERROR)$ ]]      && always_log=true ;;
        ERROR) [[ "$level_upper" == "ERROR" ]]              && always_log=true ;;
        *)     always_log=true ;;
    esac

    if [ "$always_log" = true ] && [ -n "${LOG_FILE:-}" ]; then
        echo "[$timestamp] [$level_upper] $message" >> "$LOG_FILE" 2>/dev/null || true
    fi

    case "$level_upper" in
        ERROR) echo -e "\e[31m[!] $message\e[0m" >&2 ;;
        WARN)  echo -e "\e[33m[!] $message\e[0m" ;;
        INFO)  [[ "$LOG_LEVEL" != "DEBUG" ]] && echo -e "\e[36m[*] $message\e[0m" ;;
        DEBUG) [[ "$ENABLE_DEBUG_LOG" == true ]] && echo -e "\e[90m[DEBUG] $message\e[0m" ;;
    esac
}

# ============================================================================
# FUNZIONE: Verifica dipendenze
# ============================================================================
check_dependencies() {
    local deps=("nmap" "curl" "timeout" "grep" "awk" "cut" "sort" "find" "printf" "python3")
    local missing=()
    for dep in "${deps[@]}"; do
        command -v "$dep" &>/dev/null || missing+=("$dep")
    done
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "\e[31m[-] Dipendenze mancanti: ${missing[*]}\e[0m"
        echo -e "    Installa con: sudo apt install ${missing[*]}"
        exit 1
    fi
    command -v dot &>/dev/null || log_message "WARN" "Graphviz non installato. PNG non generato. (sudo apt install graphviz)"
    log_message "INFO" "Tutte le dipendenze necessarie sono presenti."
}

# ============================================================================
# FUNZIONE: Cache NVD persistente — batch Python (evita spawn per ogni CVE)
# ============================================================================
init_nvd_cache() {
    mkdir -p "$NVD_CACHE_DIR"
    if [ ! -f "$NVD_CACHE_FILE" ] || [ ! -s "$NVD_CACHE_FILE" ]; then
        echo '{}' > "$NVD_CACHE_FILE"
    fi
    log_message "DEBUG" "Cache NVD: $NVD_CACHE_FILE"
}

# Batch read: dato un array di CVE, ritorna solo quelle non in cache
nvd_cache_get_batch() {
    local cve_list=("$@")
    python3 - "$NVD_CACHE_FILE" "${cve_list[@]}" << 'PYEOF' 2>/dev/null || true
import json, sys
cache_file = sys.argv[1]
cves = sys.argv[2:]
try:
    with open(cache_file) as f:
        data = json.load(f)
except:
    data = {}
for cve in cves:
    e = data.get(cve)
    if e:
        print(f"CVEHIT|{cve}|{e.get('av','UNKNOWN')}|{e.get('score','')}|{e.get('severity','')}")
    else:
        print(f"CVEMISS|{cve}")
PYEOF
}

# Batch write: dato un array associativo, scrive tutte le entry in una volta sola
nvd_cache_set_batch() {
    local cache_file="$1"
    shift
    python3 - "$cache_file" "$@" << 'PYEOF' 2>/dev/null || true
import json, sys
cache_file = sys.argv[1]
entries = sys.argv[2:]
try:
    with open(cache_file) as f:
        data = json.load(f)
except:
    data = {}
# entries: cve1,av1,score1,sev1,cve2,av2,score2,sev2,...
for i in range(0, len(entries), 4):
    if i+3 < len(entries):
        cve_id = entries[i]
        av = entries[i+1]
        score = entries[i+2]
        severity = entries[i+3]
        data[cve_id] = {"av": av, "score": score, "severity": severity}
with open(cache_file, 'w') as f:
    json.dump(data, f, indent=2)
PYEOF
}

# ============================================================================
# FUNZIONE: Rate limiter per NVD API
# ============================================================================
nvd_rate_limit_wait() {
    local now
    now=$(date +%s)
    # Se abbiamo API key: 50 req/s → finestra 1s, max 45 richieste (margine safety)
    # Se NON abbiamo API key: 4 req / 30s
    local window=$NVD_RATE_LIMIT_WINDOW
    local max_req=$NVD_RATE_LIMIT_MAX
    if [ -n "$NVD_API_KEY" ]; then
        window=1
        max_req=45
    fi
    if [ "$NVD_RATE_LIMIT_COUNTER" -ge "$max_req" ]; then
        local elapsed=$(( now - NVD_RATE_LIMIT_START ))
        if [ "$elapsed" -lt "$window" ]; then
            local sleep_time=$(( window - elapsed + 1 ))
            log_message "DEBUG" "Rate limit NVD: attendo ${sleep_time}s (${NVD_RATE_LIMIT_COUNTER} richieste in ${elapsed}s, key=$([ -n "$NVD_API_KEY" ] && echo 'yes' || echo 'no'))"
            sleep "$sleep_time"
        fi
        NVD_RATE_LIMIT_COUNTER=0
        NVD_RATE_LIMIT_START=$(date +%s)
    fi
    if [ "$NVD_RATE_LIMIT_COUNTER" -eq 0 ]; then
        NVD_RATE_LIMIT_START=$(date +%s)
    fi
    NVD_RATE_LIMIT_COUNTER=$(( NVD_RATE_LIMIT_COUNTER + 1 ))
}

# ============================================================================
# FUNZIONE: Fetch CVSS da NVD API (con cache batch e retry)
# ============================================================================
fetch_cvss_from_nvd_batch() {
    local output_file="$1"
    shift
    local cve_list=("$@")

    if [ ${#cve_list[@]} -eq 0 ]; then
        return
    fi

    log_message "INFO" "Fetch NVD batch per ${#cve_list[@]} CVE..."

    # Prima controlla cache per tutte
    local cache_miss=()
    local results_map=()

    while read -r line; do
        if [[ "$line" == CVEHIT\|* ]]; then
            local cve_hit
            cve_hit=$(echo "$line" | cut -d'|' -f2)
            local av_hit
            av_hit=$(echo "$line" | cut -d'|' -f3)
            local score_hit
            score_hit=$(echo "$line" | cut -d'|' -f4)
            echo "   [NVD] ✓ Cache hit: $cve_hit → AV=$av_hit Score=$score_hit" >> "$output_file"
            log_message "DEBUG" "Cache hit NVD: $cve_hit"
            results_map+=("$cve_hit|$av_hit")
        elif [[ "$line" == CVEMISS\|* ]]; then
            local cve_miss
            cve_miss=$(echo "$line" | cut -d'|' -f2)
            cache_miss+=("$cve_miss")
        fi
    done < <(nvd_cache_get_batch "${cve_list[@]}")

    # Cache hit: salva in file temporaneo con mktemp
    local av_map_file
    av_map_file=$(mktemp /tmp/recon_nvd_av_XXXXXX.tmp)
    for entry in "${results_map[@]}"; do
        echo "$entry" >> "$av_map_file"
    done

    # Cache miss: fetch da NVD con rate limit e retry
    local batch_updates=()
    for cve in "${cache_miss[@]}"; do
        nvd_rate_limit_wait

        local response=""
        local retry=0
        local http_code=0

        while [ $retry -lt $NVD_API_RETRIES ]; do
            response=$(timeout "$TIMEOUT_NVD_API" curl -s -w "%{http_code}" \
                "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve" 2>/dev/null) || true
            
            http_code="${response: -3}"
            response="${response:0:${#response}-3}"

            if [ "$http_code" = "200" ]; then
                break
            elif [ "$http_code" = "429" ]; then
                local backoff=$(( (2 ** retry) + RANDOM % 5 ))
                log_message "WARN" "NVD rate limited (429) per $cve, retry in ${backoff}s (tentativo $((retry+1))/$NVD_API_RETRIES)"
                sleep "$backoff"
                retry=$(( retry + 1 ))
            elif [ "$http_code" = "503" ]; then
                local backoff=$(( (2 ** retry) + RANDOM % 3 ))
                log_message "WARN" "NVD service unavailable (503) per $cve, retry in ${backoff}s"
                sleep "$backoff"
                retry=$(( retry + 1 ))
            else
                break
            fi
        done

        if [ -z "$response" ] || [ "$http_code" != "200" ]; then
            echo "   [NVD] API $([ "$http_code" != "000" ] && echo "HTTP $http_code" || echo "timeout") per $cve" >> "$output_file"
            log_message "WARN" "HTTP $http_code da NVD per $cve"
            continue
        fi

        local av cvss_score cvss_severity description
        av=$(echo "$response"          | grep -oP '"attackVector": "\K[^"]+' | head -1) || true
        cvss_score=$(echo "$response"  | grep -oP '"baseScore": \K[0-9.]+' | head -1) || true
        cvss_severity=$(echo "$response" | grep -oP '"baseSeverity": "\K[^"]+' | head -1) || true
        description=$(echo "$response" | grep -oP '"value": "\K[^"]+' | head -1) || true

        if [ -z "$av" ]; then
            av=$(echo "$response" | grep -oP '"accessVector": "\K[^"]+' | head -1) || true
            [[ "$av" == "ADJACENT_NETWORK" ]] && av="ADJACENT_NETWORK"
        fi

        if [ -n "$av" ]; then
            echo "   [NVD] Attack Vector: $av" >> "$output_file"
            echo "$cve|$av" >> "$av_map_file"
            batch_updates+=("$cve" "$av" "${cvss_score:-}" "${cvss_severity:-}")
        else
            echo "   [NVD] CVE $cve non trovata nel database" >> "$output_file"
            echo "$cve|UNKNOWN" >> "$av_map_file"
        fi
        [ -n "$cvss_score" ]   && echo "   [NVD] CVSS Score: $cvss_score/10 ($cvss_severity)" >> "$output_file"
        [ -n "$description" ]  && echo "   [NVD] Descrizione: ${description:0:200}..." >> "$output_file"

        # Jitter: sleep 0.5-1.5 secondi tra richieste per evitare rate limiting
        sleep 0.$(( RANDOM % 10 + 5 ))
    done

    # Salva in cache in batch
    if [ ${#batch_updates[@]} -gt 0 ]; then
        nvd_cache_set_batch "$NVD_CACHE_FILE" "${batch_updates[@]}"
        log_message "DEBUG" "Cache NVD: salvati $(( ${#batch_updates[@]} / 4 )) nuovi CVE"
    fi

    echo "$av_map_file"
}

# ============================================================================
# FUNZIONE: Verifica configurazione SSH
# ============================================================================
check_ssh_config() {
    local host="$1"
    local output_file="$2"
    echo "   [CONFIG] Analisi configurazione SSH..." >> "$output_file"

    local weak_algo=0
    local algo_output
    algo_output=$(timeout "$TIMEOUT_NMAP_WEAK" nmap -p 22 --script ssh2-enum-algos \
        -sV "$host" 2>/dev/null || true)
    weak_algo=$(echo "$algo_output" | grep -ciE "diffie-hellman-group1-sha1|ssh-rsa|ssh-dss" || true)

    if [ "${weak_algo:-0}" -gt 0 ]; then
        echo "   [CONFIG] ⚠️ Algoritmi deboli rilevati:" >> "$output_file"
        echo "$algo_output" | grep -iE "diffie-hellman-group1-sha1|ssh-rsa|ssh-dss" | head -10 >> "$output_file" || true
        echo 80
    else
        local banner
        banner=$(timeout "$TIMEOUT_NC" nc -n "$host" 22 2>/dev/null | head -1) || true
        [ -n "$banner" ] && echo "   [CONFIG] Banner SSH: $banner" >> "$output_file"
        echo "   [CONFIG] ✅ Nessun algoritmo obsoleto rilevato" >> "$output_file"
        echo 30
    fi
}

# ============================================================================
# FUNZIONE: Verifica configurazione Web
# ============================================================================
check_web_config() {
    local host="$1"
    local port="$2"
    local output_file="$3"
    echo "   [CONFIG] Analisi web su porta $port..." >> "$output_file"

    local server_status
    server_status=$(timeout "$TIMEOUT_CURL" curl -s -k \
        "http://$host:$port/server-status" 2>/dev/null | head -5) || true

    if echo "$server_status" | grep -qi "Apache Server Status" 2>/dev/null; then
        echo "   [CONFIG] ⚠️ server-status ACCESSIBILE — information leakage critico!" >> "$output_file"
        echo 90; return
    fi

    local headers
    headers=$(timeout "$TIMEOUT_CURL" curl -s -k -I "http://$host:$port" 2>/dev/null) || true

    grep -qi "Server:" <<< "$headers" 2>/dev/null && \
        echo "   [CONFIG] Server header: $(grep -i 'Server:' <<< "$headers" | head -1)" >> "$output_file"

    if grep -qi "Strict-Transport-Security" <<< "$headers" 2>/dev/null; then
        echo "   [CONFIG] ✅ HSTS abilitato" >> "$output_file"
        echo 30
    else
        echo "   [CONFIG] ⚠️ HSTS non rilevato (possibile downgrade attack)" >> "$output_file"
        echo 60
    fi
}

# ============================================================================
# FUNZIONE: Analisi CVE a 3 livelli (backporting + CVSS + config)
# ============================================================================
analizza_cve() {
    local host="$1" software="$2" version="$3" cve_id="$4" output_file="$5"
    local backport_score=50 av_score=50 config_score=50 total_score=50
    local av=""

    {
        echo ""
        echo "================================================================"
        echo "[ANALISI CVE: $cve_id]"
        echo "Host: $host | Software: $software | Versione: $version"
        echo "================================================================"
    } >> "$output_file"

    log_message "DEBUG" "Analisi CVE $cve_id su $host"

    # Livello 1: OS Backporting
    if echo "$software $version" | grep -qiE "debian|ubuntu|el[0-9]|suse|alpine|raspbian" 2>/dev/null; then
        backport_score=30
        echo "[LIVELLO 1 - OS Backporting]" >> "$output_file"
        echo "   ✅ Distribuzione rilevata → Backporting PROBABILE (score 30/100)" >> "$output_file"
    else
        backport_score=70
        echo "[LIVELLO 1 - OS Backporting]" >> "$output_file"
        echo "   ⚠️ Versione vaniglia → Backporting NON GARANTITO (score 70/100)" >> "$output_file"
    fi

    # Livello 2: CVSS Attack Vector
    echo "" >> "$output_file"
    echo "[LIVELLO 2 - CVSS Attack Vector]" >> "$output_file"

    av="${CVE_AV_MAP[$cve_id]:-}"

    if [ -n "$av" ] && [ "$av" != "UNKNOWN" ]; then
        echo "   ✓ Attack Vector (cache locale): $av" >> "$output_file"
    elif [ -n "${CVE_AV_MAP_FETCHED:-}" ]; then
        if [ -f "${NVD_AV_MAP_FILE:-}" ]; then
            local fetched_av
            fetched_av=$(grep "^$cve_id|" "$NVD_AV_MAP_FILE" 2>/dev/null | cut -d'|' -f2) || true
            if [ -n "$fetched_av" ]; then
                av="$fetched_av"
                echo "   ✓ Attack Vector (NVD): $av" >> "$output_file"
            fi
        fi
    fi

    if [ -z "$av" ] || [ "$av" = "UNKNOWN" ]; then
        echo "   → CVE non in cache né in NVD, uso UNKNOWN" >> "$output_file"
    fi

    case "$av" in
        "NETWORK")          av_score=85 ;;
        "ADJACENT_NETWORK") av_score=70 ;;
        "LOCAL")            av_score=30 ;;
        "PHYSICAL")         av_score=10 ;;
        *)                  av_score=50 ;;
    esac
    echo "   Attack Vector: ${av:-UNKNOWN} → score $av_score/100" >> "$output_file"

    # Livello 3: Configurazione reale
    echo "" >> "$output_file"
    echo "[LIVELLO 3 - Configurazione Reale]" >> "$output_file"
    config_score=50
    case "$software" in
        *ssh*|*OpenSSH*)
            config_score=$(check_ssh_config "$host" "$output_file") ;;
        *apache*|*httpd*|*nginx*)
            config_score=$(check_web_config "$host" "80" "$output_file") ;;
        *https*|*ssl*|*tls*)
            config_score=$(check_web_config "$host" "443" "$output_file") ;;
        *)
            echo "   ℹ️ Nessuna verifica automatica per $software (score 50/100)" >> "$output_file" ;;
    esac

    total_score=$(( (backport_score + av_score + config_score) / 3 ))

    {
        echo ""
        echo "[RIEPILOGO FINALE]"
        echo "   ┌──────────────────────────────────────────────┐"
        printf "   │ OS Backporting:  %-3d/100                    │\n" "$backport_score"
        printf "   │ Attack Vector:   %-3d/100                    │\n" "$av_score"
        printf "   │ Configurazione:  %-3d/100                    │\n" "$config_score"
        echo "   ├──────────────────────────────────────────────┤"
        printf "   │ TOTALE:          %-3d/100                    │\n" "$total_score"
        echo "   └──────────────────────────────────────────────┘"
    } >> "$output_file"

    if   [ "$total_score" -ge 70 ]; then
        echo "[VERDETTO] 🔴 VULNERABILITÀ CONCRETA - Priorità ALTA"  >> "$output_file"; return 1
    elif [ "$total_score" -le 35 ]; then
        echo "[VERDETTO] 🟢 FALSO POSITIVO - Priorità BASSA"         >> "$output_file"; return 0
    else
        echo "[VERDETTO] 🟡 ZONA GRIGIA - Priorità MEDIA"            >> "$output_file"; return 2
    fi
}

# ============================================================================
# FUNZIONE: Pulizia output nmap (con || true per grep)
# ============================================================================
clean_nmap_output() {
    local input_file="$1"
    [ -f "$input_file" ] || return
    grep -v -E "^(Stats:|SYN Stealth Scan Timing|Service scan Timing|About [0-9.]+% done|^$)" \
        "$input_file" 2>/dev/null | awk '!seen[$0]++' > "${input_file}.tmp" 2>/dev/null || true
    mv "${input_file}.tmp" "$input_file" 2>/dev/null || true
}

# ============================================================================
# FUNZIONE: Scansione TCP di un singolo host (con timeout globale)
# ============================================================================
scan_tcp_host() {
    local host="$1"
    local raw_out="$OUTPUT_DIR/scan_${host}_raw.txt"
    local final_out="$OUTPUT_DIR/scan_${host}.txt"

    local cmd=(nmap -sS -Pn "$NMAP_TIMING")
    [ "$USE_FRAGMENT" = true ]                && cmd+=(-f)
    [ "$USE_DECOYS" = true ] && [ -n "$DECOY_HOSTS" ] && cmd+=(-D "$DECOY_HOSTS")
    [ "$USE_SPOOF"  = true ] && [ "$SPOOF_MAC" != "0" ] && cmd+=(--spoof-mac "$SPOOF_MAC")

    if [ "$USE_ALL_PORTS" = true ]; then
        cmd+=(-p-)
    else
        cmd+=(--top-ports "$NMAP_TOP_PORTS_DETAIL")
    fi

    cmd+=(-sV --version-intensity "$NMAP_VERSION_INTENSITY")
    [ -n "$NMAP_SCRIPTS" ] && cmd+=(--script="$NMAP_SCRIPTS")
    cmd+=("$host")

    # Timeout: 30 min per scan TCP su top-ports, 120 min per tutte le porte
    local timeout_sec=1800
    [ "$USE_ALL_PORTS" = true ] && timeout_sec=7200

    log_message "DEBUG" "Avvio scan TCP su $host (timeout ${timeout_sec}s)"
    local rc=0
    timeout "$timeout_sec" "${cmd[@]}" > "$raw_out" 2>>"$OUTPUT_DIR/nmap_errors.log" || rc=$?
    if [ "$rc" -eq 124 ]; then
        log_message "WARN" "Scan TCP su $host: timeout dopo ${timeout_sec}s"
        echo "TCP scan TIMEOUT after ${timeout_sec}s" > "$raw_out"
    fi

    clean_nmap_output "$raw_out"
    mv "$raw_out" "$final_out" 2>/dev/null || true
}

# ============================================================================
# FUNZIONE: Scansione UDP di un singolo host
# ============================================================================
scan_udp_host() {
    local host="$1"
    local out="$OUTPUT_DIR/scan_udp_${host}.txt"

    local UDP_PORTS="53,69,123,161,162,137,138,389,520,1900,5353"
    local cmd=(nmap -sU -Pn "$NMAP_TIMING" -p "$UDP_PORTS"
               --version-intensity "$NMAP_VERSION_INTENSITY")
    [ -n "$NMAP_SCRIPTS" ] && cmd+=(--script="$NMAP_SCRIPTS")
    cmd+=("$host")

    log_message "DEBUG" "Avvio scan UDP su $host"
    local rc=0
    timeout 600 "${cmd[@]}" > "$out" 2>>"$OUTPUT_DIR/nmap_errors.log" || rc=$?
    if [ "$rc" -eq 124 ]; then
        log_message "WARN" "Scan UDP su $host: timeout dopo 600s"
        echo "UDP scan TIMEOUT after 600s" > "$out"
    fi

    if grep -q "161/udp.*open" "$out" 2>/dev/null; then
        echo "   [UDP-SNMP] ⚠️ SNMP aperto, test community 'public'..." >> "$out" 2>/dev/null || true
        if command -v snmpwalk &>/dev/null; then
            timeout 5 snmpwalk -v2c -c public "$host" system 2>/dev/null | head -10 >> "$out" || true
        fi
    fi
}

# ============================================================================
# FUNZIONE: Lock per scrittura file condivisi
# ============================================================================
write_lock() {
    local lock_file="$1"
    local timeout=30
    while ! mkdir "${lock_file}.lock" 2>/dev/null; do
        sleep 0.1
        timeout=$(( timeout - 1 ))
        [ "$timeout" -le 0 ] && return 1
    done
}

write_unlock() {
    rmdir "$1.lock" 2>/dev/null || true
}

# ============================================================================
# FUNZIONE: Analisi risultati di un host (CVE, web, grafo)
# ============================================================================
analyze_host_results() {
    local host="$1"
    local scan_file="$OUTPUT_DIR/scan_${host}.txt"
    [ -f "$scan_file" ] || return

    # Rilevamento OS
    local os_detected
    os_detected=$(grep -E "OS details:|Service Info: OS:" "$scan_file" \
        | cut -d: -f3- | head -1 | sed 's/^[ \t]*//;s/;//;s/"//g') || true
    [ -z "$os_detected" ] && os_detected=$(grep -oP 'cpe:/o:\K[^:]+:[^:]+' "$scan_file" | head -1) || true
    [ -z "$os_detected" ] && os_detected="Sconosciuto"
    echo -e "\e[36m   └─ OS rilevato: \e[37m$os_detected\e[0m"

    local software="unknown" version="unknown"
    if grep -q "^22/tcp.*open" "$scan_file" 2>/dev/null; then
        software="OpenSSH"
        version=$(grep -E "^22/tcp.*open" "$scan_file" | sed -E 's/.*OpenSSH ([^ ]+).*/\1/') || true
    else
        local line
        line=$(grep -E "^[0-9]+/tcp.*open" "$scan_file" | head -1) || true
        if [ -n "$line" ]; then
            software=$(echo "$line" | awk '{print $3}' | cut -d'/' -f1) || true
            version=$(echo "$line" | awk '{print $4}') || true
        fi
    fi
    [ -z "$software" ] && software="unknown"
    [ -z "$version"  ] && version="unknown"

    local open_ports_count=0
    open_ports_count=$(grep -cE "^[0-9]+/tcp.*open" "$scan_file" 2>/dev/null || echo 0)
    open_ports_count=$(echo "$open_ports_count" | tr -cd '0-9')
    [ -z "$open_ports_count" ] && open_ports_count=0
    echo -e "\e[36m   └─ Porte TCP aperte: \e[37m$open_ports_count\e[0m"

    # Porte UDP (file separato, nessuna race condition)
    local udp_file="$OUTPUT_DIR/scan_udp_${host}.txt"
    if [ -f "$udp_file" ]; then
        local udp_open
        udp_open=$(grep -cE "^[0-9]+/udp.*open" "$udp_file" 2>/dev/null || echo 0)
        udp_open="${udp_open//[!0-9]/}"
        [ -z "$udp_open" ] && udp_open=0
        echo -e "\e[36m   └─ Porte UDP aperte: \e[37m$udp_open\e[0m"
        if [ "$udp_open" -gt 0 ] 2>/dev/null; then
            grep -E "^[0-9]+/udp.*open" "$udp_file" 2>/dev/null | while read -r line; do
                echo -e "      └─ \e[37m$line\e[0m"
            done
        fi
    fi

    # Analisi CVE
    local cve_present=false
    if grep -qi "CVE-" "$scan_file" 2>/dev/null; then
        cve_present=true
        echo -e "\e[31m   [!] Vulnerabilità potenziali rilevate!\e[0m"

        # Lock per scrittura su file condivisi
        write_lock "$OUTPUT_DIR/.report_vuln_lock"
        {
            echo ""
            echo "[HOST] -> $host"
            echo "OS RILEVATO: $os_detected"
            echo "CRITICITÀ INDIVIDUATE:"
        } >> "$REPORT_VULN" 2>/dev/null || true
        write_unlock "$OUTPUT_DIR/.report_vuln_lock"

        mapfile -t cve_list < <(grep -oE "CVE-[0-9]{4}-[0-9]{4,}" "$scan_file" | sort -u)

        # Fetch NVD batch per tutte le CVE di questo host
        local host_av_map_file=""
        if [ ${#cve_list[@]} -gt 0 ]; then
            host_av_map_file=$(fetch_cvss_from_nvd_batch "$REPORT_ANALISI" "${cve_list[@]}")
        fi

        for cve in "${cve_list[@]}"; do
            local saved_av_map_file="$host_av_map_file"
            local saved_av_map_fetched=""
            [ -n "$host_av_map_file" ] && saved_av_map_fetched="true"
            export NVD_AV_MAP_FILE="$saved_av_map_file"
            export CVE_AV_MAP_FETCHED="$saved_av_map_fetched"
            local score="0"
            score=$(grep -A1 "$cve" "$scan_file" 2>/dev/null | grep -oE "[0-9]+\.[0-9]" | head -1 || echo "0")
            write_lock "$OUTPUT_DIR/.report_vuln_lock"
            echo "     $cve ${score:-N/A}" >> "$REPORT_VULN" 2>/dev/null || true
            write_unlock "$OUTPUT_DIR/.report_vuln_lock"
            analizza_cve "$host" "$software" "$version" "$cve" "$REPORT_ANALISI" || true
        done
        write_lock "$OUTPUT_DIR/.report_vuln_lock"
        echo "------------------------------------------------------------------" >> "$REPORT_VULN" 2>/dev/null || true
        write_unlock "$OUTPUT_DIR/.report_vuln_lock"

        echo -e "\e[36m   └─ CVE trovate:\e[0m"
        grep -oE "CVE-[0-9]{4}-[0-9]{4,}" "$scan_file" | sort -u | while read -r cve; do
            local score color
            score=$(grep -A1 "$cve" "$scan_file" 2>/dev/null | grep -oE "[0-9]+\.[0-9]" | head -1 || echo "0")
            if python3 -c "exit(0 if float('${score:-0}') >= 7.0 else 1)" 2>/dev/null; then
                color="\e[31m"
            elif python3 -c "exit(0 if float('${score:-0}') >= 4.0 else 1)" 2>/dev/null; then
                color="\e[33m"
            else
                color="\e[32m"
            fi
            echo -e "      └─ ${color}$cve\e[0m (score: ${score:-N/A})"
        done

        echo "    \"$host\" [color=tomato, label=\"$host\\nOS: $os_detected\\n(CRITICO)\"];" >> "$GRAPH_DOT" 2>/dev/null || true
    fi

    # Pulisci av_map file se presente (usa variabile locale per evitare race condition)
    if [ -n "${host_av_map_file:-}" ] && [ -f "$host_av_map_file" ]; then
        rm -f "$host_av_map_file" 2>/dev/null || true
    fi
    unset NVD_AV_MAP_FILE CVE_AV_MAP_FETCHED

    if [ "$cve_present" = false ]; then
        echo -e "\e[32m   └─ Nessuna vulnerabilità nota rilevata\e[0m"
        echo "    \"$host\" [label=\"$host\\nOS: $os_detected\"];" >> "$GRAPH_DOT" 2>/dev/null || true
    fi

    # Servizio web → grab headers
    if grep -qE "80/tcp|443/tcp|8080/tcp|8443/tcp|8888/tcp" "$scan_file" 2>/dev/null; then
        echo -e "\e[36m   └─ Servizio web rilevato → grab headers\e[0m"
        timeout "$TIMEOUT_CURL" curl -I -s -A "Mozilla/5.0" --max-time "$TIMEOUT_CURL" \
            "http://$host" > "$OUTPUT_DIR/web_header_${host}.txt" 2>/dev/null || true
    fi

    [ "$host" != "$GATEWAY" ] && \
        echo "    \"$GATEWAY\" -- \"$host\";" >> "$GRAPH_DOT" 2>/dev/null || true
}

# ============================================================================
# FUNZIONE: Scansione parallela di un host (TCP + UDP)
# ============================================================================
scan_host_parallel() {
    local host="$1"
    log_message "INFO" "Analisi host: $host"

    # Prima UDP (in background), poi TCP (sincrono), infine attendi UDP
    # Questo evita race condition: UDP non scrive sullo stesso file di TCP
    scan_udp_host "$host" &
    local udp_pid=$!
    scan_tcp_host "$host"
    wait "$udp_pid" 2>/dev/null || true

    analyze_host_results "$host"
}

# ============================================================================
# FUNZIONE: Test unitari
# ============================================================================
run_tests() {
    log_message "INFO" "Avvio test automatici..."
    local passed=0 failed=0

    echo "Test 1: clean_nmap_output" >> "$TEST_LOG"
    local t1
    t1=$(mktemp /tmp/test_nmap_XXXXXX.txt)
    printf "Stats: 0:00:01 elapsed\nNmap scan report for 127.0.0.1\nNot shown: 998 closed\n" > "$t1"
    clean_nmap_output "$t1"
    if grep -q "Stats:" "$t1" 2>/dev/null; then echo "FAIL" >> "$TEST_LOG"; failed=$(( failed + 1 )); else echo "PASS" >> "$TEST_LOG"; passed=$(( passed + 1 )); fi
    rm -f "$t1"

    echo "Test 2: analizza_cve cache" >> "$TEST_LOG"
    local t2
    t2=$(mktemp /tmp/test_analisi_XXXXXX.txt)
    analizza_cve "127.0.0.1" "OpenSSH" "8.9p1 Ubuntu-3" "CVE-2021-44228" "$t2" || true
    if grep -q "NETWORK" "$t2" 2>/dev/null; then echo "PASS" >> "$TEST_LOG"; passed=$(( passed + 1 )); else echo "FAIL" >> "$TEST_LOG"; failed=$(( failed + 1 )); fi
    rm -f "$t2"

    echo "Test 3: nvd_cache set/get batch" >> "$TEST_LOG"
    local test_cache
    test_cache=$(mktemp /tmp/test_cache_XXXXXX.json)
    echo '{}' > "$test_cache"
    nvd_cache_set_batch "$test_cache" "CVE-TEST-0001" "LOCAL" "5.5" "MEDIUM"
    local cached_val
    cached_val=$(nvd_cache_get_batch "CVE-TEST-0001")
    if echo "$cached_val" | grep -q "CVEHIT|CVE-TEST-0001|LOCAL" 2>/dev/null; then echo "PASS" >> "$TEST_LOG"; passed=$(( passed + 1 )); else echo "FAIL" >> "$TEST_LOG"; failed=$(( failed + 1 )); fi
    rm -f "$test_cache"

    log_message "INFO" "Test: $passed passati, $failed falliti"
    [ "$failed" -gt 0 ] && log_message "WARN" "Alcuni test falliti — vedere $TEST_LOG"
    # Non bloccare mai lo script principale anche se i test falliscono
    return 0
}

# ============================================================================
# FUNZIONE: Generazione report JSON (SICURA — passa path via sys.argv)
# ============================================================================
generate_json_report() {
    local json_file="$OUTPUT_DIR/report.json"
    log_message "INFO" "Generazione report JSON..."

    export RECOGNIZE_TARGET="$TARGET"
    export RECOGNIZE_MODE="$MODE_CHOICE"
    export RECOGNIZE_OUTDIR="$OUTPUT_DIR"
    export RECOGNIZE_JSON_OUT="$json_file"

    python3 - "$OUTPUT_DIR" "$json_file" << 'PYEOF'
import json, os, re, sys
from datetime import datetime

out_dir = sys.argv[1]
json_out = sys.argv[2]
target = os.environ.get("RECOGNIZE_TARGET", "unknown")
mode   = os.environ.get("RECOGNIZE_MODE", "?")

report = {
    "meta": {
        "tool": "recognize.sh",
        "version": "3.3",
        "author": "Scotti Davide - Universita Statale di Milano",
        "generated": datetime.now().isoformat(),
        "target": target,
        "mode": mode,
        "output_dir": out_dir
    },
    "hosts": []
}

for fname in sorted(os.listdir(out_dir)):
    if not (fname.startswith("scan_") and fname.endswith(".txt") and "udp" not in fname):
        continue
    ip = fname.replace("scan_","").replace(".txt","")
    host_data = {
        "ip": ip, "os": "Unknown",
        "ports_tcp": [], "ports_udp": [],
        "cves": [], "web_services": [],
        "verdetti": []
    }

    full_path = os.path.join(out_dir, fname)
    if not os.path.exists(full_path):
        continue
    with open(full_path, "r", errors="ignore") as f:
        content = f.read()

    for line in content.splitlines():
        if "OS details:" in line or "Service Info: OS:" in line:
            host_data["os"] = line.split(":",1)[-1].strip().rstrip(";")
            break

    for line in content.splitlines():
        m = re.match(r'^(\d+)/tcp\s+open\s+(\S+)\s*(.*)', line)
        if m:
            host_data["ports_tcp"].append({
                "port": int(m.group(1)),
                "service": m.group(2),
                "version": m.group(3).strip()
            })

    for cve in sorted(set(re.findall(r'CVE-\d{4}-\d{4,}', content))):
        sm = re.search(rf'{re.escape(cve)}.*?(\d+\.\d)', content)
        host_data["cves"].append({
            "id": cve,
            "score": float(sm.group(1)) if sm else None
        })

    udp_file = os.path.join(out_dir, f"scan_udp_{ip}.txt")
    if os.path.exists(udp_file):
        with open(udp_file, "r", errors="ignore") as f:
            udp_content = f.read()
        for line in udp_content.splitlines():
            m = re.match(r'^(\d+)/udp\s+open\s+(\S+)\s*(.*)', line)
            if m:
                host_data["ports_udp"].append({
                    "port": int(m.group(1)),
                    "service": m.group(2),
                    "version": m.group(3).strip()
                })

    web_file = os.path.join(out_dir, f"web_header_{ip}.txt")
    if os.path.exists(web_file):
        with open(web_file, "r", errors="ignore") as f:
            wc = f.read()
        server = next((l.split(":",1)[1].strip() for l in wc.splitlines()
                       if l.lower().startswith("server:")), "")
        hsts = "Strict-Transport-Security" in wc
        host_data["web_services"].append({
            "server": server, "hsts": hsts
        })

    analisi_file = os.path.join(out_dir, "analisi_falsi_positivi.txt")
    if os.path.exists(analisi_file):
        with open(analisi_file, "r", errors="ignore") as f:
            analisi = f.read()
        for cve_entry in host_data["cves"]:
            cve = cve_entry["id"]
            block_start = analisi.find(f"[ANALISI CVE: {cve}]")
            if block_start != -1:
                block = analisi[block_start:block_start+800]
                if "VERDETTO" in block:
                    verdict_line = [l for l in block.splitlines() if "VERDETTO" in l]
                    if verdict_line:
                        host_data["verdetti"].append({
                            "cve": cve, "verdetto": verdict_line[0].strip()
                        })

    report["hosts"].append(host_data)

with open(json_out, "w") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)

n_hosts = len(report['hosts'])
n_cves = sum(len(h['cves']) for h in report['hosts'])
print(f"  JSON generato: {json_out} ({n_hosts} host, {n_cves} CVE totali)")
PYEOF
    echo -e "\e[32m   [✓] report.json pronto per analyze.sh\e[0m"
}

# ============================================================================
# FUNZIONE: Generazione file CSV (per Excel/LibreOffice)
# ============================================================================
generate_csv_report() {
    local csv_file="$OUTPUT_DIR/00_priorita.csv"
    log_message "INFO" "Generazione report CSV..."
    {
        echo "Priorita;CVE;Score;Host;OS;Verdetto"
        if [ -f "$REPORT_VULN" ]; then
            grep -E "CVE-[0-9]{4}-[0-9]{4,}" "$REPORT_VULN" 2>/dev/null | while read -r line; do
                local cve score priority verdetto
                cve=$(echo "$line" | grep -oE "CVE-[0-9]{4}-[0-9]{4,}") || true
                score=$(echo "$line" | grep -oE "[0-9]+\.[0-9]" | head -1) || true
                priority=$(python3 -c "
import sys
s = float('${score:-0}')
if s >= 7.0: print('CRITICA')
elif s >= 4.0: print('MEDIA')
else: print('BASSA')
" 2>/dev/null || echo "N/D")
                verdetto=$(grep -A20 "$cve" "$REPORT_ANALISI" 2>/dev/null \
                    | grep "VERDETTO" | head -1 | sed 's/.*\] //;s/ - /;/' || echo "N/D")
                echo "${priority};${cve};${score:-N/A};${TARGET};${OS_DETECTED:-Sconosciuto};${verdetto}"
            done || true
        fi
    } > "$csv_file" 2>/dev/null || true
    echo -e "\e[32m   [✓] Report CSV generato: $csv_file\e[0m"
}

# ============================================================================
# FUNZIONE: Lock file per esecuzioni singole
# ============================================================================
LOCK_FILE="/tmp/recon_manager_scan.lock"

acquire_lock() {
    # Se il lock file esiste e il processo è vivo, esci
    if [ -f "$LOCK_FILE" ]; then
        local old_pid
        old_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
            echo -e "\e[31m[-] Un'altra scansione è già in esecuzione (PID $old_pid).\e[0m"
            echo -e "    Se sei sicuro che sia terminata, elimina: rm -f $LOCK_FILE"
            exit 1
        fi
        # Processo morto — lock residue, lo rimuoviamo
        rm -f "$LOCK_FILE" 2>/dev/null || true
    fi
    # Crea nuovo lock
    echo "$$" > "$LOCK_FILE" 2>/dev/null || true
    trap 'rm -f "$LOCK_FILE" 2>/dev/null || true' EXIT INT TERM
    log_message "DEBUG" "Lock acquisito (PID $$)"
}

# ============================================================================
# FUNZIONE: Generazione file priorità
# ============================================================================
generate_priority_file() {
    PRIORITY_FILE="$OUTPUT_DIR/00_priorita.txt"
    cat > "$PRIORITY_FILE" << EOF
╔══════════════════════════════════════════════════════════════════════════════╗
║                      PRIORITÀ VULNERABILITÀ                                 ║
║                      Ordinamento per gravità                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
$(date)
Target: $TARGET
┌──────────────┬──────────────┬────────┬────────────────────────────────────┐
│ PRIORITÀ     │ CVE          │ SCORE  │ VERDETTO                           │
├──────────────┼──────────────┼────────┼────────────────────────────────────┤
EOF

    if [ -f "$REPORT_VULN" ]; then
        local tmp
        tmp=$(mktemp /tmp/recon_prio_XXXXXX.txt)
        grep -E "CVE-[0-9]{4}-[0-9]{4,}" "$REPORT_VULN" 2>/dev/null | while read -r line; do
            local cve score priority verdetto
            cve=$(echo "$line"   | grep -oE "CVE-[0-9]{4}-[0-9]{4,}") || true
            score=$(echo "$line" | grep -oE "[0-9]+\.[0-9]" | head -1) || true
            priority=$(python3 -c "
s = float('${score:-0}')
if s >= 7.0: print('🔴 CRITICA')
elif s >= 4.0: print('🟡 MEDIA')
else: print('🟢 BASSA')
" 2>/dev/null || echo "N/D")
            verdetto=$(grep -A20 "$cve" "$REPORT_ANALISI" 2>/dev/null \
                | grep "VERDETTO" | head -1 | cut -d' ' -f2- || echo "N/D")
            echo "${score:-0}|$priority|$cve|$verdetto" >> "$tmp" 2>/dev/null || true
        done || true
        if [ -f "$tmp" ]; then
            sort -rn "$tmp" 2>/dev/null | while IFS='|' read -r score priority cve verdetto; do
                printf "│ %-12s │ %-12s │ %-6s │ %-34s │\n" \
                    "$priority" "$cve" "$score" "${verdetto:0:34}" >> "$PRIORITY_FILE"
            done || true
            rm -f "$tmp" 2>/dev/null || true
        fi
    fi

    cat >> "$PRIORITY_FILE" << 'EOF'
└──────────────┴──────────────┴────────┴────────────────────────────────────┘
📌 LEGENDA:
   🔴 CRITICA (score ≥ 7.0) → Intervenire immediatamente
   🟡 MEDIA   (score 4.0–6.9) → Pianificare intervento
   🟢 BASSA   (score < 4.0)  → Monitorare
EOF
}

# ============================================================================
# FUNZIONE: Core scanning per un singolo target (Fasi 1-7)
# ============================================================================
scan_single_target() {
    local target="$1"

    log_message "INFO" "Scan del target: $target | modalità: ${MODE_CHOICE:-?}"

    # ── File di report per questo target ─────────────────────────────────
    REPORT_VULN="$OUTPUT_DIR/macchine_vulnerabili.txt"
    REPORT_ANALISI="$OUTPUT_DIR/analisi_falsi_positivi.txt"
    GRAPH_DOT="$OUTPUT_DIR/struttura_rete.dot"
    GRAPH_PNG="$OUTPUT_DIR/struttura_rete.png"

    if [ ! -f "$REPORT_VULN" ]; then
        {
            echo "=== REPORT ANALISI E PRIORITIZZAZIONE CVE ==="
            echo "Generato: $(date)"
            echo "Target: $target"
            echo "------------------------------------------------------------------"
        } > "$REPORT_VULN"
        {
            echo "=== ANALISI LOGICA FALSI POSITIVI ==="
            echo "Generato: $(date)"
            echo "Metodologia: OS Backporting + CVSS (NVD/Cache) + Config Validation"
            echo "------------------------------------------------------------------"
        } > "$REPORT_ANALISI"
    fi

    # ═══════════════════════════════════════════════════════════════════
    # FASE 1/7 — Scansione TCP iniziale
    # ═══════════════════════════════════════════════════════════════════
    echo -e "\n\e[34m╔═══════════════════════════════════════════════════════════════╗\e[0m"
    echo -e "\e[34m║  [1/7] SCANSIONE TCP INIZIALE SU $target           ║\e[0m"
    echo -e "\e[34m╚═══════════════════════════════════════════════════════════════╝\e[0m"

    NMAP_INITIAL=(nmap -sS -Pn "$NMAP_TIMING")
    [ "$USE_FRAGMENT" = true ] && NMAP_INITIAL+=(-f)
    [ "$USE_SPOOF" = true ] && [ "$SPOOF_MAC" != "0" ] && NMAP_INITIAL+=(--spoof-mac "$SPOOF_MAC")
    if [ "$USE_ALL_PORTS" = true ]; then
        NMAP_INITIAL+=(-p-)
        echo -e "\e[33m   → Tutte le porte (1-65535)\e[0m"
    else
        NMAP_INITIAL+=(--top-ports "$NMAP_TOP_PORTS_INITIAL")
        echo -e "\e[33m   → Top $NMAP_TOP_PORTS_INITIAL porte\e[0m"
    fi
    NMAP_INITIAL+=(-sV --version-intensity "$NMAP_VERSION_INTENSITY")
    [ -n "$NMAP_SCRIPTS" ] && NMAP_INITIAL+=(--script="$NMAP_SCRIPTS")
    NMAP_INITIAL+=("$target")

    echo -ne "\e[36m   [⏳] Scansione in corso...\e[0m"
    # Timeout globale per scansione iniziale
    local init_timeout=3600
    local init_rc=0
    timeout "$init_timeout" "${NMAP_INITIAL[@]}" > "$OUTPUT_DIR/target_initial_raw.txt" 2>>"$OUTPUT_DIR/nmap_errors.log" || init_rc=$?
    if [ "$init_rc" -eq 124 ]; then
        echo -e "\r\e[33m   [!] Scansione iniziale: timeout dopo ${init_timeout}s\e[0m"
        echo "INITIAL SCAN TIMEOUT after ${init_timeout}s" > "$OUTPUT_DIR/target_initial_raw.txt"
    fi
    clean_nmap_output "$OUTPUT_DIR/target_initial_raw.txt"
    mv "$OUTPUT_DIR/target_initial_raw.txt" "$OUTPUT_DIR/target_initial.txt" 2>/dev/null || true
    echo -e "\r\e[32m   [✓] Scansione completata!\e[0m"

    # ═══════════════════════════════════════════════════════════════════
    # FASE 2/7 — Identificazione rete via ARP
    # ═══════════════════════════════════════════════════════════════════
    SUBNET=""
    GATEWAY=""
    if command -v ip &>/dev/null; then
        PREF_SRC=$(ip -o route get "$target" 2>/dev/null | awk '{print $5; exit}') || true
        if [ -n "$PREF_SRC" ]; then
            GW_CANDIDATE=$(ip -o route get "$target" 2>/dev/null | awk '{print $3; exit}') || true
            [ -n "$GW_CANDIDATE" ] && [ "$GW_CANDIDATE" != "$PREF_SRC" ] && GATEWAY="$GW_CANDIDATE"
            SUBNET_CANDIDATE=$(ip -o -f inet addr show 2>/dev/null | awk -v ip="$PREF_SRC" '$0 ~ ip {print $4; exit}') || true
            [ -n "$SUBNET_CANDIDATE" ] && SUBNET="$SUBNET_CANDIDATE"
        fi
    fi
    if [ -z "$SUBNET" ]; then
        target_net=""
        target_net=$(echo "$target" | grep -oE '^([0-9]{1,3}\.){2}[0-9]{1,3}\.' || true)
        if [ -n "$target_net" ]; then
            SUBNET="${target_net}0/24"
        else
            SUBNET="10.0.0.0/24"
        fi
        log_message "WARN" "Fallback subnet $SUBNET"
    fi
    if [ -z "$GATEWAY" ]; then
        GATEWAY=$(ip route 2>/dev/null | grep "^default" | awk '{print $3}' | head -1) || true
        if [ -z "$GATEWAY" ]; then
            GATEWAY=$(echo "$SUBNET" | sed 's/\.0\/24/.1/' || echo "10.0.0.1")
        fi
        log_message "WARN" "Fallback gateway $GATEWAY"
    fi

    echo -e "\n\e[34m╔═══════════════════════════════════════════════════════════════╗\e[0m"
    echo -e "\e[34m║  [2/7] IDENTIFICAZIONE DISPOSITIVI IN RETE               ║\e[0m"
    echo -e "\e[34m╚═══════════════════════════════════════════════════════════════╝\e[0m"
    log_message "INFO" "Scan ARP sulla subnet $SUBNET (gateway: $GATEWAY)"
    echo -e "\e[33m   → Subnet: $SUBNET\e[0m"
    echo -e "\e[33m   → Gateway: $GATEWAY\e[0m"

    echo -ne "\e[36m   [⏳] Scan ARP in corso...\e[0m"
    nmap -PR -sn "$SUBNET" -oG "$OUTPUT_DIR/hosts_vivi.gnmap" 2>>"$OUTPUT_DIR/nmap_errors.log" || true
    HOSTS_ATTIVI=$(grep "Host:" "$OUTPUT_DIR/hosts_vivi.gnmap" 2>/dev/null | cut -d' ' -f2 | sort -u || echo "")
    NUM_HOSTS=$(echo "$HOSTS_ATTIVI" | grep -c . 2>/dev/null || echo 0)
    echo -e "\r\e[32m   [✓] Trovati $NUM_HOSTS host attivi!\e[0m"

    if [ "$NUM_HOSTS" -gt 0 ] 2>/dev/null; then
        echo "$HOSTS_ATTIVI" | while read -r h; do
            echo -e "      └─ \e[37m$h\e[0m"
        done
    fi

    # Inizializza grafo DOT
    cat > "$GRAPH_DOT" << EOF
graph G {
    label="Mappa Strutturale Rete\\nTarget: $target | $(date)"
    labelloc="t"
    fontsize=14
    node [shape=box, style=filled, color=lightblue, fontname="Helvetica"];
    "Attacker/Kali" -- "$GATEWAY" [label="Gateway", color=red];
EOF

    # ═══════════════════════════════════════════════════════════════════
    # FASE 3/7 — Analisi parallela host
    # ═══════════════════════════════════════════════════════════════════
    echo -e "\n\e[34m╔═══════════════════════════════════════════════════════════════╗\e[0m"
    echo -e "\e[34m║  [3/7] ANALISI PARALLELA DEGLI HOST                     ║\e[0m"
    echo -e "\e[34m╚═══════════════════════════════════════════════════════════════╝\e[0m"
    echo -e "\e[33m   → Job paralleli: $MAX_PARALLEL_JOBS\e[0m"
    log_message "INFO" "Avvio analisi parallela ($MAX_PARALLEL_JOBS job) su $NUM_HOSTS host"

    declare -a PIDS=()
    counter=0
    for host in $HOSTS_ATTIVI; do
        counter=$(( counter + 1 ))
        echo -e "\n\e[36m   [$counter/$NUM_HOSTS] → $host\e[0m"
        scan_host_parallel "$host" &
        PIDS+=($!)
        while [ ${#PIDS[@]} -ge "$MAX_PARALLEL_JOBS" ]; do
            for i in "${!PIDS[@]}"; do
                if ! kill -0 "${PIDS[$i]}" 2>/dev/null; then
                    wait "${PIDS[$i]}" 2>/dev/null || true
                    unset 'PIDS[$i]'
                fi
            done
            PIDS=("${PIDS[@]}")
            sleep 0.5
        done
    done
    for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
    echo -e "\n\e[32m   [✓] Analisi di tutti gli host completata\e[0m"
    echo "}" >> "$GRAPH_DOT"

    # ═══════════════════════════════════════════════════════════════════
    # FASE 4/7 — Diagramma rete PNG
    # ═══════════════════════════════════════════════════════════════════
    echo -e "\n\e[34m╔═══════════════════════════════════════════════════════════════╗\e[0m"
    echo -e "\e[34m║  [4/7] GENERAZIONE DIAGRAMMA DI RETE                     ║\e[0m"
    echo -e "\e[34m╚═══════════════════════════════════════════════════════════════╝\e[0m"
    echo -ne "\e[36m   [⏳] Generazione PNG...\e[0m"
    if command -v dot &>/dev/null; then
        dot -Tpng "$GRAPH_DOT" -o "$GRAPH_PNG" 2>/dev/null || true
        echo -e "\r\e[32m   [✓] Diagramma generato!\e[0m"
    else
        echo -e "\r\e[33m   [!] Graphviz non installato\e[0m"
    fi

    # ═══════════════════════════════════════════════════════════════════
    # FASE 5/7 — Pulizia
    # ═══════════════════════════════════════════════════════════════════
    echo -e "\n\e[34m╔═══════════════════════════════════════════════════════════════╗\e[0m"
    echo -e "\e[34m║  [5/7] PULIZIA FILE TEMPORANEI                           ║\e[0m"
    echo -e "\e[34m╚═══════════════════════════════════════════════════════════════╝\e[0m"
    rm -f "$OUTPUT_DIR"/*_raw.txt 2>/dev/null || true
    rm -f "$OUTPUT_DIR"/*.gnmap  2>/dev/null || true
    find "$OUTPUT_DIR" -name "web_header_*.txt" -size 0 -delete 2>/dev/null || true
    find "$OUTPUT_DIR" -type f -size 0 -delete 2>/dev/null || true
    # Pulisci temp file
    rm -f /tmp/recon_nvd_av_*.tmp 2>/dev/null || true
    echo -e "\e[32m   [✓] Pulizia completata!\e[0m"

    # ═══════════════════════════════════════════════════════════════════
    # FASE 6/7 — Priorità
    # ═══════════════════════════════════════════════════════════════════
    echo -e "\n\e[34m╔═══════════════════════════════════════════════════════════════╗\e[0m"
    echo -e "\e[34m║  [6/7] GENERAZIONE PRIORITÀ VULNERABILITÀ                ║\e[0m"
    echo -e "\e[34m╚═══════════════════════════════════════════════════════════════╝\e[0m"
    generate_priority_file
    echo -e "\e[32m   [✓] File priorità generato\e[0m"

    # ═══════════════════════════════════════════════════════════════════
    # FASE 7/7 — Report JSON + CSV
    # ═══════════════════════════════════════════════════════════════════
    echo -e "\n\e[34m╔═══════════════════════════════════════════════════════════════╗\e[0m"
    echo -e "\e[34m║  [7/7] GENERAZIONE REPORT JSON + CSV                     ║\e[0m"
    echo -e "\e[34m╚═══════════════════════════════════════════════════════════════╝\e[0m"
    generate_json_report
    generate_csv_report

    # Riepilogo target completato
    critical_cves=""
    critical_cves=$(grep -c "🔴 CRITICA" "$PRIORITY_FILE" 2>/dev/null || echo 0)
    echo -e "\n\e[32m   [✓] Target $target completato\e[0m"
    [ "${critical_cves:-0}" -gt 0 ] && echo -e "\e[31m   ⚠️  $critical_cves vulnerabilità CRITICHE\e[0m"
}

# ============================================================================
# INIZIO SCRIPT PRINCIPALE
# ============================================================================

BATCH_FILE=""
TARGET=""
SKIP_DISCLAIMER=false
NON_INTERACTIVE=false

# Help
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "Uso: $0 <IP_TARGET>"
    echo "     $0 --batch <file_targets.txt>"
    echo "     $0 -h | --help"
    echo "     $0 --yes <IP_TARGET>"
    echo ""
    echo "Opzioni:"
    echo "  --yes | --non-interactive  Modalità non interattiva (salta disclaimer e menu)"
    echo ""
    echo "Modalità singola:   $0 192.168.1.10"
    echo "Modalità batch:     $0 --batch targets.txt"
    echo ""
    echo "Formato file batch: un IP o hostname per riga"
    echo "                    Righe vuote e commenti (#) ignorati"
    echo "Pentesting etico — solo su reti autorizzate"
    exit 0
fi

# Parsing argomenti
PARSED_TARGET=""
PARSED_OUTPUT_DIR=""
PARSED_NMAP_TIMING=""
PARSED_TOP_PORTS=""
PARSED_MAX_PARALLEL=""
PARSED_MODE=""
PARSED_LOG_LEVEL=""

i=1
while [ $i -le $# ]; do
    arg="${!i}"
    next_idx=$(( i + 1 ))
    next="${!next_idx:-}"

    if [ "$arg" = "--batch" ]; then
        BATCH_FILE="$next"
        i=$(( i + 2 ))
        continue
    fi

    if [ "$arg" = "--single-target" ]; then
        PARSED_TARGET="$next"
        i=$(( i + 2 ))
        continue
    fi

    # Flag non interattivo
    if [ "$arg" = "--yes" ] || [ "$arg" = "--non-interactive" ]; then
        NON_INTERACTIVE=true
        SKIP_DISCLAIMER=true
        i=$(( i + 1 ))
        continue
    fi

    # Flag con valore (stile --flag=value)
    if [[ "$arg" =~ ^--[a-z-]+=.* ]]; then
        flag_name="${arg%%=*}"
        flag_val="${arg#*=}"
        case "$flag_name" in
            --output-dir)   PARSED_OUTPUT_DIR="$flag_val" ;;
            --nmap-timing)  PARSED_NMAP_TIMING="$flag_val" ;;
            --top-ports)    PARSED_TOP_PORTS="$flag_val" ;;
            --max-parallel) PARSED_MAX_PARALLEL="$flag_val" ;;
            --mode)         PARSED_MODE="$flag_val" ;;
            --log-level)    PARSED_LOG_LEVEL="$flag_val" ;;
        esac
        i=$(( i + 1 ))
        continue
    fi

    # Se il primo argomento non è un flag, è il target
    if [ $i -eq 1 ] && [[ "$arg" != --* ]]; then
        TARGET="$arg"
        i=$(( i + 1 ))
        continue
    fi

    # Flag semplice con valore successivo
    case "$arg" in
        --output-dir)   PARSED_OUTPUT_DIR="$next"; i=$(( i + 2 )) ;;
        --nmap-timing)  PARSED_NMAP_TIMING="$next"; i=$(( i + 2 )) ;;
        --top-ports)    PARSED_TOP_PORTS="$next"; i=$(( i + 2 )) ;;
        --max-parallel) PARSED_MAX_PARALLEL="$next"; i=$(( i + 2 )) ;;
        --mode)         PARSED_MODE="$next"; i=$(( i + 2 )) ;;
        --log-level)    PARSED_LOG_LEVEL="$next"; i=$(( i + 2 )) ;;
        *) i=$(( i + 1 )) ;;
    esac
done
# Se --single-target ha fornito un target, impostalo
if [ -n "$PARSED_TARGET" ]; then
    TARGET="$PARSED_TARGET"
    SKIP_DISCLAIMER=true
    [ -n "$PARSED_OUTPUT_DIR" ]  && OUTPUT_DIR="$PARSED_OUTPUT_DIR"
    [ -n "$PARSED_NMAP_TIMING" ] && NMAP_TIMING="$PARSED_NMAP_TIMING"
    [ -n "$PARSED_TOP_PORTS" ]   && NMAP_TOP_PORTS_INITIAL="$PARSED_TOP_PORTS" && NMAP_TOP_PORTS_DETAIL="$PARSED_TOP_PORTS"
    [ -n "$PARSED_MAX_PARALLEL" ] && MAX_PARALLEL_JOBS="$PARSED_MAX_PARALLEL"
    [ -n "$PARSED_MODE" ]        && MODE_CHOICE="$PARSED_MODE"
    [ -n "$PARSED_LOG_LEVEL" ]   && LOG_LEVEL="$PARSED_LOG_LEVEL"
fi

# Validazione batch
if [ -n "$BATCH_FILE" ]; then
    if [ -z "$BATCH_FILE" ] || [ ! -f "$BATCH_FILE" ]; then
        echo -e "\e[31m[-] Errore: --batch richiede un file valido.\e[0m"
        echo -e "Uso: $0 --batch <file_targets.txt>"
        exit 1
    fi
fi

# Se non abbiamo target e non è batch, errore
if [ -z "$TARGET" ] && [ -z "$BATCH_FILE" ]; then
    echo -e "\e[31m[-] Errore: fornire un IP target o --batch <file>.\e[0m"
    echo -e "Uso: $0 <IP_TARGET>"
    echo -e "     $0 --batch <file_targets.txt>"
    exit 1
fi

# ── MODALITÀ BATCH ──────────────────────────────────────────────────────────
if [ -n "$BATCH_FILE" ]; then
    echo -e "\e[36m═══════════════════════════════════════════════════════════════\e[0m"
    echo -e "\e[36m         MODALITÀ BATCH — Target multipli                    \e[0m"
    echo -e "\e[36m═══════════════════════════════════════════════════════════════\e[0m"
    echo ""

    # Leggi target dal file (salta righe vuote e commenti)
    mapfile -t ALL_TARGETS < <(grep -vE '^\s*(#|$)' "$BATCH_FILE" | sed 's/#.*//' | tr -d '[:space:]')
    NUM_TARGETS="${#ALL_TARGETS[@]}"

    if [ "$NUM_TARGETS" -eq 0 ]; then
        echo -e "\e[31m[-] Nessun target valido trovato in $BATCH_FILE\e[0m"
        exit 1
    fi

    echo -e "\e[33m   File: $BATCH_FILE\e[0m"
    echo -e "\e[33m   Target trovati: $NUM_TARGETS\e[0m"
    echo ""

    # Directory di output unica per tutto il batch
    OUTPUT_DIR="ricognizione_$(date +%Y%m%d_%H%M%S)_batch"
    mkdir -p "$OUTPUT_DIR"
    LOG_FILE="$OUTPUT_DIR/execution.log"
    echo "=== LOG ESECUZIONE BATCH ===" > "$LOG_FILE"
    echo "Avvio: $(date)" >> "$LOG_FILE"
    log_message "INFO" "Batch avviato — $NUM_TARGETS target da $BATCH_FILE"

    # Disclaimer una volta sola
    show_disclaimer
    # Selezione modalità una volta sola
    select_mode
    # Dipendenze + cache una volta sola
    check_dependencies
    init_nvd_cache

    # Test automatici
    TEST_LOG="$OUTPUT_DIR/test_results.log"
    run_tests

    # Loop su tutti i target: chiamata ricorsiva con --single-target + flag
    counter=0
    for t in "${ALL_TARGETS[@]}"; do
        counter=$(( counter + 1 ))
        echo ""
        echo -e "\e[34m═══════════════════════════════════════════════════════════════\e[0m"
        echo -e "\e[34m   [$counter/$NUM_TARGETS] TARGET: $t\e[0m"
        echo -e "\e[34m═══════════════════════════════════════════════════════════════\e[0m"

        bash "$0" --single-target "$t" \
            --output-dir "$OUTPUT_DIR" \
            --nmap-timing "$NMAP_TIMING" \
            --top-ports "$NMAP_TOP_PORTS_INITIAL" \
            --max-parallel "$MAX_PARALLEL_JOBS" \
            --mode "${MODE_CHOICE:-0}" \
            --log-level "$LOG_LEVEL" 2>&1 | tee -a "$OUTPUT_DIR/batch_progress.log" || true

        log_message "INFO" "Target $counter/$NUM_TARGETS: $t completato"
    done

    # Riepilogo batch
    total_cves=$(grep -r "CVE-" "$OUTPUT_DIR" 2>/dev/null | grep -c "CVE-" || echo 0)

    echo ""
    echo -e "\e[32m╔═══════════════════════════════════════════════════════════════╗\e[0m"
    echo -e "\e[32m║  ✓ BATCH COMPLETATO — $NUM_TARGETS target scansionati           ║\e[0m"
    echo -e "\e[32m╚═══════════════════════════════════════════════════════════════╝\e[0m"
    echo -e "\e[36m   📁 Output consolidato: \e[33m$OUTPUT_DIR\e[0m"
    echo -e "\e[36m   📊 Report per target: \e[33m$total_cves CVE totali\e[0m"
    echo -e "\e[36m   📄 Log batch: \e[33m$OUTPUT_DIR/batch_progress.log\e[0m"

    exit 0
fi

# ── MODALITÀ SINGOLA TARGET (diretta o ricorsiva da batch) ────────────────

if [ "$SKIP_DISCLAIMER" != "true" ]; then
    show_disclaimer
    select_mode
    OUTPUT_DIR="ricognizione_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTPUT_DIR"
    LOG_FILE="$OUTPUT_DIR/execution.log"
    TEST_LOG="$OUTPUT_DIR/test_results.log"
    echo "=== LOG DI ESECUZIONE ===" > "$LOG_FILE"
    echo "Avvio: $(date)" >> "$LOG_FILE"

    check_dependencies
    init_nvd_cache

    # Acquisisci lock per evitare scansioni concorrenti
    acquire_lock

    run_tests
fi

# Validazione target — ottieni l'IP risolto
TARGET_RESOLVED=$(validate_target "$TARGET" || echo "")
if [ -n "$TARGET_RESOLVED" ]; then
    TARGET="$TARGET_RESOLVED"
fi

# Esecuzione scan
scan_single_target "$TARGET"

# Riepilogo finale
crit_count=""
crit_count=$(grep -c "🔴 CRITICA" "$OUTPUT_DIR/00_priorita.txt" 2>/dev/null || echo 0)

echo -e "\n\e[32m╔═══════════════════════════════════════════════════════════════╗\e[0m"
echo -e "\e[32m║  ✓ RICOGNIZIONE COMPLETATA CON SUCCESSO                       ║\e[0m"
echo -e "\e[32m╚═══════════════════════════════════════════════════════════════╝\e[0m"
echo -e "\e[36m   📁 Risultati in: \e[33m$OUTPUT_DIR\e[0m"

if [ "${crit_count:-0}" -gt 0 ]; then
    echo -e "\n\e[31m   ⚠️  ATTENZIONE: $crit_count vulnerabilità CRITICHE rilevate!\e[0m"
fi

log_message "INFO" "Script terminato. Output: $OUTPUT_DIR"
exit 0