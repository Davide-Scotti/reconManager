#!/bin/bash
################################################################################
# SCRIPT: analyze.sh
# DESCRIZIONE: Fase 2 di ricognizione. Prende in input il report.json
#              generato da recognize.sh ed esegue analisi approfondite:
#              nikto (web), enum4linux (SMB), snmpwalk (SNMP UDP),
#              testssl.sh (HTTPS), hydra (bruteforce ssh),
#              whois/PTR lookup, e genera un report finale consolidato.
#
# AUTORE: Scotti Davide - Università Statale degli Studi di Milano
# VERSIONE: 2.1
# DATA: 2026-06-22
#
# USO: ./analyze.sh <report.json>
#
# DIPENDENZE OPZIONALI: nikto, enum4linux, snmpwalk, testssl.sh, hydra, whois
################################################################################

# NOTA: NON usiamo set -e per garantire resilienza.
# Lo script deve sopravvivere a errori parziali (tool esterni che falliscono, etc.)
# e continuare fino al completamento di tutte le analisi.
set -uo pipefail

# ============================================================================
# CONTROLLO INPUT
# ============================================================================
JSON_FILE="${1:-}"
if [ -z "$JSON_FILE" ] || [ ! -f "$JSON_FILE" ]; then
    echo -e "\e[31m[-] Errore: fornire un file report.json valido.\e[0m"
    echo -e "Uso: $0 <report.json>"
    exit 1
fi

# ============================================================================
# CONFIGURAZIONE
# ============================================================================
OUTPUT_DIR="analisi_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/analyze.log"
REPORT_FINAL="$OUTPUT_DIR/report_finale.txt"
TIMEOUT_TOOL=120    # timeout generico per ogni tool esterno
TIMEOUT_NIKTO=180
TIMEOUT_TESTSSL=90
TIMEOUT_HYDRA=300   # 5 min per hydra
HYDRA_USERLIST="/usr/share/wordlists/metasploit/namelist.txt"
HYDRA_PASSLIST="/usr/share/wordlists/rockyou.txt.gz"

trap_cleanup() {
    rm -f "${STDERR_TMP:-}" 2>/dev/null || true
}
trap trap_cleanup EXIT INT TERM

# Error handler NON-bloccante (logga ma non esce)
error_handler() {
    local line=$1
    local cmd=$2
    local rc=$3
    echo -e "\e[31m[!] ERRORE RECUPERATO (linea $line): comando '$cmd' terminato con codice $rc\e[0m" >&2
    log "WARN" "Errore recuperato linea $line: $cmd (exit=$rc)"
}
trap 'error_handler $LINENO "$BASH_COMMAND" $?' ERR

# ============================================================================
# LOGGING
# ============================================================================
log() {
    local level="$1" msg="$2"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] [$level] $msg" >> "$LOG_FILE" 2>/dev/null || true
    case "$level" in
        INFO)  echo -e "\e[36m[*] $msg\e[0m" ;;
        WARN)  echo -e "\e[33m[!] $msg\e[0m" ;;
        ERROR) echo -e "\e[31m[!] $msg\e[0m" >&2 ;;
        OK)    echo -e "\e[32m[✓] $msg\e[0m" ;;
    esac
}

# ============================================================================
# BANNER
# ============================================================================
clear
echo -e "\e[34m╔═══════════════════════════════════════════════════════════════╗\e[0m"
echo -e "\e[34m║  analyze.sh v2.1 — Fase 2 ricognizione approfondita          ║\e[0m"
echo -e "\e[34m╚═══════════════════════════════════════════════════════════════╝\e[0m"
echo -e "\e[36m   Input: $JSON_FILE\e[0m"
echo -e "\e[36m   Output: $OUTPUT_DIR\e[0m"
echo ""

# ============================================================================
# DISCLAIMER
# ============================================================================
echo -e "\e[33m  ⚠️  Questo script esegue analisi attive sugli host nel report.\e[0m"
echo -e "\e[33m      Usare SOLO su reti autorizzate. Art. 615-ter c.p.\e[0m"
read -rp "  Confermo autorizzazione [si/no]: " ok
[[ "$ok" != "si" ]] && { echo "Uscita."; exit 0; }
echo ""

# ============================================================================
# VERIFICA DIPENDENZE OPZIONALI
# ============================================================================
declare -A TOOLS_AVAILABLE=(
    [nikto]=false [enum4linux]=false [snmpwalk]=false
    [testssl]=false [hydra]=false [whois]=false [dig]=false
)

for tool in nikto enum4linux snmpwalk hydra whois; do
    command -v "$tool" &>/dev/null && TOOLS_AVAILABLE[$tool]=true
done
# testssl può essere script o binario
{ command -v testssl &>/dev/null || command -v testssl.sh &>/dev/null; } && \
    TOOLS_AVAILABLE[testssl]=true
# dig per PTR lookup
command -v dig &>/dev/null && TOOLS_AVAILABLE[dig]=true

echo -e "\e[36m  Tool disponibili:\e[0m"
for tool in "${!TOOLS_AVAILABLE[@]}"; do
    if [ "${TOOLS_AVAILABLE[$tool]}" = true ]; then
        echo -e "    ✅ $tool"
    else
        echo -e "    ❌ $tool \e[90m(installare con: sudo apt install $tool)\e[0m"
    fi
done
echo ""

# ============================================================================
# FUNZIONE: Esecuzione tool esterno in modo sicuro (NO eval)
# ============================================================================
run_tool_exec() {
    local tool_name="$1"
    local -n cmd_ref=$2  # nameref all'array
    local out_file="$3"
    local timeout_sec="$4"
    local desc="$5"

    echo -e "\e[36m   [$tool_name] $desc...\e[0m"
    log "INFO" "$tool_name su $desc"

    # Crea temp file sicuro per stderr
    STDERR_TMP=$(mktemp /tmp/analyze_stderr_XXXXXX.tmp) || true
    trap trap_cleanup EXIT INT TERM

    # Esecuzione DIRETTA senza eval — usa l'array
    timeout "$timeout_sec" "${cmd_ref[@]}" > "$out_file" 2>"$STDERR_TMP" || true
    local rc=$?

    if [ $rc -eq 124 ]; then
        log "WARN" "$tool_name: timeout dopo ${timeout_sec}s su $desc"
        echo -e "\e[33m      [!] Timeout dopo ${timeout_sec}s\e[0m"
        rm -f "$STDERR_TMP" 2>/dev/null || true
        return 1
    elif [ $rc -ne 0 ] && [ $rc -ne 1 ] && [ $rc -ne 2 ]; then
        # rc=1 = tool ha trovato vulnerabilità (normale per nikto/testssl)
        # rc=2 = errori di connessione (normale per molti tool)
        # rc>2 = errore reale (crash, segfault)
        local err_msg
        err_msg=$(cat "$STDERR_TMP" 2>/dev/null || true)
        log "WARN" "$tool_name: errore (exit $rc) su $desc — $err_msg"
        echo -e "\e[33m      [!] $tool_name terminato con errore (exit=$rc)\e[0m"
        [ -n "$err_msg" ] && echo -e "\e[90m        stderr: ${err_msg:0:200}\e[0m"
        rm -f "$STDERR_TMP" 2>/dev/null || true
        return 1
    fi
    rm -f "$STDERR_TMP" 2>/dev/null || true
    return 0
}

# ============================================================================
# ESTRAZIONE HOST DAL JSON (python3 — SICURO: path via sys.argv)
# ============================================================================
log "INFO" "Parsing report JSON..."

# Estrai dati host in formato semplice per bash
HOST_DATA=$(python3 - "$JSON_FILE" << 'PYEOF'
import json, sys

try:
    data = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"ERRORE: {e}", file=sys.stderr)
    sys.exit(1)

meta = data.get("meta", {})
print(f"META_TARGET={meta.get('target','?')}")
print(f"META_DATE={meta.get('generated','?')}")
print(f"META_MODE={meta.get('mode','?')}")

for host in data.get("hosts", []):
    ip = host["ip"]
    os_info = host.get("os","Unknown").replace(" ","_")
    
    tcp_ports = ",".join(str(p["port"]) for p in host.get("ports_tcp",[]))
    udp_ports = ",".join(str(p["port"]) for p in host.get("ports_udp",[]))
    
    # Servizi per tipo
    web_ports  = ",".join(str(p["port"]) for p in host.get("ports_tcp",[])
                          if p["service"] in ("http","https","http-alt","ssl/http")
                          or p["port"] in (80,443,8080,8443,8888))
    ssh_open   = any(p["port"]==22 for p in host.get("ports_tcp",[]))
    smb_open   = any(p["port"] in (139,445) for p in host.get("ports_tcp",[]))
    snmp_open  = any(p["port"]==161 for p in host.get("ports_udp",[]))
    https_open = any(p["port"] in (443,8443) for p in host.get("ports_tcp",[]))
    
    cves = "|".join(
        f"{c['id']}:{c['score'] or 0}"
        for c in sorted(host.get("cves",[]), key=lambda x: x.get("score") or 0, reverse=True)
    )
    
    print(f"HOST={ip}|{os_info}|{tcp_ports}|{udp_ports}|{web_ports}|"
          f"{int(ssh_open)}|{int(smb_open)}|{int(snmp_open)}|{int(https_open)}|{cves}")
PYEOF
) || true

if [ $? -ne 0 ] || [ -z "$HOST_DATA" ]; then
    log "ERROR" "Parsing JSON fallito o report vuoto"
    echo -e "\e[31m[-] Parsing JSON fallito. Verifica il file: $JSON_FILE\e[0m"
    exit 1
fi

# Estrai metadati
META_TARGET=$(echo "$HOST_DATA" | grep "^META_TARGET" | cut -d= -f2) || true
META_DATE=$(echo "$HOST_DATA"   | grep "^META_DATE"   | cut -d= -f2) || true
META_MODE=$(echo "$HOST_DATA"   | grep "^META_MODE"   | cut -d= -f2) || true

log "OK" "Report da: $META_TARGET — scansionato: $META_DATE — modalità: $META_MODE"

# Intestazione report finale
cat > "$REPORT_FINAL" << EOF || true
╔══════════════════════════════════════════════════════════════════════════════╗
║              REPORT ANALISI APPROFONDITA — FASE 2                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
Target originale : $META_TARGET
Data scansione   : $META_DATE
Modalità         : $META_MODE
Analisi eseguita : $(date)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF

# ============================================================================
# LOOP HOST
# ============================================================================
HOST_LINES=$(echo "$HOST_DATA" | grep "^HOST=" || true)
TOTAL_HOSTS=$(echo "$HOST_LINES" | grep -c .) || true
[ -z "$TOTAL_HOSTS" ] && TOTAL_HOSTS=0
COUNTER=0

while IFS= read -r raw_line; do
    [ -z "$raw_line" ] && continue
    line="${raw_line#HOST=}"
    IFS='|' read -r ip os_info tcp_ports udp_ports web_ports \
                    ssh_open smb_open snmp_open https_open cves <<< "$line" || true

    COUNTER=$(( COUNTER + 1 ))
    HOST_OUT="$OUTPUT_DIR/host_${ip}"
    mkdir -p "$HOST_OUT" 2>/dev/null || true

    echo -e "\n\e[34m╔═══════════════════════════════════════════════════════════════╗\e[0m"
    echo -e "\e[34m║  HOST [$COUNTER/$TOTAL_HOSTS]: $ip\e[0m"                      ║
    echo -e "\e[34m╚═══════════════════════════════════════════════════════════════╝\e[0m"
    echo -e "\e[36m   OS: $(echo "$os_info" | tr '_' ' ')\e[0m"
    echo -e "\e[36m   TCP: $tcp_ports\e[0m"
    echo -e "\e[36m   UDP: $udp_ports\e[0m"
    log "INFO" "Analisi $ip — SSH:$ssh_open SMB:$smb_open SNMP:$snmp_open WEB:$web_ports HTTPS:$https_open"

    {
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "HOST: $ip"
        echo "OS  : $(echo "$os_info" | tr '_' ' ')"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    } >> "$REPORT_FINAL"

    # ── WHOIS / PTR Lookup ────────────────────────────────────────────────
    echo -e "\e[36m   [WHOIS/PTR]\e[0m"
    {
        echo "[WHOIS/PTR]"
        if [ "${TOOLS_AVAILABLE[whois]}" = true ]; then
            timeout 20 whois "$ip" 2>/dev/null | grep -iE "netname|descr|country|orgname|abuse" | head -10 || true
        fi
        # PTR record
        if [ "${TOOLS_AVAILABLE[dig]}" = true ]; then
            PTR=$(timeout 5 dig -x "$ip" +short 2>/dev/null | head -3 || echo "PTR: N/D")
        else
            PTR=$(timeout 5 nslookup "$ip" 2>/dev/null | grep "name =" | head -1 | awk '{print $NF}' || echo "PTR: N/D")
        fi
        echo "  PTR: $PTR"
    } >> "$REPORT_FINAL" 2>/dev/null || true
    echo -e "\e[32m      [✓] WHOIS completato\e[0m"

    # ── NIKTO (web) ───────────────────────────────────────────────────────
    if [ -n "$web_ports" ] && [ "${TOOLS_AVAILABLE[nikto]}" = true ]; then
        echo -e "\e[36m   [NIKTO] Porte web: $web_ports\e[0m"
        echo "[NIKTO - Web Vulnerability Scan]" >> "$REPORT_FINAL"

        IFS=',' read -ra WPORTS <<< "$web_ports"
        for port in "${WPORTS[@]}"; do
            echo -e "\e[36m      → nikto su $ip:$port...\e[0m"
            local_out="$HOST_OUT/nikto_${port}.txt"
            nikto_cmd="nikto -host $ip -port $port -Format txt -output $OUTPUT_DIR/nikto_${ip}_${port}.txt"
            run_tool_exec "NIKTO" nikto_cmd "$local_out" "$TIMEOUT_NIKTO" "nikto $ip:$port" || true
            
            if [ -f "$local_out" ] && [ -s "$local_out" ]; then
                # Estrai solo i findings (+) per il report finale
                {
                    echo "  Porta $port:"
                    grep "^+" "$local_out" 2>/dev/null | head -20 || echo "  Nessun finding nikto"
                } >> "$REPORT_FINAL" 2>/dev/null || true
                NIKTO_FINDINGS=$(grep -c "^+" "$local_out" 2>/dev/null || echo 0)
                echo -e "\e[32m      [✓] Nikto: $NIKTO_FINDINGS finding su porta $port\e[0m"
            fi
        done
    elif [ -n "$web_ports" ]; then
        echo -e "\e[33m   [NIKTO] Non installato — skip\e[0m"
    fi

    # ── TESTSSL (HTTPS) ───────────────────────────────────────────────────
    if [ "$https_open" = "1" ] && [ "${TOOLS_AVAILABLE[testssl]}" = true ]; then
        echo -e "\e[36m   [TESTSSL] Analisi SSL/TLS su $ip:443...\e[0m"
            local_out="$HOST_OUT/testssl.txt"
            TESTSSL_BIN="testssl"
            command -v testssl.sh &>/dev/null && TESTSSL_BIN="testssl.sh"

            testssl_cmd="$TESTSSL_BIN --severity MEDIUM --logfile $OUTPUT_DIR/testssl_${ip}.txt $ip"
        run_tool_exec "TESTSSL" testssl_cmd "$local_out" "$TIMEOUT_TESTSSL" "testssl $ip:443" || true

        if [ -f "$local_out" ] && [ -s "$local_out" ]; then
            {
                echo "[TESTSSL - SSL/TLS Analysis]"
                grep -iE "VULNERABLE|LOW|MEDIUM|HIGH|CRITICAL" "$local_out" 2>/dev/null | head -20 \
                    || echo "  Nessuna vulnerabilità SSL rilevata"
            } >> "$REPORT_FINAL" 2>/dev/null || true
            VULN_SSL=$(grep -ciE "VULNERABLE|HIGH|CRITICAL" "$local_out" 2>/dev/null || echo 0)
            echo -e "\e[32m      [✓] testssl: $VULN_SSL issue critici SSL/TLS\e[0m"
        fi
    fi

    # ── ENUM4LINUX (SMB) ──────────────────────────────────────────────────
    if [ "$smb_open" = "1" ]; then
        if [ "${TOOLS_AVAILABLE[enum4linux]}" = true ]; then
            echo -e "\e[36m   [ENUM4LINUX] Enumerazione SMB su $ip...\e[0m"
            local_out="$HOST_OUT/smb_enum4linux.txt"
            enum_cmd="enum4linux -a $ip"
            run_tool_exec "ENUM4LINUX" enum_cmd "$local_out" "$TIMEOUT_TOOL" "enum4linux $ip" || true

            if [ -f "$local_out" ] && [ -s "$local_out" ]; then
                {
                    echo "[ENUM4LINUX - SMB Enumeration]"
                    # Estrai users, shares, workgroup
                    grep -E "^\[.+\]|user:|Share|Workgroup|Domain" "$local_out" 2>/dev/null \
                        | grep -v "^$" | head -30 || echo "  Nessun dato SMB estratto"
                } >> "$REPORT_FINAL" 2>/dev/null || true
                USERS=$(grep -c "user:" "$local_out" 2>/dev/null || echo 0)
                SHARES=$(grep -c "Share" "$local_out" 2>/dev/null || echo 0)
                echo -e "\e[32m      [✓] enum4linux: $USERS utenti, $SHARES share trovati\e[0m"
            fi
        else
            echo -e "\e[33m   [ENUM4LINUX] Non installato — uso nmap smb-enum-shares\e[0m"
            local_out="$HOST_OUT/smb_nmap.txt"
            nmap_smb_cmd="nmap -p 139,445 --script smb-vuln* --script-args unsafe=1 -oN $OUTPUT_DIR/nmap_smb_${ip}.txt $ip"
            run_tool_exec "SMB-NMAP" nmap_smb_cmd "$local_out" "$TIMEOUT_TOOL" "nmap SMB $ip" || true
            {
                echo "[SMB via nmap scripts]"
                cat "$local_out" 2>/dev/null || true
            } >> "$REPORT_FINAL" 2>/dev/null || true
        fi
    fi

    # ── SNMPWALK (UDP 161) ────────────────────────────────────────────────
    if [ "$snmp_open" = "1" ]; then
        if [ "${TOOLS_AVAILABLE[snmpwalk]}" = true ]; then
            echo -e "\e[36m   [SNMPWALK] Dump SNMP su $ip (community: public)...\e[0m"
            local_out="$HOST_OUT/snmp_dump.txt"
            snmp_cmd="snmpwalk -v 2c -c public $ip"
            run_tool_exec "SNMPWALK" snmp_cmd "$local_out" 30 "snmpwalk $ip public" || true

            if [ -s "$local_out" ]; then
                SNMP_LINES=$(wc -l < "$local_out") || true
                {
                    echo "[SNMPWALK - SNMP Dump (community: public)]"
                    echo "  OID estratti: $SNMP_LINES"
                    # Mostra info rilevanti: sysDescr, sysName, interfacce
                    grep -iE "sysDescr|sysName|sysContact|ifDescr|hrDeviceDescr" \
                        "$local_out" 2>/dev/null | head -20 || true
                } >> "$REPORT_FINAL" 2>/dev/null || true
                echo -e "\e[31m      [!] SNMP aperto con community 'public'! $SNMP_LINES OID estratti\e[0m"
            else
                echo "  [SNMP] Community 'public' non risponde (o filtrata)" >> "$REPORT_FINAL" 2>/dev/null || true
                echo -e "\e[32m      [✓] SNMP: community 'public' non accessibile\e[0m"
            fi
        fi

        # Prova anche v1 e community "private"
        if [ "${TOOLS_AVAILABLE[snmpwalk]}" = true ]; then
            local_out_priv="$HOST_OUT/snmp_private.txt"
            snmp_priv_cmd="snmpwalk -v 2c -c private $ip"
            run_tool_exec "SNMPWALK" snmp_priv_cmd "$local_out_priv" 20 "snmpwalk $ip private" || true
            [ -s "$local_out_priv" ] && \
                echo -e "\e[31m      [!] SNMP community 'private' ACCESSIBILE!\e[0m"
        fi
    fi

    # ── HYDRA — Bruteforce SSH (solo se wordlist disponibile) ─────────────
    if [ "$ssh_open" = "1" ] && [ "${TOOLS_AVAILABLE[hydra]}" = true ]; then
        echo -e "\e[36m   [HYDRA] Test bruteforce SSH su $ip...\e[0m"
        
        # Determina wordlist disponibile
        userlist=""
        passlist=""
        
        if [ -f "$HYDRA_USERLIST" ]; then
            userlist="$HYDRA_USERLIST"
        elif [ -f "/usr/share/wordlists/metasploit/namelist.txt" ]; then
            userlist="/usr/share/wordlists/metasploit/namelist.txt"
        elif [ -f "/usr/share/wordlists/rockyou.txt" ]; then
            userlist="/usr/share/wordlists/rockyou.txt"
        fi
        
        if [ -f "$HYDRA_PASSLIST" ]; then
            passlist="$HYDRA_PASSLIST"
        elif [ -f "/usr/share/wordlists/rockyou.txt" ]; then
            passlist="/usr/share/wordlists/rockyou.txt"
        fi
        
        if [ -n "$userlist" ] && [ -n "$passlist" ]; then
            local_out="$HOST_OUT/hydra_ssh.txt"
            # Usa solo i primi 50 utenti e 100 password per velocità
            hydra_cmd="hydra -L $userlist -P $passlist ssh://$ip:$port -o $OUTPUT_DIR/hydra_ssh_${ip}_${port}.txt -f -vV"
            run_tool_exec "HYDRA" hydra_cmd "$local_out" "$TIMEOUT_HYDRA" "hydra SSH $ip" || true
            
            if [ -f "$local_out" ] && [ -s "$local_out" ]; then
                found=$(grep -c "login:" "$local_out" 2>/dev/null || echo 0)
                if [ "$found" -gt 0 ]; then
                    echo -e "\e[31m      [!] HYDRA: $found credenziali SSH trovate!\e[0m"
                    {
                        echo "[HYDRA - SSH Bruteforce]"
                        echo "  ⚠️  CREDENZIALI TROVATE:"
                        grep "login:" "$local_out" 2>/dev/null || true
                    } >> "$REPORT_FINAL" 2>/dev/null || true
                else
                    echo -e "\e[32m      [✓] Nessuna credenziale SSH trovata\e[0m"
                    echo "[HYDRA - SSH Bruteforce] Nessuna credenziale trovata" >> "$REPORT_FINAL" 2>/dev/null || true
                fi
            fi
        else
            echo -e "\e[33m   [HYDRA] Wordlist non trovata — skip bruteforce\e[0m"
            echo "[HYDRA - SSH Bruteforce] Skip: wordlist non disponibile" >> "$REPORT_FINAL" 2>/dev/null || true
        fi
        
        # Segnala comunque SSH aperta
        echo "$ip" >> "$OUTPUT_DIR/ssh_targets.txt" 2>/dev/null || true
        {
            echo "[SSH] Porta 22 aperta su $ip"
            echo "  → Candidato per bruteforce manuale con hydra"
            echo "  → Verificare accesso anonimo: ssh -o BatchMode=yes root@$ip 2>&1"
        } >> "$REPORT_FINAL" 2>/dev/null || true
    elif [ "$ssh_open" = "1" ]; then
        echo -e "\e[33m   [SSH] Porta 22 aperta — annotato in ssh_targets.txt\e[0m"
        echo "$ip" >> "$OUTPUT_DIR/ssh_targets.txt" 2>/dev/null || true
        {
            echo "[SSH] Porta 22 aperta su $ip"
            echo "  → Candidato per bruteforce con: hydra -L users.txt -P pass.txt $ip ssh"
            echo "  → Verificare accesso anonimo: ssh -o BatchMode=yes root@$ip 2>&1"
        } >> "$REPORT_FINAL" 2>/dev/null || true
    fi

    # ── CVE critiche — riepilogo per host ────────────────────────────────
    if [ -n "$cves" ]; then
        echo -e "\e[36m   [CVE] Riepilogo vulnerabilità:\e[0m"
        echo "[CVE - Riepilogo vulnerabilità]" >> "$REPORT_FINAL"

        IFS='|' read -ra CVE_LIST <<< "$cves"
        for cve_entry in "${CVE_LIST[@]}"; do
            cve_id="${cve_entry%%:*}"
            cve_score="${cve_entry##*:}"
            
            if python3 -c "exit(0 if float('${cve_score:-0}') >= 7.0 else 1)" 2>/dev/null; then
                color="\e[31m"; label="CRITICA"
            elif python3 -c "exit(0 if float('${cve_score:-0}') >= 4.0 else 1)" 2>/dev/null; then
                color="\e[33m"; label="MEDIA  "
            else
                color="\e[32m"; label="BASSA  "
            fi
            echo -e "      └─ ${color}[$label] $cve_id (score: $cve_score)\e[0m"
            echo "  [$label] $cve_id — score: $cve_score" >> "$REPORT_FINAL" 2>/dev/null || true
        done
    fi

    echo -e "\e[32m\n   [✓] Host $ip completato → $HOST_OUT\e[0m"
done <<< "$HOST_LINES"

# ============================================================================
# RIEPILOGO FINALE
# ============================================================================
{
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "RIEPILOGO ANALISI"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Host analizzati : $TOTAL_HOSTS"
    if [ -f "$OUTPUT_DIR/ssh_targets.txt" ]; then
        echo "SSH targets     : $(wc -l < "$OUTPUT_DIR/ssh_targets.txt")"
    fi
    echo "Output in       : $OUTPUT_DIR"
    echo "Data            : $(date)"
} >> "$REPORT_FINAL" 2>/dev/null || true

echo -e "\n\e[32m╔═══════════════════════════════════════════════════════════════╗\e[0m"
echo -e "\e[32m║  ✓ ANALISI FASE 2 COMPLETATA                                  ║\e[0m"
echo -e "\e[32m╚═══════════════════════════════════════════════════════════════╝\e[0m"
echo -e "\e[36m   📁 Output: \e[33m$OUTPUT_DIR\e[0m"
echo -e "\e[36m   📄 Report finale: \e[33m$REPORT_FINAL\e[0m"
[ -f "$OUTPUT_DIR/ssh_targets.txt" ] && \
    echo -e "\e[33m   ⚠️  SSH targets in: ssh_targets.txt\e[0m"

log "OK" "analyze.sh completato. Output: $OUTPUT_DIR"
exit 0