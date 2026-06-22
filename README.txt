================================================================================
RECON MANAGER v2.0 — FRAMEWORK DI RICOGNIZIONE E VULNERABILITY ASSESSMENT
================================================================================

Autore: Scotti Davide — Università Statale degli Studi di Milano
Versione: 2.0
Data: 2026-06-22

================================================================================
INDICE
================================================================================
1.  Panoramica
2.  Prerequisiti
3.  Installazione
    3.1 Installazione locale (Debian/Ubuntu/Kali)
    3.2 Installazione Docker
    3.3 Verifica installazione
4.  Guida Rapida
5.  Flusso di Lavoro
    5.1 Nuova Ricognizione (Fase 1)
    5.2 Analisi Approfondita (Fase 2)
    5.3 Report PDF
    5.4 Batch Scanning
6.  Modalità di Scansione
7.  Sistema di Scoring CVE (3 Livelli)
8.  Struttura dei File
9.  Uso con Docker
10. Uso con Makefile
11. Configurazione (recon.conf)
12. Risoluzione Problemi
13. Note Legali

================================================================================
1. PANORAMICA
================================================================================

Recon Manager è un framework professionale per penetration testing e
vulnerability assessment, composto da 5 script principali:

  manager.sh      Interfaccia interattiva con menu (10 opzioni)
  recognize.sh    Fase 1: scansioni nmap, CVE analysis, mappa di rete
  analyze.sh      Fase 2: nikto, testssl, enum4linux, snmpwalk, hydra, whois
  install.sh      Setup automatico dipendenze e aggiornamento
  report_pdf.sh   Generazione report PDF professionale

Caratteristiche principali:
  ✓ 4 modalità di scansione (Silent, Fast, Fast&Massive, Silent&Massive)
  ✓ Analisi CVE a 3 livelli (backporting + CVSS + configurazione reale)
  ✓ Cache NVD persistente con batch processing
  ✓ Parallelizzazione host (fino a 8 job simultanei)
  ✓ Mappa di rete PNG (Graphviz)
  ✓ Report in formato JSON, TXT, CSV, PDF
  ✓ Lock file per esecuzioni singole
  ✓ Containerizzazione Docker
  ✓ Configurazione YAML (recon.conf)
  ✓ Rotazione automatica dei log
  ✓ Verifica checksum SHA256

================================================================================
2. PREREQUISITI
================================================================================

Sistema operativo: Kali Linux (raccomandato) / Debian 12+ / Ubuntu 22.04+
Connessione Internet: Richiesta per download dipendenze e API NVD
Privilegi: sudo (per SYN scan e installazione)
Disco libero: Almeno 500 MB
RAM: Almeno 2 GB (4 GB raccomandati per scan massivi)

Dipendenze obbligatorie:
  nmap, curl, python3, python3-pip, graphviz, dnsutils, netcat-openbsd

Dipendenze opzionali (Fase 2):
  nikto, enum4linux, snmp, whois, hydra, testssl.sh

Per la generazione PDF:
  pip3 install --user reportlab

Per il parsing della configurazione YAML:
  pip3 install --user pyyaml

API Key NVD (gratuita, raccomandata):
  https://nvd.nist.gov/developers/request-an-api-key
  Senza API key: 5 richieste ogni 30 secondi (rate limiting automatico)
  Con API key: 50 richieste al secondo

================================================================================
3. INSTALLAZIONE
================================================================================

3.1 Installazione locale (Debian/Ubuntu/Kali)

  git clone https://github.com/Davide-Scotti/reconManager.git
  cd reconManager
  chmod +x *.sh
  sudo ./install.sh

  L'installer esegue automaticamente:
  - Aggiornamento indici apt
  - Installazione dipendenze obbligatorie
  - Installazione dipendenze opzionali
  - Download testssl.sh in /usr/local/bin
  - Aggiornamento nmap scripts + vulners.nse
  - Inizializzazione cache NVD
  - Installazione pyyaml (parsing configurazione)
  - Impostazione permessi esecuzione script

  Comandi aggiuntivi:
    sudo ./install.sh --update-only    # Solo aggiornamento
    ./install.sh --check-only          # Solo verifica stato

3.2 Installazione Docker

  docker build -t recon-manager .
  # Oppure con docker compose:
  docker compose build

3.3 Verifica installazione

  ./install.sh --check-only

  Oppure dal manager interattivo:
  ./manager.sh → Opzione [5] → 3) Verifica stato dipendenze

================================================================================
4. GUIDA RAPIDA
================================================================================

  # 1. Avvia il manager interattivo
  ./manager.sh

  # 2. Oppure esecuzione diretta (Fase 1)
  sudo ./recognize.sh 192.168.1.10

  # 3. Analisi Fase 2 su report esistente
  ./analyze.sh sessioni/ricognizione_20260622_120000/report.json

  # 4. Genera report PDF
  ./report_pdf.sh sessioni/ricognizione_20260622_120000/report.json

  # 5. Batch scanning da file
  sudo ./recognize.sh --batch targets.txt

  # 6. Con Docker
  docker compose run --rm recon ./recognize.sh 192.168.1.10

  # 7. Con Makefile
  make scan TARGET=192.168.1.10

================================================================================
5. FLUSSO DI LAVORO
================================================================================

5.1 Nuova Ricognizione (Fase 1) — recognize.sh

  Avvio: ./manager.sh → Opzione [1] → Inserisci IP target

  Il flusso completo:
  [0/7] Validazione target (formato IP, RFC 1918, raggiungibilità)
  [1/7] Scansione TCP iniziale (SYN scan con modalità scelta)
  [2/7] Identificazione dispositivi in rete (ARP scan)
  [3/7] Analisi parallela host (TCP + UDP + CVE)
  [4/7] Generazione diagramma di rete PNG
  [5/7] Pulizia file temporanei
  [6/7] Generazione priorità vulnerabilità
  [7/7] Report JSON + CSV

  Output in: sessioni/ricognizione_YYYYMMDD_HHMMSS/
  - scan_<IP>.txt              Risultati scan TCP per host
  - scan_udp_<IP>.txt          Risultati scan UDP per host
  - macchine_vulnerabili.txt   CVE trovate
  - analisi_falsi_positivi.txt Analisi 3 livelli
  - 00_priorita.txt            Priorità vulnerabilità
  - 00_priorita.csv            Versione CSV (per Excel)
  - struttura_rete.png         Mappa di rete Graphviz
  - report.json                Input per Fase 2 e PDF
  - execution.log              Log di esecuzione

5.2 Analisi Approfondita (Fase 2) — analyze.sh

  Avvio: ./manager.sh → Opzione [2] → Scegli report.json

  Esegue su ogni host:
  ✓ WHOIS/PTR lookup
  ✓ Nikto (web vulnerability scanner) su porte HTTP/HTTPS
  ✓ testssl.sh (SSL/TLS analysis) su porte HTTPS
  ✓ enum4linux (SMB enumeration) su porte 139/445
  ✓ snmpwalk (SNMP dump) su UDP 161 (community public/private)
  ✓ hydra (SSH bruteforce) su porta 22 (se wordlist disponibile)
  ✓ Riepilogo CVE con classificazione

  Output in: sessioni/analisi_YYYYMMDD_HHMMSS/
  - report_finale.txt          Report consolidato
  - analyze.log                Log di esecuzione
  - ssh_targets.txt            Host con SSH aperta
  - host_<IP>/                 Dettaglio per host
    - nikto_<port>.txt
    - testssl.txt
    - smb_enum4linux.txt
    - snmp_dump.txt
    - hydra_ssh.txt

5.3 Report PDF

  Avvio: ./manager.sh → Opzione [8] → Scegli report.json

  Il PDF include:
  - Copertina con classificazione CONFIDENZIALE
  - Indice
  - Executive Summary con statistiche e livello di rischio
  - Tabella vulnerabilità (ordinate per gravità)
  - Dettaglio host (porte, servizi, CVE)
  - Metodologia e legenda scoring
  - Allegati tecnici
  - Note e limitazioni

5.4 Batch Scanning

  Avvio: ./manager.sh → Opzione [3] → Inserisci file targets

  Formato file targets.txt:
    # Commenti ignorati
    192.168.1.10
    192.168.1.11
    10.0.0.1
    server.example.com

  Output unico in: sessioni/ricognizione_YYYYMMDD_HHMMSS_batch/

================================================================================
6. MODALITÀ DI SCANSIONE
================================================================================

  ┌──────────────────┬────────┬──────────────┬──────────┬──────────────────┐
  │ Modalità         │ Timing │ Porte        │ Script   │ Stealth          │
  ├──────────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ SILENT           │ T2     │ Top 100      │ Nessuno  │ Decoy + Spoof    │
  │ FAST             │ T4     │ Top 1000     │ vulners  │ Nessuno          │
  │ FAST & MASSIVE   │ T5     │ Tutte (1-    │ vulners  │ Nessuno          │
  │                  │        │ 65535)       │          │                  │
  │ SILENT & MASSIVE │ T2     │ Tutte (1-    │ vulners  │ Decoy + Spoof    │
  │                  │        │ 65535)       │          │                  │
  └──────────────────┴────────┴──────────────┴──────────┴──────────────────┘

  SILENT:          Massima furtività, minimo rumore, pochi risultati
  FAST:            Buon compromesso velocità/risultati
  FAST & MASSIVE:  Massima velocità, tutte le porte, molto rumorosa
  SILENT & MASSIVE:Stealth ma completa, richiede molto tempo

================================================================================
7. SISTEMA DI SCORING CVE (3 LIVELLI)
================================================================================

  Livello 1 — OS Backporting:
    Se la distribuzione è riconoscibile (Debian, Ubuntu, RHEL, SUSE, Alpine),
    il backporting delle patch è probabile → score 30/100
    Altrimenti (versione vaniglia) → score 70/100

  Livello 2 — CVSS Attack Vector:
    NETWORK          → score 85/100
    ADJACENT_NETWORK → score 70/100
    LOCAL            → score 30/100
    PHYSICAL         → score 10/100
    UNKNOWN          → score 50/100

  Livello 3 — Configurazione Reale:
    SSH:  verifica algoritmi deboli (diffie-hellman-group1-sha1, ssh-rsa)
    HTTP: verifica server-status accessibile, HSTS
    Altri: score default 50/100

  Score finale = (backporting + attack_vector + configurazione) / 3

  Classificazione:
    ≥ 70/100  → 🔴 VULNERABILITÀ CONCRETA — Intervento immediato
    36-69/100 → 🟡 ZONA GRIGIA — Approfondire / Pianificare
    ≤ 35/100  → 🟢 FALSO POSITIVO — Monitorare

================================================================================
8. STRUTTURA DEI FILE
================================================================================

  ~/recon_manager/
  ├── manager.sh              Interfaccia interattiva (menu 10 opzioni)
  ├── recognize.sh            Fase 1: ricognizione TCP+UDP+CVE
  ├── analyze.sh              Fase 2: analisi approfondita
  ├── install.sh              Setup dipendenze
  ├── report_pdf.sh           Generazione report PDF
  ├── recon.conf              Configurazione YAML
  ├── Makefile                Comandi rapidi
  ├── Dockerfile              Containerizzazione
  ├── docker-compose.yml      Orchestrazione Docker
  ├── checksums.sha256        Checksum SHA256 degli script
  ├── manager.log             Log del manager (rotazione automatica)
  ├── sessioni/
  │   ├── ricognizione_YYYYMMDD_HHMMSS/
  │   │   ├── report.json
  │   │   ├── scan_<IP>.txt
  │   │   ├── scan_udp_<IP>.txt
  │   │   ├── macchine_vulnerabili.txt
  │   │   ├── analisi_falsi_positivi.txt
  │   │   ├── 00_priorita.txt
  │   │   ├── 00_priorita.csv
  │   │   ├── struttura_rete.png
  │   │   └── execution.log
  │   └── analisi_YYYYMMDD_HHMMSS/
  │       ├── report_finale.txt
  │       ├── analyze.log
  │       ├── ssh_targets.txt
  │       └── host_<IP>/
  │           ├── nikto_80.txt
  │           ├── testssl.txt
  │           ├── smb_enum4linux.txt
  │           ├── snmp_dump.txt
  │           └── hydra_ssh.txt
  └── ~/.cache/recognize_nvd/
      └── cvss_cache.json     Cache NVD persistente

================================================================================
9. USO CON DOCKER
================================================================================

  Build immagine:
    docker build -t recon-manager .
    # Oppure
    docker compose build

  Scan singolo target:
    docker compose run --rm recon ./recognize.sh 192.168.1.10

  Batch scan:
    # Prepara targets.txt nella directory ./targets/
    docker compose run --rm recon ./recognize.sh --batch /data/targets.txt

  Analisi Fase 2:
    docker compose run --rm recon ./analyze.sh /app/sessioni/ricognizione_*/report.json

  Report PDF:
    docker compose run --rm recon ./report_pdf.sh /app/sessioni/ricognizione_*/report.json

  Shell interattiva:
    docker compose run --rm recon /bin/bash

  Con API key NVD:
    NVD_API_KEY=your-api-key docker compose run --rm recon ./recognize.sh 192.168.1.10

  Variabili d'ambiente:
    NVD_API_KEY    Chiave API NVD (opzionale, aumenta rate limit)
    TZ             Fuso orario (default: Europe/Rome)

  Volumi:
    ./sessioni:/app/sessioni       Output sessioni (persistente)
    ./targets:/data:ro             File targets per batch
    ./output:/app/output           Output generico
    recon_cache:/root/.cache/...   Cache NVD (persistente)
    ./recon.conf:/app/recon.conf   Config personalizzata

================================================================================
10. USO CON MAKEFILE
================================================================================

  make help              Mostra questo help
  make build             Build immagine Docker
  make scan TARGET=...   Scan singolo target
  make batch FILE=...    Batch scan da file
  make pdf REPORT=...    Genera report PDF
  make shell             Shell interattiva nel container
  make check             Verifica dipendenze locali
  make install           Installa dipendenze locali (sudo)
  make clean             Pulisce output Docker + cache
  make checksum          Genera checksum SHA256
  make verify            Verifica checksum integrità

================================================================================
11. CONFIGURAZIONE (recon.conf)
================================================================================

  Il file recon.conf in formato YAML permette di personalizzare:

  - Log level (DEBUG, INFO, WARN, ERROR)
  - Parallelizzazione host (2-16 job)
  - API key NVD e timeout
  - Timing e porte nmap per ogni modalità
  - Timeout per ogni tool esterno
  - Opzioni stealth (decoy, spoof, fragment)
  - Whitelist target (allowed_targets)
  - Separatore CSV

  La configurazione viene caricata automaticamente all'avvio di manager.sh
  tramite Python/pyyaml. Se pyyaml non è installato, vengono usati i default.

  Esempio di whitelist:
    security:
      allowed_targets: ["192.168.1.0/24", "10.0.0.0/8"]

================================================================================
12. RISOLUZIONE PROBLEMI
================================================================================

  Problema: "nmap non trovato"
    Soluzione: sudo ./install.sh

  Problema: "report.json non valido"
    Soluzione: Prima eseguire recognize.sh su un target

  Problema: "dot non trovato" (mappa PNG non generata)
    Soluzione: sudo apt install graphviz

  Problema: "Cache NVD non si aggiorna"
    Soluzione: Verificare connessione internet
               Svuotare cache: manager.sh → Opzione [6] → 1
               Registrare API key NVD per rate limit più alto

  Problema: "sudo: nmap non trovato"
    Soluzione: Riavviare terminale o eseguire: hash -r

  Problema: "manager non trova recognize.sh"
    Soluzione: Verificare che tutti gli .sh siano nella stessa directory
               chmod +x *.sh

  Problema: "Permission denied" durante scan
    Soluzione: nmap SYN scan (-sS) richiede root
               Eseguire con sudo o come root

  Problema: "hydra: wordlist non trovata"
    Soluzione: Installare wordlist: sudo apt install wordlist
               Oppure: sudo apt install metasploit-framework

  Problema: "reportlab non installato"
    Soluzione: pip3 install --user reportlab

  Problema: "pyyaml non installato"
    Soluzione: pip3 install --user pyyaml
               (La configurazione funziona comunque con valori default)

  Problema: "Log file troppo grande"
    Soluzione: La rotazione automatica mantiene gli ultimi 3 log
               Massimo 10 MB per file
               Cancellazione manuale: manager.sh → Opzione [7] → 1

================================================================================
13. NOTE LEGALI
================================================================================

  AVVISO LEGALE — Art. 615-ter c.p. (Italia)

  Questo strumento è destinato ESCLUSIVAMENTE a:
  - Attività di penetration testing su reti di cui si è proprietari
  - Ambienti di laboratorio e test autorizzati
  - Ricerca accademica con consenso esplicito del proprietario

  L'uso non autorizzato di questo strumento su reti o sistemi di terzi
  costituisce reato ai sensi dell'art. 615-ter del Codice Penale Italiano
  ("Accesso abusivo ad un sistema informatico o telematico") e normative
  equivalenti internazionali.

  L'autore declina ogni responsabilità per usi impropri del software.

  Licenza: Tutti i diritti riservati.
  Per licenze commerciali, contattare l'autore.

================================================================================
© 2026 Scotti Davide — Università Statale degli Studi di Milano
================================================================================