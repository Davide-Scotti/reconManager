================================================================================
GUIDA COMPLETA ALL'AMBIENTE RECON MANAGER – PROGETTO DI LAUREA
================================================================================

Questa guida spiega passo passo come installare e usare il sistema composto da
manager.sh, install.sh, recognize.sh e analyze.sh.
Autore: Scotti Davide – Università Statale di Milano

================================================================================
1. PREREQUISITI
================================================================================
- Sistema operativo: Debian / Ubuntu / Kali Linux (basato su apt)
- Connessione Internet
- Utente con privilegi sudo
- Disco libero: almeno 500 MB

AVVISO LEGALE: utilizzare solo su reti autorizzate. L'uso non autorizzato viola
l'art. 615-ter c.p.

================================================================================
2. INSTALLAZIONE
================================================================================
2.1 Creare la directory e copiare i quattro script (manager.sh, install.sh,
    recognize.sh, analyze.sh) nella stessa cartella, ad esempio ~/recon_manager

    mkdir -p ~/recon_manager
    cd ~/recon_manager
    # copiare i file .sh in questa cartella

2.2 Rendere eseguibili gli script

    chmod +x *.sh

2.3 Lanciare l'installazione completa (come root)

    sudo ./install.sh

Cosa fa install.sh:
- Aggiorna gli indici apt
- Installa dipendenze obbligatorie (nmap, python3, curl, graphviz, ...)
- Installa dipendenze opzionali (nikto, enum4linux, snmpwalk, hydra, whois, ...)
- Scarica testssl.sh in /usr/local/bin
- Aggiorna i database nmap e installa vulners.nse
- Crea la cache NVD in ~/.cache/recognize_nvd
- Rende eseguibili gli script

Comandi aggiuntivi di install.sh:
- Solo aggiornamento: sudo ./install.sh --update-only
- Solo verifica stato: ./install.sh --check-only

================================================================================
3. USO DEL MANAGER INTERATTIVO (manager.sh)
================================================================================
Avviare con:

    ./manager.sh

Menu principale:

1 - Nuova ricognizione (recognize.sh)
2 - Analisi Fase 2 (analyze.sh) su report.json esistente
3 - Storico sessioni + pulizia
4 - Installazione / Aggiornamento
5 - Gestione cache NVD
6 - Visualizza log manager
7 - Guida rapida
0 - Esci

================================================================================
4. FLUSSO DI LAVORO TIPICO
================================================================================
4.1 Nuova ricognizione (opzione 1)
- Inserire IP o hostname target
- Confermare se pubblico (richiede autorizzazione scritta)
- Scegliere modalità:
    SILENT          - T2, top 100 porte, stealth (decoy, spoof)
    FAST            - T4, top 1000 porte, vulners
    FAST&MASSIVE    - T5, tutte le porte, molto rumoroso
    SILENT&MASSIVE  - T2, tutte le porte, decoy+spoof, stealth ma lento
- Al termine viene creata una cartella in sessioni/ricognizione_YYYYMMDD_HHMMSS/
  con:
    scan_<IP>.txt, scan_udp_<IP>.txt
    macchine_vulnerabili.txt (CVE trovate)
    analisi_falsi_positivi.txt (analisi 3 livelli: backporting, CVSS, config)
    00_priorita.txt (priorità vulnerabilità)
    struttura_rete.png (mappa Graphviz)
    report.json (input per analyze.sh)

- Il manager chiede se avviare subito analyze.sh su quel report.

4.2 Analisi Fase 2 (opzione 2)
- Scegliere un report.json dall'elenco interattivo
- analyze.sh esegue:
    WHOIS/PTR lookup
    Nikto sulle porte web
    testssl.sh su HTTPS
    enum4linux (SMB)
    snmpwalk (community public/private)
    Segnalazione host con SSH aperta (candidati hydra)
    Riepilogo CVE
- Output in sessioni/analisi_YYYYMMDD_HHMMSS/ con report_finale.txt

4.3 Storico sessioni (opzione 3)
- Visualizza tutte le sessioni con dimensioni e numero CVE
- Comandi:
    a - aprire cartella sessioni
    b - eliminare sessioni più vecchie di 30 giorni

4.4 Gestione cache NVD (opzione 5)
- Mostra le CVE in cache (da ~/.cache/recognize_nvd/cvss_cache.json)
- Possibilità di svuotare la cache per forzare re-fetch dall'API NVD

4.5 Log manager (opzione 6)
- Visualizza ultime 40 righe di manager.log
- Possibilità di cancellare il log

================================================================================
5. ESECUZIONE MANUALE (senza manager)
================================================================================
Ricognizione:
    sudo ./recognize.sh 192.168.1.10   (richiede root per SYN scan)

Analisi Fase 2:
    ./analyze.sh sessioni/ricognizione_<data>/report.json

================================================================================
6. RISOLUZIONE PROBLEMI
================================================================================
- nmap non trovato: eseguire sudo ./install.sh
- report.json non valido: prima lanciare recognize.sh su un target
- dot non trovato: sudo apt install graphviz
- cache NVD non si aggiorna: verificare internet, svuotare cache (opzione 5)
- sudo: nmap non trovato: riavviare terminale o eseguire hash -r
- manager non trova recognize.sh: verificare che tutti gli .sh siano nella stessa
  directory e siano eseguibili (chmod +x)

================================================================================
7. STRUTTURA DELLE DIRECTORY
================================================================================
~/recon_manager/
├── manager.sh
├── install.sh
├── recognize.sh
├── analyze.sh
├── manager.log
└── sessioni/
    ├── ricognizione_YYYYMMDD_HHMMSS/
    │   ├── report.json
    │   ├── scan_<IP>.txt
    │   ├── scan_udp_<IP>.txt
    │   ├── macchine_vulnerabili.txt
    │   ├── analisi_falsi_positivi.txt
    │   ├── 00_priorita.txt
    │   ├── struttura_rete.png
    │   └── execution.log
    └── analisi_YYYYMMDD_HHMMSS/
        ├── report_finale.txt
        ├── analyze.log
        ├── ssh_targets.txt
        └── host_<IP>/
            ├── nikto_80.txt
            ├── testssl.txt
            ├── smb_enum4linux.txt
            └── ...

================================================================================
8. CONCLUSIONI
================================================================================
Ora l'ambiente è pronto. Utilizzare il manager per semplificare il flusso di
lavoro. Buona tesi!