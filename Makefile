################################################################################
# Makefile — Recon Manager
# Comandi rapidi per build, scan, report e pulizia
#
# AUTORE: Scotti Davide - Università Statale degli Studi di Milano
# VERSIONE: 2.0
#
# USO: make build          # Build immagine Docker
#       make scan TARGET=192.168.1.1   # Scan singolo target
#       make batch FILE=targets.txt     # Batch scan da file
#       make pdf REPORT=sessioni/ricognizione_*/report.json  # Genera PDF
#       make shell         # Shell interattiva nel container
#       make clean         # Pulisce output e sessioni
################################################################################

# ── Variabili ──
TARGET ?= 192.168.1.1
FILE ?= targets.txt
REPORT ?= sessioni/ricognizione_latest/report.json
DOCKER_TAG ?= recon-manager:latest
COMPOSE ?= docker compose

# Colori per output
GREEN := \033[32m
CYAN := \033[36m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m

# ── Help ──
.PHONY: help
help:
	@echo ""
	@echo "$(CYAN)╔═══════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(CYAN)║  Recon Manager — Makefile                                   ║$(RESET)"
	@echo "$(CYAN)╚═══════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(GREEN)build$(RESET)         Build immagine Docker"
	@echo "$(GREEN)scan$(RESET)          Avvia scan singolo:    make scan TARGET=192.168.1.1"
	@echo "$(GREEN)batch$(RESET)         Avvia batch scan:      make batch FILE=targets.txt"
	@echo "$(GREEN)pdf$(RESET)           Genera report PDF:     make pdf REPORT=report.json"
	@echo "$(GREEN)shell$(RESET)         Shell interattiva nel container"
	@echo "$(GREEN)check$(RESET)         Verifica dipendenze locali"
	@echo "$(GREEN)install$(RESET)       Installa dipendenze locali (sudo)"
	@echo "$(GREEN)clean$(RESET)         Pulisce output Docker + sessioni vecchie"
	@echo "$(GREEN)checksum$(RESET)      Genera checksum SHA256 degli script"
	@echo "$(GREEN)verify$(RESET)        Verifica checksum integrità"
	@echo ""

# ── Build ──
.PHONY: build
build:
	@echo "$(CYAN)[*] Build immagine Docker...$(RESET)"
	docker build -t $(DOCKER_TAG) .

# ── Scan singolo ──
.PHONY: scan
scan:
	@echo "$(CYAN)[*] Avvio scan su target: $(TARGET)$(RESET)"
	@mkdir -p sessioni output targets
	$(COMPOSE) run --rm recon ./recognize.sh $(TARGET)

# ── Batch scan ──
.PHONY: batch
batch:
	@echo "$(CYAN)[*] Avvio batch scan da file: $(FILE)$(RESET)"
	@mkdir -p sessioni output targets
	@if [ ! -f "$(FILE)" ]; then \
		echo "$(RED)[-] File non trovato: $(FILE)$(RESET)"; \
		exit 1; \
	fi
	$(COMPOSE) run --rm recon ./recognize.sh --batch /data/$(notdir $(FILE))

# ── Report PDF ──
.PHONY: pdf
pdf:
	@echo "$(CYAN)[*] Generazione PDF da: $(REPORT)$(RESET)"
	@if [ ! -f "$(REPORT)" ]; then \
		echo "$(RED)[-] Report non trovato: $(REPORT)$(RESET)"; \
		echo "$(YELLOW)[!] Cerca con: find sessioni -name report.json$(RESET)"; \
		exit 1; \
	fi
	$(COMPOSE) run --rm recon ./report_pdf.sh $(abspath $(REPORT))

# ── Shell interattiva ──
.PHONY: shell
shell:
	@echo "$(CYAN)[*] Shell interattiva nel container...$(RESET)"
	$(COMPOSE) run --rm recon /bin/bash

# ── Verifica dipendenze (locale) ──
.PHONY: check
check:
	@echo "$(CYAN)[*] Verifica dipendenze locali...$(RESET)"
	@for tool in nmap curl python3 nikto enum4linux snmpwalk hydra whois graphviz; do \
		if command -v $$tool &>/dev/null; then \
			echo "  $(GREEN)✅ $$tool$(RESET)"; \
		else \
			echo "  $(YELLOW)⚠️  $$tool$(RESET) (opzionale)"; \
		fi; \
	done

# ── Installazione locale ──
.PHONY: install
install:
	@echo "$(CYAN)[*] Installazione dipendenze locali...$(RESET)"
	sudo ./install.sh

# ── Clean ──
.PHONY: clean
clean:
	@echo "$(YELLOW)[!] Pulizia in corso...$(RESET)"
	@echo "  Rimuovo immagini Docker dangling..."
	docker image prune -f 2>/dev/null || true
	@echo "  Rimuovo volume cache NVD..."
	docker volume rm recon_manager_cache 2>/dev/null || true
	@echo "$(GREEN)[✓] Pulizia completata$(RESET)"

# ── Checksum ──
.PHONY: checksum
checksum:
	@echo "$(CYAN)[*] Generazione checksum SHA256...$(RESET)"
	sha256sum *.sh > checksums.sha256 2>/dev/null || true
	@echo "$(GREEN)[✓] checksums.sha256 aggiornato$(RESET)"

# ── Verify ──
.PHONY: verify
verify:
	@echo "$(CYAN)[*] Verifica checksum...$(RESET)"
	@if [ -f checksums.sha256 ]; then \
		sha256sum -c checksums.sha256 --quiet 2>/dev/null && \
			echo "$(GREEN)[✓] Tutti i checksum corrispondono$(RESET)" || \
			echo "$(RED)[-] Attenzione: alcuni file sono stati modificati!$(RESET)"; \
	else \
		echo "$(YELLOW)[!] checksums.sha256 non trovato. Genera con: make checksum$(RESET)"; \
	fi