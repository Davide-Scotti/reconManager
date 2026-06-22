#!/bin/bash
################################################################################
# SCRIPT: report_pdf.sh
# DESCRIZIONE: Genera un report PDF professionale dal report.json di recognize.sh
#              Include executive summary, tabella vulnerabilità, analisi host,
#              note e limitazioni.
#
# DIPENDENZE: python3 + reportlab (pip3 install --user reportlab)
#
# AUTORE: Scotti Davide - Università Statale degli Studi di Milano
# VERSIONE: 2.0
# DATA: 2026-06-22
#
# USO: ./report_pdf.sh <report.json> [output.pdf]
################################################################################

set -euo pipefail

JSON_FILE="${1:-}"
if [ -z "$JSON_FILE" ] || [ ! -f "$JSON_FILE" ]; then
    echo -e "\e[31m[-] Errore: fornire un file report.json valido.\e[0m"
    echo -e "Uso: $0 <report.json> [output.pdf]"
    exit 1
fi

OUTPUT_PDF="${2:-${JSON_FILE%.json}_report.pdf}"

# Verifica reportlab (installazione --user per utente singolo)
python3 -c "import reportlab" 2>/dev/null || {
    echo -e "\e[33m[!] reportlab non installato. Installazione in corso...\e[0m"
    pip3 install --user reportlab 2>/dev/null || {
        echo -e "\e[31m[-] Errore: installare reportlab con: pip3 install --user reportlab\e[0m"
        exit 1
    }
}

# Passa i parametri a Python via sys.argv (SICURO)
python3 - "$JSON_FILE" "$OUTPUT_PDF" << 'PYEOF'
import json, sys, os, textwrap
from datetime import datetime

# ── Reportlab imports ──
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.colors import HexColor, black, white, Color
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether, ListFlowable, ListItem
)
from reportlab.platypus.flowables import HRFlowable

# ── Load JSON (con encoding utf-8 esplicito) ──
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)

meta = data.get("meta", {})
target = meta.get("target", "N/D")
mode = meta.get("mode", "?")
generated = meta.get("generated", "N/D")
hosts = data.get("hosts", [])

# ── Color palette ──
COLOR_PRIMARY = HexColor("#1a237e")     # blu scuro
COLOR_SECONDARY = HexColor("#283593")
COLOR_ACCENT = HexColor("#3949ab")
COLOR_DANGER = HexColor("#c62828")
COLOR_WARNING = HexColor("#f57f17")
COLOR_SAFE = HexColor("#2e7d32")
COLOR_GRAY = HexColor("#424242")
COLOR_LIGHT_GRAY = HexColor("#f5f5f5")
COLOR_MEDIUM_GRAY = HexColor("#e0e0e0")
COLOR_HEADER_BG = HexColor("#1a237e")
COLOR_ROW_ALT = HexColor("#e8eaf6")

# ── Styles ──
styles = getSampleStyleSheet()

style_title = ParagraphStyle(
    'CustomTitle', parent=styles['Title'],
    fontSize=26, leading=32, textColor=COLOR_PRIMARY,
    spaceAfter=6*mm, alignment=TA_CENTER
)
style_subtitle = ParagraphStyle(
    'CustomSubtitle', parent=styles['Normal'],
    fontSize=14, leading=18, textColor=COLOR_GRAY,
    spaceAfter=4*mm, alignment=TA_CENTER
)
style_h1 = ParagraphStyle(
    'H1', parent=styles['Heading1'],
    fontSize=18, leading=22, textColor=COLOR_PRIMARY,
    spaceBefore=8*mm, spaceAfter=4*mm,
    borderWidth=2, borderColor=COLOR_PRIMARY, borderPadding=4
)
style_h2 = ParagraphStyle(
    'H2', parent=styles['Heading2'],
    fontSize=14, leading=18, textColor=COLOR_SECONDARY,
    spaceBefore=5*mm, spaceAfter=3*mm
)
style_h3 = ParagraphStyle(
    'H3', parent=styles['Heading3'],
    fontSize=12, leading=15, textColor=COLOR_ACCENT,
    spaceBefore=4*mm, spaceAfter=2*mm
)
style_body = ParagraphStyle(
    'Body', parent=styles['Normal'],
    fontSize=10, leading=14, textColor=COLOR_GRAY,
    spaceAfter=3*mm, alignment=TA_JUSTIFY
)
style_code = ParagraphStyle(
    'Code', parent=styles['Code'],
    fontSize=8, leading=10, backColor=COLOR_LIGHT_GRAY,
    borderWidth=1, borderColor=COLOR_MEDIUM_GRAY,
    borderPadding=6, spaceAfter=3*mm
)
style_small = ParagraphStyle(
    'Small', parent=styles['Normal'],
    fontSize=8, leading=10, textColor=HexColor("#757575")
)
style_centered = ParagraphStyle(
    'Centered', parent=styles['Normal'],
    fontSize=10, leading=14, alignment=TA_CENTER
)
style_footer = ParagraphStyle(
    'Footer', parent=styles['Normal'],
    fontSize=7, leading=9, textColor=HexColor("#9e9e9e"),
    alignment=TA_CENTER
)

def score_to_color(score):
    if score is None: return COLOR_GRAY
    try:
        s = float(score)
        if s >= 7.0: return COLOR_DANGER
        elif s >= 4.0: return COLOR_WARNING
        else: return COLOR_SAFE
    except: return COLOR_GRAY

def score_to_label(score):
    if score is None: return "N/D"
    try:
        s = float(score)
        if s >= 7.0: return "CRITICA"
        elif s >= 4.0: return "MEDIA"
        else: return "BASSA"
    except: return "N/D"

# ════════════════════════════════════════════════════════════════════
# BUILD DOCUMENT
# ════════════════════════════════════════════════════════════════════

doc = SimpleDocTemplate(
    sys.argv[2],
    pagesize=A4,
    topMargin=2*cm, bottomMargin=2*cm,
    leftMargin=2.5*cm, rightMargin=2.5*cm,
    title=f"Report di Sicurezza - {target}",
    author="Recon Manager - Scotti Davide"
)

story = []

# ── HELPER: Severity badge ──
def severity_badge(score):
    c = score_to_color(score)
    label = score_to_label(score)
    return f'<font color="{c.hexval()}"><b>● {label}</b></font>'

# ════════════════════════════════════════════════════════════════════
# COPERTINA
# ════════════════════════════════════════════════════════════════════

story.append(Spacer(1, 3*cm))
story.append(HRFlowable(width="100%", color=COLOR_PRIMARY, thickness=3))
story.append(Spacer(1, 1.5*cm))

story.append(Paragraph(
    "REPORT DI SICUREZZA", style_title))
story.append(Paragraph(
    "Vulnerability Assessment & Penetration Test", style_subtitle))
story.append(Spacer(1, 1.5*cm))

# Dettagli target in tabella
target_data = [
    ["Target:", f"<b>{target}</b>"],
    ["Data scansione:", generated],
    ["Modalità:", f"{mode}"],
    ["Strumento:", f"Recon Manager v{meta.get('version','?')}"],
    ["Autore:", meta.get('author','N/D')],
]
target_table = Table(target_data, colWidths=[4*cm, 10*cm])
target_table.setStyle(TableStyle([
    ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
    ('FONTNAME', (1,0), (1,-1), 'Helvetica'),
    ('FONTSIZE', (0,0), (-1,-1), 11),
    ('TEXTCOLOR', (0,0), (-1,-1), COLOR_GRAY),
    ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ('TOPPADDING', (0,0), (-1,-1), 6),
    ('ALIGN', (0,0), (0,-1), 'RIGHT'),
    ('ALIGN', (1,0), (1,-1), 'LEFT'),
]))
story.append(target_table)

story.append(Spacer(1, 1*cm))
story.append(HRFlowable(width="100%", color=COLOR_PRIMARY, thickness=1))
story.append(Spacer(1, 1*cm))

# Classificazione
story.append(Paragraph(
    '<b>CLASSIFICAZIONE: CONFIDENZIALE - USO AUTORIZZATO</b>',
    ParagraphStyle('Class', parent=style_body, alignment=TA_CENTER,
                   textColor=COLOR_DANGER, fontSize=10)
))

story.append(Spacer(1, 2*cm))
story.append(Paragraph(
    "Il presente documento contiene informazioni riservate. "
    "La distribuzione è consentita esclusivamente ai soggetti autorizzati.",
    style_small
))

story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# INDICE (semplice)
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("INDICE", style_h1))
toc_items = [
    "1. Executive Summary",
    "2. Riepilogo Vulnerabilità",
    "3. Dettaglio Host Analizzati",
    "4. Metodologia",
    "5. Allegati Tecnici",
    "6. Note e Limitazioni",
]
for item in toc_items:
    story.append(Paragraph(item, style_body))
    story.append(Spacer(1, 2*mm))
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# 1. EXECUTIVE SUMMARY
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("1. Executive Summary", style_h1))

# Calcola statistiche
n_hosts = len(hosts)
n_cves = sum(len(h.get('cves',[])) for h in hosts)
n_critical = sum(1 for h in hosts for c in h.get('cves',[]) if c.get('score') and float(c['score']) >= 7.0)
n_medium = sum(1 for h in hosts for c in h.get('cves',[]) if c.get('score') and 4.0 <= float(c['score']) < 7.0)
n_low = sum(1 for h in hosts for c in h.get('cves',[]) if c.get('score') and float(c['score']) < 4.0)
n_unknown = sum(1 for h in hosts for c in h.get('cves',[]) if not c.get('score'))

n_ports_open = sum(len(h.get('ports_tcp',[])) + len(h.get('ports_udp',[])) for h in hosts)

# Rischio complessivo
if n_critical > 0:
    risk_level = "CRITICO"
    risk_color = COLOR_DANGER
elif n_medium > 0:
    risk_level = "ALTO"
    risk_color = COLOR_WARNING
else:
    risk_level = "BASSO"
    risk_color = COLOR_SAFE

# Box riepilogo
summary_table_data = [
    ["<b>Indicatore</b>", "<b>Valore</b>"],
    ["Livello di Rischio Complessivo", f'<font color="{risk_color.hexval()}"><b>{risk_level}</b></font>'],
    ["Host Analizzati", str(n_hosts)],
    ["Vulnerabilità Identificate", str(n_cves)],
    ["🔴 Critiche (CVSS ≥ 7.0)", str(n_critical)],
    ["🟡 Medie (CVSS 4.0-6.9)", str(n_medium)],
    ["🟢 Basse (CVSS < 4.0)", str(n_low)],
    ["Porte Aperte (TCP+UDP)", str(n_ports_open)],
]
summary_table = Table(summary_table_data, colWidths=[6*cm, 8*cm])
summary_table.setStyle(TableStyle([
    ('BACKGROUND', (0,0), (-1,0), COLOR_HEADER_BG),
    ('TEXTCOLOR', (0,0), (-1,0), white),
    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
    ('FONTSIZE', (0,0), (-1,-1), 10),
    ('ALIGN', (0,0), (-1,-1), 'LEFT'),
    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ('GRID', (0,0), (-1,-1), 0.5, COLOR_MEDIUM_GRAY),
    ('ROWBACKGROUNDS', (0,1), (-1,-1), [white, COLOR_ROW_ALT]),
    ('TOPPADDING', (0,0), (-1,-1), 6),
    ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ('LEFTPADDING', (0,0), (-1,-1), 8),
]))
story.append(summary_table)

story.append(Spacer(1, 5*mm))
story.append(Paragraph(
    f"È stata condotta un'analisi di sicurezza su <b>{n_hosts}</b> host "
    f"appartenenti al target <b>{target}</b>. "
    f"Sono state identificate <b>{n_cves}</b> vulnerabilità, di cui "
    f"<b><font color=\"{COLOR_DANGER.hexval()}\">{n_critical} critiche</font></b>, "
    f"<b><font color=\"{COLOR_WARNING.hexval()}\">{n_medium} medie</font></b> e "
    f"<b><font color=\"{COLOR_SAFE.hexval()}\">{n_low} basse</font></b>. "
    f"L'analisi è stata condotta in modalità {mode}.",
    style_body
))
story.append(Spacer(1, 3*mm))
story.append(Paragraph(
    '<b>Raccomandazione:</b> Si raccomanda di correggere immediatamente le '
    'vulnerabilità critiche e medie, a partire dagli host esposti su rete pubblica.',
    style_body
))

story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# 2. RIEPILOGO VULNERABILITÀ
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("2. Riepilogo Vulnerabilità", style_h1))
story.append(Paragraph(
    "Tabella riepilogativa di tutte le vulnerabilità identificate, "
    "ordinate per gravità decrescente.", style_body
))
story.append(Spacer(1, 3*mm))

# Raccogli tutte le CVE
all_cves = []
for h in hosts:
    for c in h.get('cves',[]):
        all_cves.append((c.get('score') or 0, h['ip'], c['id'], c.get('score')))
all_cves.sort(key=lambda x: float(x[0]) if x[0] else 0, reverse=True)

if all_cves:
    # Tabella CVE
    cve_header = ["<b>Priorità</b>", "<b>CVE</b>", "<b>Host</b>", "<b>Score</b>"]
    cve_data = [cve_header]
    for score, ip, cve_id, cve_score in all_cves:
        badge = severity_badge(cve_score)
        cve_data.append([
            badge,
            cve_id,
            ip,
            str(cve_score) if cve_score else "N/A"
        ])

    cve_table = Table(cve_data, colWidths=[3*cm, 4.5*cm, 3.5*cm, 2.5*cm])
    cve_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), COLOR_HEADER_BG),
        ('TEXTCOLOR', (0,0), (-1,0), white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('ALIGN', (1,0), (-1,-1), 'LEFT'),
        ('ALIGN', (0,0), (0,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.5, COLOR_MEDIUM_GRAY),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [white, COLOR_ROW_ALT]),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(cve_table)
else:
    story.append(Paragraph("Nessuna vulnerabilità identificata.", style_body))

story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# 3. DETTAGLIO HOST
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("3. Dettaglio Host Analizzati", style_h1))

for idx, host in enumerate(hosts, 1):
    ip = host.get('ip', 'N/D')
    os_info = host.get('os', 'Sconosciuto')
    ports_tcp = host.get('ports_tcp', [])
    ports_udp = host.get('ports_udp', [])
    cves = host.get('cves', [])
    web = host.get('web_services', [])

    # Host header
    story.append(Paragraph(
        f"3.{idx} Host: <b>{ip}</b>", style_h2
    ))

    # Info box
    info_data = [
        ["<b>Proprietà</b>", "<b>Valore</b>"],
        ["Indirizzo IP", ip],
        ["Sistema Operativo", os_info],
        ["Porte TCP aperte", str(len(ports_tcp))],
        ["Porte UDP aperte", str(len(ports_udp))],
    ]
    # CVE count
    if cves:
        n_crit = sum(1 for c in cves if c.get('score') and float(c['score']) >= 7.0)
        n_med = sum(1 for c in cves if c.get('score') and 4.0 <= float(c['score']) < 7.0)
        info_data.append(["Vulnerabilità", f"{len(cves)} totali ({n_crit} critiche, {n_med} medie)"])

    info_table = Table(info_data, colWidths=[3.5*cm, 10*cm])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), COLOR_SECONDARY),
        ('TEXTCOLOR', (0,0), (-1,0), white),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.3, COLOR_MEDIUM_GRAY),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [white, COLOR_LIGHT_GRAY]),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 3*mm))

    # Porte TCP
    if ports_tcp:
        story.append(Paragraph("<b>Porte TCP:</b>", style_h3))
        port_data = [["<b>Porta</b>", "<b>Servizio</b>", "<b>Versione</b>"]]
        for p in ports_tcp[:15]:  # max 15 porte per host
            port_data.append([
                str(p.get('port', '?')),
                p.get('service', '?'),
                p.get('version', '')[:40]
            ])
        if len(ports_tcp) > 15:
            port_data.append(["...", f"e altre {len(ports_tcp)-15} porte", ""])

        port_table = Table(port_data, colWidths=[2*cm, 3.5*cm, 8*cm])
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), COLOR_MEDIUM_GRAY),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.3, COLOR_MEDIUM_GRAY),
            ('TOPPADDING', (0,0), (-1,-1), 2),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(port_table)
        story.append(Spacer(1, 2*mm))

    # CVE per host
    if cves:
        story.append(Paragraph("<b>Vulnerabilità:</b>", style_h3))
        cve_data = [["<b>CVE</b>", "<b>Score</b>", "<b>Priorità</b>"]]
        for c in sorted(cves, key=lambda x: float(x.get('score') or 0), reverse=True):
            s = c.get('score')
            cve_data.append([
                c.get('id', '?'),
                str(s) if s else "N/A",
                severity_badge(s)
            ])
        cve_t = Table(cve_data, colWidths=[4.5*cm, 2.5*cm, 6*cm])
        cve_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), COLOR_MEDIUM_GRAY),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.3, COLOR_MEDIUM_GRAY),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [white, COLOR_LIGHT_GRAY]),
            ('TOPPADDING', (0,0), (-1,-1), 2),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(cve_t)

    # Web services
    if web:
        story.append(Paragraph("<b>Servizi Web:</b>", style_h3))
        for w in web:
            hsts_status = "✅" if w.get('hsts') else "⚠️ No HSTS"
            story.append(Paragraph(
                f"Server: {w.get('server','?')} | HSTS: {hsts_status}",
                style_small
            ))

    story.append(Spacer(1, 5*mm))

story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# 4. METODOLOGIA
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("4. Metodologia", style_h1))
story.append(Paragraph(
    "L'analisi è stata condotta utilizzando il framework <b>Recon Manager</b> "
    "sviluppato da Scotti Davide presso l'Università Statale di Milano.",
    style_body
))
story.append(Spacer(1, 3*mm))

method_steps = [
    ("<b>Fase 1 - Ricognizione:</b> Scansione TCP (SYN) e UDP con nmap. "
     "Rilevamento versioni servizi e sistema operativo."),
    ("<b>Fase 2 - Identificazione Vulnerabilità:</b> Esecuzione script vulners "
     "di nmap per l'identificazione di CVE note."),
    ("<b>Fase 3 - Analisi a 3 Livelli:</b>",
     [
         "Livello 1: Verifica backporting (distro vs vaniglia)",
         "Livello 2: CVSS Attack Vector (da NVD o cache locale)",
         "Livello 3: Configurazione reale (SSH algo, HSTS, server-status)"
     ]),
    ("<b>Fase 4 - Analisi Approfondita:</b> Esecuzione di nikto (web), "
     "testssl.sh (SSL/TLS), enum4linux (SMB), snmpwalk (SNMP), "
     "hydra (SSH bruteforce), whois/PTR lookup."),
    ("<b>Fase 5 - Priorizzazione:</b> Calcolo score composito (0-100) e "
     "classificazione in critica/media/bassa."),
    ("<b>Fase 6 - Report:</b> Generazione report JSON, TXT, PNG (mappa rete) e PDF."),
]

for step in method_steps:
    if isinstance(step, tuple) and len(step) > 1 and isinstance(step[1], list):
        story.append(Paragraph(step[0], style_body))
        for sub in step[1]:
            story.append(Paragraph(f"&nbsp;&nbsp;&nbsp;• {sub}", style_small))
    else:
        story.append(Paragraph(
            f"&nbsp;&nbsp;{step[0] if isinstance(step, str) else step[0]}",
            style_body
        ))
    story.append(Spacer(1, 2*mm))

story.append(Spacer(1, 5*mm))

# Legenda scoring
story.append(Paragraph("<b>Legenda Scoring CVE:</b>", style_h3))
legend_data = [
    ["<b>Score</b>", "<b>Livello</b>", "<b>Azione</b>"],
    ["≥ 70/100", "🔴 VULNERABILITÀ CONCRETA", "Intervento immediato"],
    ["36-69/100", "🟡 ZONA GRIGIA", "Approfondire / Pianificare"],
    ["≤ 35/100", "🟢 FALSO POSITIVO", "Monitorare"],
]
legend_table = Table(legend_data, colWidths=[3*cm, 5*cm, 5.5*cm])
legend_table.setStyle(TableStyle([
    ('BACKGROUND', (0,0), (-1,0), COLOR_MEDIUM_GRAY),
    ('FONTSIZE', (0,0), (-1,-1), 9),
    ('GRID', (0,0), (-1,-1), 0.3, COLOR_MEDIUM_GRAY),
    ('TOPPADDING', (0,0), (-1,-1), 4),
    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ('LEFTPADDING', (0,0), (-1,-1), 6),
]))
story.append(legend_table)

story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# 5. ALLEGATI TECNICI
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("5. Allegati Tecnici", style_h1))
story.append(Paragraph(
    "<b>N.B.</b> Per i dettagli completi, fare riferimento ai file di log "
    "e report generati nella directory di output.",
    style_body
))
story.append(Spacer(1, 3*mm))

allegati = [
    f"Target analizzato: {target}",
    f"Host scoperti: {n_hosts}",
    f"Vulnerabilità totali: {n_cves}",
    f"Report JSON: {os.path.basename(sys.argv[1])}",
]
for a in allegati:
    story.append(Paragraph(f"• {a}", style_body))

story.append(Spacer(1, 1*cm))
story.append(HRFlowable(width="100%", color=COLOR_PRIMARY, thickness=1))
story.append(Spacer(1, 5*mm))
story.append(Paragraph(
    f"Report generato il {datetime.now().strftime('%Y-%m-%d %H:%M')} "
    f"da Recon Manager v{meta.get('version','?')}",
    style_footer
))
story.append(Paragraph(
    "Scotti Davide — Università Statale degli Studi di Milano",
    style_footer
))
story.append(Paragraph(
    "Classificazione: CONFIDENZIALE",
    style_footer
))

story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# 6. NOTE E LIMITAZIONI
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("6. Note e Limitazioni", style_h1))

note_items = [
    ("<b>Copertura:</b> L'analisi è limitata agli host e servizi rilevati "
     "durante la fase di ricognizione. Host non rispondenti o protetti da "
     "firewall potrebbero non essere stati inclusi."),
    ("<b>Falsi positivi:</b> Il sistema di scoring a 3 livelli riduce ma "
     "non elimina la possibilità di falsi positivi. Si raccomanda verifica "
     "manuale delle vulnerabilità critiche."),
    ("<b>Tempistiche:</b> Le vulnerabilità sono riferite alla data di "
     "scansione. Nuove vulnerabilità potrebbero essere scoperte "
     "successivamente."),
    ("<b>Tool esterni:</b> Alcuni tool (nikto, enum4linux, hydra) sono "
     "opzionali. La loro assenza riduce la copertura dell'analisi."),
    ("<b>Rate limiting NVD:</b> Senza API key NVD, il rate limiting è "
     "limitato a 5 richieste ogni 30 secondi. Si consiglia di registrare "
     "una API key gratuita all'indirizzo: "
     "https://nvd.nist.gov/developers/request-an-api-key"),
]

for item in note_items:
    story.append(Paragraph(item, style_body))
    story.append(Spacer(1, 3*mm))

story.append(Spacer(1, 1*cm))
story.append(HRFlowable(width="100%", color=COLOR_PRIMARY, thickness=1))
story.append(Spacer(1, 5*mm))
story.append(Paragraph(
    f"Report generato il {datetime.now().strftime('%Y-%m-%d %H:%M')} "
    f"da Recon Manager v{meta.get('version','?')}",
    style_footer
))
story.append(Paragraph(
    "Scotti Davide — Università Statale degli Studi di Milano",
    style_footer
))
story.append(Paragraph(
    "Classificazione: CONFIDENZIALE — Il presente documento è coperto da segreto professionale",
    style_footer
))

# ════════════════════════════════════════════════════════════════════
# GENERATE PDF
# ════════════════════════════════════════════════════════════════════
doc.build(story)
print(f"PDF generato: {sys.argv[2]}")
print(f"Host: {n_hosts} | CVE: {n_cves} | Critiche: {n_critical} | Medie: {n_medium} | Basse: {n_low}")
PYEOF