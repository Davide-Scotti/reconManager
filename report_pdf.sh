#!/bin/bash
################################################################################
# SCRIPT: report_pdf.sh
# DESCRIZIONE: Genera un report PDF professionale dal report.json di recognize.sh
#              Include executive summary, tabella vulnerabilità, analisi host,
#              grafici CVSS, note e limitazioni.
#
# DIPENDENZE: python3 + reportlab
#
# AUTORE: Scotti Davide - Università Statale degli Studi di Milano
# VERSIONE: 2.0
# DATA: 2026-06-25
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

python3 -c "import reportlab" 2>/dev/null || {
    echo -e "\e[33m[!] reportlab non installato. Installazione in corso...\e[0m"
    pip3 install --break-system-packages reportlab 2>/dev/null || \
    pip3 install --user reportlab 2>/dev/null || {
        echo -e "\e[31m[-] Errore: installare reportlab con: pip3 install reportlab\e[0m"
        exit 1
    }
}

python3 - "$JSON_FILE" "$OUTPUT_PDF" << 'PYEOF'
import json, sys, os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.colors import HexColor, black, white, Color
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, Frame, BaseDocTemplate, PageTemplate
)
from reportlab.platypus.flowables import HRFlowable, Flowable
from reportlab.pdfgen import canvas as pdfcanvas

PAGE_W, PAGE_H = A4

# ════════════════════════════════════════════════════════════════════
# PALETTE — dark professional security theme
# ════════════════════════════════════════════════════════════════════
C_INK        = HexColor("#0D1117")   # quasi nero
C_NAVY       = HexColor("#0A1628")   # blu navy profondo (copertina)
C_BLUE       = HexColor("#1565C0")   # blu principale
C_BLUE_MID   = HexColor("#1976D2")
C_BLUE_LIGHT = HexColor("#E3F2FD")   # sfondo alternato righe
C_ACCENT     = HexColor("#0288D1")   # accento cyan
C_DANGER     = HexColor("#B71C1C")   # rosso critico
C_DANGER_BG  = HexColor("#FFEBEE")
C_WARNING    = HexColor("#E65100")   # arancio medio
C_WARNING_BG = HexColor("#FFF3E0")
C_SAFE       = HexColor("#1B5E20")   # verde basso
C_SAFE_BG    = HexColor("#E8F5E9")
C_GRAY_DARK  = HexColor("#37474F")
C_GRAY       = HexColor("#546E7A")
C_GRAY_MID   = HexColor("#90A4AE")
C_GRAY_LIGHT = HexColor("#ECEFF1")
C_GRAY_LINE  = HexColor("#CFD8DC")
C_WHITE      = white

# ════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════
def score_color(s):
    try:
        v = float(s)
        if v >= 9.0: return HexColor("#7B0000")
        if v >= 7.0: return C_DANGER
        if v >= 4.0: return C_WARNING
        return C_SAFE
    except: return C_GRAY

def score_bg(s):
    try:
        v = float(s)
        if v >= 7.0: return C_DANGER_BG
        if v >= 4.0: return C_WARNING_BG
        return C_SAFE_BG
    except: return C_GRAY_LIGHT

def score_label(s):
    try:
        v = float(s)
        if v >= 9.0: return "CRITICA"
        if v >= 7.0: return "CRITICA"
        if v >= 4.0: return "MEDIA"
        return "BASSA"
    except: return "N/D"

def badge(s):
    c = score_color(s).hexval()
    lbl = score_label(s)
    return f'<font color="{c}"><b>● {lbl}</b></font>'

def hx(color): return color.hexval()

# ════════════════════════════════════════════════════════════════════
# CUSTOM FLOWABLE — CVSS bar chart
# ════════════════════════════════════════════════════════════════════
class CVSSBar(Flowable):
    """Horizontal bar chart of CVE scores."""
    def __init__(self, cves, width=440, bar_h=12, max_bars=20):
        super().__init__()
        self.cves = sorted(cves, key=lambda x: float(x.get('score') or 0), reverse=True)[:max_bars]
        self.width = width
        self.bar_h = bar_h
        self.gap = 4
        self.label_w = 105
        self.height = len(self.cves) * (bar_h + self.gap) + 24

    def draw(self):
        c = self.canv
        chart_w = self.width - self.label_w - 10
        # axis
        c.setStrokeColor(C_GRAY_LINE)
        c.setLineWidth(0.5)
        c.line(self.label_w, 0, self.label_w, self.height - 18)
        # score markers
        c.setFont("Helvetica", 6)
        c.setFillColor(C_GRAY_MID)
        for v in [0, 2, 4, 6, 8, 10]:
            x = self.label_w + (v / 10) * chart_w
            c.line(x, 0, x, self.height - 18)
            c.drawCentredString(x, self.height - 14, str(v))

        y = self.height - 22
        for cve in self.cves:
            score = float(cve.get('score') or 0)
            bar_w = (score / 10.0) * chart_w
            col = score_color(score)
            # bar fill
            c.setFillColor(col)
            c.setStrokeColor(col)
            c.roundRect(self.label_w, y, bar_w, self.bar_h, 2, fill=1, stroke=0)
            # score label inside bar
            if bar_w > 22:
                c.setFillColor(C_WHITE)
                c.setFont("Helvetica-Bold", 6.5)
                c.drawRightString(self.label_w + bar_w - 3, y + 3.5, f"{score:.1f}")
            # CVE label
            c.setFillColor(C_GRAY_DARK)
            c.setFont("Helvetica", 7)
            c.drawRightString(self.label_w - 4, y + 3.5, cve.get('id','?'))
            y -= (self.bar_h + self.gap)

# ════════════════════════════════════════════════════════════════════
# CUSTOM FLOWABLE — Risk gauge (simple colored block)
# ════════════════════════════════════════════════════════════════════
class RiskGauge(Flowable):
    def __init__(self, level, color, width=120, height=42):
        super().__init__()
        self.level = level
        self.color = color
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        c.setFillColor(self.color)
        c.roundRect(0, 0, self.width, self.height, 6, fill=1, stroke=0)
        c.setFillColor(C_WHITE)
        c.setFont("Helvetica-Bold", 9)
        c.drawCentredString(self.width/2, self.height - 16, "RISCHIO")
        c.setFont("Helvetica-Bold", 14)
        c.drawCentredString(self.width/2, 8, self.level)

# ════════════════════════════════════════════════════════════════════
# STYLES
# ════════════════════════════════════════════════════════════════════
styles = getSampleStyleSheet()

def S(name, **kw):
    return ParagraphStyle(name, parent=styles['Normal'], **kw)

sT = S('sTitle', fontSize=28, leading=34, textColor=C_WHITE,
       alignment=TA_LEFT, fontName='Helvetica-Bold', spaceAfter=2*mm)
sSub = S('sSub', fontSize=13, leading=17, textColor=HexColor("#90CAF9"),
         alignment=TA_LEFT, spaceAfter=4*mm)
sH1 = S('sH1', fontSize=14, leading=18, textColor=C_WHITE,
        fontName='Helvetica-Bold', backColor=C_BLUE,
        borderPadding=(5, 8, 5, 8), spaceAfter=4*mm, spaceBefore=6*mm)
sH2 = S('sH2', fontSize=12, leading=16, textColor=C_BLUE,
        fontName='Helvetica-Bold', spaceAfter=3*mm, spaceBefore=5*mm,
        borderWidth=0, borderPadding=0)
sH3 = S('sH3', fontSize=10, leading=14, textColor=C_GRAY_DARK,
        fontName='Helvetica-Bold', spaceAfter=2*mm, spaceBefore=3*mm)
sBody = S('sBody', fontSize=9.5, leading=14, textColor=C_GRAY_DARK,
          spaceAfter=3*mm, alignment=TA_JUSTIFY)
sSmall = S('sSmall', fontSize=8, leading=11, textColor=C_GRAY)
sFooter = S('sFooter', fontSize=7, leading=9, textColor=C_GRAY_MID,
            alignment=TA_CENTER)
sMono = S('sMono', fontSize=8, leading=11, fontName='Courier',
          textColor=C_INK, backColor=C_GRAY_LIGHT,
          borderPadding=4, spaceAfter=2*mm)
sCover = S('sCover', fontSize=9, leading=13, textColor=HexColor("#B0BEC5"))
sCoverVal = S('sCoverVal', fontSize=9, leading=13, textColor=C_WHITE,
              fontName='Helvetica-Bold')

# ════════════════════════════════════════════════════════════════════
# HEADER / FOOTER via canvas
# ════════════════════════════════════════════════════════════════════
REPORT_DATE = datetime.now().strftime('%Y-%m-%d %H:%M')

def on_page(canv, doc, target, author, version):
    canv.saveState()
    w, h = A4
    if doc.page == 1:
        # Full-bleed navy cover background
        canv.setFillColor(C_NAVY)
        canv.rect(0, 0, w, h, fill=1, stroke=0)
        # Accent stripe
        canv.setFillColor(C_ACCENT)
        canv.rect(0, h * 0.38, w, 3, fill=1, stroke=0)
        # Bottom bar
        canv.setFillColor(HexColor("#111D2B"))
        canv.rect(0, 0, w, 45*mm, fill=1, stroke=0)
    else:
        # Header bar
        canv.setFillColor(C_BLUE)
        canv.rect(0, h - 18*mm, w, 18*mm, fill=1, stroke=0)
        canv.setFillColor(C_WHITE)
        canv.setFont("Helvetica-Bold", 8)
        canv.drawString(20*mm, h - 11*mm, f"REPORT DI SICUREZZA — {target}")
        canv.setFont("Helvetica", 7)
        canv.drawRightString(w - 20*mm, h - 11*mm, f"CONFIDENZIALE")
        # thin accent line under header
        canv.setFillColor(C_ACCENT)
        canv.rect(0, h - 18.8*mm, w, 0.8*mm, fill=1, stroke=0)

        # Footer
        canv.setFillColor(C_GRAY_LIGHT)
        canv.rect(0, 0, w, 14*mm, fill=1, stroke=0)
        canv.setFillColor(C_ACCENT)
        canv.rect(0, 13.4*mm, w, 0.6*mm, fill=1, stroke=0)
        canv.setFont("Helvetica", 7)
        canv.setFillColor(C_GRAY)
        canv.drawString(20*mm, 5*mm,
            f"Recon Manager v{version} — {author}")
        canv.drawRightString(w - 20*mm, 5*mm,
            f"Pag. {doc.page}   |   Generato il {REPORT_DATE}")

    canv.restoreState()

# ════════════════════════════════════════════════════════════════════
# LOAD DATA
# ════════════════════════════════════════════════════════════════════
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)

meta    = data.get("meta", {})
target  = meta.get("target", "N/D")
mode    = meta.get("mode", "?")
gen_raw = meta.get("generated", meta.get("date", "N/D"))
version = meta.get("version", "?")
author  = meta.get("author", "N/D")
hosts   = data.get("hosts", [])

# Stats
n_hosts    = len(hosts)
all_cves   = [(c, h['ip']) for h in hosts for c in h.get('cves', [])]
n_cves     = len(all_cves)
n_critical = sum(1 for c,_ in all_cves if c.get('score') and float(c['score']) >= 7.0)
n_medium   = sum(1 for c,_ in all_cves if c.get('score') and 4.0 <= float(c['score']) < 7.0)
n_low      = sum(1 for c,_ in all_cves if c.get('score') and float(c['score']) < 4.0)
n_ports    = sum(len(h.get('ports_tcp',[])) + len(h.get('ports_udp',[])) for h in hosts)

if n_critical > 0:
    risk_level, risk_color = "CRITICO", C_DANGER
elif n_medium > 0:
    risk_level, risk_color = "ALTO", C_WARNING
else:
    risk_level, risk_color = "BASSO", C_SAFE

# ════════════════════════════════════════════════════════════════════
# DOC SETUP
# ════════════════════════════════════════════════════════════════════
doc = SimpleDocTemplate(
    sys.argv[2],
    pagesize=A4,
    topMargin=22*mm, bottomMargin=18*mm,
    leftMargin=20*mm, rightMargin=20*mm,
    title=f"Report di Sicurezza — {target}",
    author=author,
    subject="Vulnerability Assessment & Penetration Test",
    creator=f"Recon Manager v{version}"
)

# Inject canvas callbacks
_on_page = lambda c, d: on_page(c, d, target, author, version)

story = []

# ════════════════════════════════════════════════════════════════════
# PAGE 1 — COPERTINA
# ════════════════════════════════════════════════════════════════════
# Top spacer (below where the text will sit)
story.append(Spacer(1, 52*mm))

story.append(Paragraph("REPORT DI SICUREZZA", sT))
story.append(Paragraph("Vulnerability Assessment &amp; Penetration Test", sSub))
story.append(Spacer(1, 8*mm))

# Horizontal rule accent
story.append(HRFlowable(width="100%", color=C_ACCENT, thickness=1.5))
story.append(Spacer(1, 6*mm))

# Cover info table
cov_data = [
    [Paragraph("Target", sCover),      Paragraph(f"<b>{target}</b>", sCoverVal)],
    [Paragraph("Data scansione", sCover), Paragraph(gen_raw, sCoverVal)],
    [Paragraph("Modalità", sCover),    Paragraph(str(mode), sCoverVal)],
    [Paragraph("Strumento", sCover),   Paragraph(f"Recon Manager v{version}", sCoverVal)],
    [Paragraph("Autore", sCover),      Paragraph(author, sCoverVal)],
]
cov_t = Table(cov_data, colWidths=[38*mm, 120*mm])
cov_t.setStyle(TableStyle([
    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ('TOPPADDING', (0,0), (-1,-1), 5),
    ('LINEBELOW', (0,0), (-1,-2), 0.3, HexColor("#1E3A5F")),
]))
story.append(cov_t)

story.append(Spacer(1, 10*mm))
story.append(HRFlowable(width="100%", color=C_ACCENT, thickness=1))
story.append(Spacer(1, 6*mm))

# Classification banner
cls_style = S('cls', fontSize=9, textColor=HexColor("#EF9A9A"),
              alignment=TA_CENTER, fontName='Helvetica-Bold')
story.append(Paragraph("⚠  CLASSIFICAZIONE: CONFIDENZIALE — USO AUTORIZZATO  ⚠", cls_style))
story.append(Spacer(1, 3*mm))
disc_s = S('disc', fontSize=8, textColor=HexColor("#78909C"), alignment=TA_CENTER)
story.append(Paragraph(
    "Il presente documento contiene informazioni riservate. "
    "La distribuzione è consentita esclusivamente ai soggetti autorizzati. "
    "Vietata la riproduzione non autorizzata.",
    disc_s
))

story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# INDICE
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("INDICE", sH1))
story.append(Spacer(1, 2*mm))
toc = [
    ("1.", "Executive Summary"),
    ("2.", "Riepilogo Vulnerabilità"),
    ("3.", "Analisi CVSS — Distribuzione"),
    ("4.", "Dettaglio Host Analizzati"),
    ("5.", "Metodologia"),
    ("6.", "Allegati Tecnici"),
    ("7.", "Note e Limitazioni"),
]
toc_data = [[Paragraph(n, S('tn', fontSize=9, fontName='Helvetica-Bold', textColor=C_BLUE)),
             Paragraph(t, S('tt', fontSize=9, textColor=C_GRAY_DARK)),
             Paragraph("· · ·", S('td', fontSize=8, textColor=C_GRAY_MID, alignment=TA_RIGHT))]
            for n, t in toc]
toc_t = Table(toc_data, colWidths=[10*mm, 130*mm, 25*mm])
toc_t.setStyle(TableStyle([
    ('LINEBELOW', (0,0), (-1,-1), 0.4, C_GRAY_LINE),
    ('TOPPADDING', (0,0), (-1,-1), 5),
    ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
]))
story.append(toc_t)
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# 1. EXECUTIVE SUMMARY
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("1.  Executive Summary", sH1))

# KPI cards row — simulated as a 4-col table
def kpi_cell(label, value, sub, color):
    inner = Table([
        [Paragraph(label, S('kl', fontSize=7, textColor=HexColor("#90A4AE"), alignment=TA_CENTER))],
        [Paragraph(f'<font color="{hx(color)}"><b>{value}</b></font>',
                   S('kv', fontSize=20, leading=24, alignment=TA_CENTER, fontName='Helvetica-Bold'))],
        [Paragraph(sub, S('ks', fontSize=7, textColor=C_GRAY, alignment=TA_CENTER))],
    ], colWidths=[34*mm])
    inner.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), C_GRAY_LIGHT),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('ROUNDEDCORNERS', [4]),
    ]))
    return inner

kpi_row = Table([[
    kpi_cell("HOST ANALIZZATI", str(n_hosts), "target in scope", C_BLUE),
    kpi_cell("VULNERABILITÀ", str(n_cves), "totali identificate", risk_color),
    kpi_cell("CRITICHE", str(n_critical), "CVSS ≥ 7.0", C_DANGER),
    kpi_cell("PORTE APERTE", str(n_ports), "TCP + UDP", C_ACCENT),
]], colWidths=[38*mm, 38*mm, 38*mm, 38*mm])
kpi_row.setStyle(TableStyle([
    ('ALIGN', (0,0), (-1,-1), 'CENTER'),
    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ('LEFTPADDING', (0,0), (-1,-1), 2),
    ('RIGHTPADDING', (0,0), (-1,-1), 2),
]))
story.append(kpi_row)
story.append(Spacer(1, 5*mm))

# Risk gauge + narrative side by side
gauge = RiskGauge(risk_level, risk_color, width=100, height=44)
narrative = Paragraph(
    f"L'analisi di sicurezza condotta sul target <b>{target}</b> ha identificato "
    f"<b>{n_cves}</b> vulnerabilità distribuite su <b>{n_hosts}</b> host. "
    f"Di queste, <b><font color=\"{hx(C_DANGER)}\">{n_critical} sono classificate come critiche</font></b> "
    f"(CVSS ≥ 7.0), <b><font color=\"{hx(C_WARNING)}\">{n_medium} come medie</font></b> "
    f"(CVSS 4.0–6.9) e <b><font color=\"{hx(C_SAFE)}\">{n_low} come basse</font></b>. "
    f"Il livello di rischio complessivo è valutato come "
    f"<b><font color=\"{hx(risk_color)}\">{risk_level}</font></b>. "
    f"Si raccomanda intervento immediato sulle vulnerabilità critiche, "
    f"prioritizzando gli host esposti su rete pubblica.",
    sBody
)

sum_row = Table([[gauge, narrative]], colWidths=[28*mm, 137*mm])
sum_row.setStyle(TableStyle([
    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ('LEFTPADDING', (1,0), (1,0), 8),
    ('RIGHTPADDING', (0,0), (0,0), 4),
]))
story.append(sum_row)
story.append(Spacer(1, 4*mm))

# Summary statistics table
stat_header = [
    Paragraph("<b>Indicatore</b>", S('sh', fontSize=9, textColor=C_WHITE, fontName='Helvetica-Bold')),
    Paragraph("<b>Valore</b>", S('sh2', fontSize=9, textColor=C_WHITE, fontName='Helvetica-Bold', alignment=TA_CENTER)),
    Paragraph("<b>Note</b>", S('sh3', fontSize=9, textColor=C_WHITE, fontName='Helvetica-Bold')),
]
stat_rows = [
    ["Livello di Rischio Complessivo",
     f'<font color="{hx(risk_color)}"><b>{risk_level}</b></font>',
     "Basato su CVSS e copertura"],
    ["Host Analizzati", str(n_hosts), "In scope per questa sessione"],
    ["Vulnerabilità Totali", str(n_cves), "Identificate via vulners + NVD"],
    [f'<font color="{hx(C_DANGER)}">■</font>  Critiche (CVSS ≥ 7.0)',
     f'<font color="{hx(C_DANGER)}"><b>{n_critical}</b></font>', "Intervento immediato"],
    [f'<font color="{hx(C_WARNING)}">■</font>  Medie (CVSS 4.0–6.9)',
     f'<font color="{hx(C_WARNING)}"><b>{n_medium}</b></font>', "Pianificare remediation"],
    [f'<font color="{hx(C_SAFE)}">■</font>  Basse (CVSS &lt; 4.0)',
     f'<font color="{hx(C_SAFE)}"><b>{n_low}</b></font>', "Monitorare"],
    ["Porte Aperte (TCP + UDP)", str(n_ports), "Rilevate nella fase 1"],
    ["Modalità di Scansione", str(mode), "Definisce la profondità"],
]

ps9 = S('ps9', fontSize=9, textColor=C_GRAY_DARK)
ps9c = S('ps9c', fontSize=9, textColor=C_GRAY_DARK, alignment=TA_CENTER)
ps9g = S('ps9g', fontSize=8, textColor=C_GRAY)

tdata = [stat_header] + [
    [Paragraph(r[0], ps9), Paragraph(r[1], ps9c), Paragraph(r[2], ps9g)]
    for r in stat_rows
]
stat_t = Table(tdata, colWidths=[72*mm, 28*mm, 65*mm])
stat_t.setStyle(TableStyle([
    ('BACKGROUND', (0,0), (-1,0), C_BLUE),
    ('FONTSIZE', (0,0), (-1,-1), 9),
    ('ALIGN', (1,0), (1,-1), 'CENTER'),
    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ('GRID', (0,0), (-1,-1), 0.4, C_GRAY_LINE),
    ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_BLUE_LIGHT]),
    ('TOPPADDING', (0,0), (-1,-1), 5),
    ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ('LEFTPADDING', (0,0), (-1,-1), 7),
    ('LINEBELOW', (0,0), (-1,0), 1, C_ACCENT),
]))
story.append(stat_t)

story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# 2. RIEPILOGO VULNERABILITÀ
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("2.  Riepilogo Vulnerabilità", sH1))
story.append(Paragraph(
    "Tabella riepilogativa di tutte le vulnerabilità identificate, ordinate per "
    "punteggio CVSS decrescente. Le vulnerabilità critiche richiedono intervento immediato.",
    sBody
))

sorted_cves = sorted(all_cves, key=lambda x: float(x[0].get('score') or 0), reverse=True)

if sorted_cves:
    hdr = [
        Paragraph("<b>#</b>", S('ch', fontSize=8, textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph("<b>CVE ID</b>", S('ch', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
        Paragraph("<b>Host</b>", S('ch', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
        Paragraph("<b>CVSS</b>", S('ch', fontSize=8, textColor=C_WHITE, alignment=TA_CENTER, fontName='Helvetica-Bold')),
        Paragraph("<b>Severity</b>", S('ch', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
        Paragraph("<b>Priorità</b>", S('ch', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
    ]
    rows = [hdr]
    row_style_cmds = [
        ('BACKGROUND', (0,0), (-1,0), C_BLUE),
        ('LINEBELOW', (0,0), (-1,0), 1, C_ACCENT),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.3, C_GRAY_LINE),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('ALIGN', (0,0), (0,-1), 'CENTER'),
        ('ALIGN', (3,0), (3,-1), 'CENTER'),
    ]

    for i, (cve, ip) in enumerate(sorted_cves, 1):
        sc  = cve.get('score')
        sc_f = float(sc) if sc else 0
        lbl = score_label(sc)
        col = score_color(sc)
        bg  = C_BLUE_LIGHT if i % 2 == 0 else C_WHITE
        row_style_cmds.append(('BACKGROUND', (0,i), (-1,i), bg))
        # severity color on score cell
        row_style_cmds.append(('TEXTCOLOR', (3,i), (3,i), col))
        rows.append([
            Paragraph(str(i), S('rc', fontSize=8, textColor=C_GRAY, alignment=TA_CENTER)),
            Paragraph(f'<font color="{hx(C_INK)}"><b>{cve.get("id","?")}</b></font>',
                      S('ri', fontSize=8, fontName='Courier')),
            Paragraph(ip, S('rip', fontSize=8, textColor=C_GRAY_DARK)),
            Paragraph(f'<b>{sc_f:.1f}</b>' if sc else "N/A",
                      S('rs', fontSize=9, fontName='Helvetica-Bold',
                        textColor=col, alignment=TA_CENTER)),
            Paragraph(f'<b>{lbl}</b>', S('rl', fontSize=8, textColor=col, fontName='Helvetica-Bold')),
            Paragraph(
                "Intervento immediato" if sc_f >= 7 else
                "Pianificare remediation" if sc_f >= 4 else "Monitorare",
                S('rp', fontSize=8, textColor=C_GRAY)
            ),
        ])

    cve_t = Table(rows, colWidths=[10*mm, 40*mm, 28*mm, 18*mm, 28*mm, 41*mm])
    cve_t.setStyle(TableStyle(row_style_cmds))
    story.append(cve_t)
else:
    story.append(Paragraph("Nessuna vulnerabilità identificata.", sBody))

story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# 3. ANALISI CVSS — DISTRIBUZIONE
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("3.  Analisi CVSS — Distribuzione", sH1))
story.append(Paragraph(
    "Visualizzazione grafica dei punteggi CVSS per tutte le vulnerabilità identificate. "
    "Le barre sono ordinate per gravità decrescente.",
    sBody
))

all_cve_objs = [c for c, _ in sorted_cves]
if all_cve_objs:
    story.append(Spacer(1, 3*mm))
    story.append(CVSSBar(all_cve_objs, width=165*mm, bar_h=13))
    story.append(Spacer(1, 5*mm))

# Distribution by bucket
story.append(Paragraph("Distribuzione per Livello di Gravità", sH3))
dist_data = [
    [Paragraph("<b>Livello</b>", S('dh', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
     Paragraph("<b>Range CVSS</b>", S('dh2', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
     Paragraph("<b>Count</b>", S('dh3', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold', alignment=TA_CENTER)),
     Paragraph("<b>%</b>", S('dh4', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold', alignment=TA_CENTER)),
     Paragraph("<b>Azione richiesta</b>", S('dh5', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
    ],
    [Paragraph(f'<font color="{hx(C_DANGER)}"><b>● CRITICA</b></font>', S('d1', fontSize=9)),
     Paragraph("≥ 7.0", S('d2', fontSize=9)),
     Paragraph(f"<b>{n_critical}</b>", S('d3', fontSize=10, fontName='Helvetica-Bold', textColor=C_DANGER, alignment=TA_CENTER)),
     Paragraph(f"{n_critical/n_cves*100:.0f}%" if n_cves else "0%", S('d4', fontSize=9, alignment=TA_CENTER)),
     Paragraph("Patch / mitigazione immediata", S('d5', fontSize=9)),
    ],
    [Paragraph(f'<font color="{hx(C_WARNING)}"><b>● MEDIA</b></font>', S('d1b', fontSize=9)),
     Paragraph("4.0 – 6.9", S('d2b', fontSize=9)),
     Paragraph(f"<b>{n_medium}</b>", S('d3b', fontSize=10, fontName='Helvetica-Bold', textColor=C_WARNING, alignment=TA_CENTER)),
     Paragraph(f"{n_medium/n_cves*100:.0f}%" if n_cves else "0%", S('d4b', fontSize=9, alignment=TA_CENTER)),
     Paragraph("Pianificare remediation (30 gg)", S('d5b', fontSize=9)),
    ],
    [Paragraph(f'<font color="{hx(C_SAFE)}"><b>● BASSA</b></font>', S('d1c', fontSize=9)),
     Paragraph("&lt; 4.0", S('d2c', fontSize=9)),
     Paragraph(f"<b>{n_low}</b>", S('d3c', fontSize=10, fontName='Helvetica-Bold', textColor=C_SAFE, alignment=TA_CENTER)),
     Paragraph(f"{n_low/n_cves*100:.0f}%" if n_cves else "0%", S('d4c', fontSize=9, alignment=TA_CENTER)),
     Paragraph("Monitorare / next cycle", S('d5c', fontSize=9)),
    ],
]
dist_t = Table(dist_data, colWidths=[30*mm, 25*mm, 18*mm, 15*mm, 77*mm])
dist_t.setStyle(TableStyle([
    ('BACKGROUND', (0,0), (-1,0), C_BLUE),
    ('LINEBELOW', (0,0), (-1,0), 1, C_ACCENT),
    ('FONTSIZE', (0,0), (-1,-1), 9),
    ('GRID', (0,0), (-1,-1), 0.4, C_GRAY_LINE),
    ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_BLUE_LIGHT]),
    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ('TOPPADDING', (0,0), (-1,-1), 5),
    ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ('LEFTPADDING', (0,0), (-1,-1), 7),
]))
story.append(dist_t)
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# 4. DETTAGLIO HOST
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("4.  Dettaglio Host Analizzati", sH1))

for idx, host in enumerate(hosts, 1):
    ip        = host.get('ip', 'N/D')
    os_info   = host.get('os', 'Sconosciuto')
    ports_tcp = host.get('ports_tcp', [])
    ports_udp = host.get('ports_udp', [])
    cves_h    = host.get('cves', [])
    web       = host.get('web_services', [])

    n_crit_h = sum(1 for c in cves_h if c.get('score') and float(c['score']) >= 7.0)
    n_med_h  = sum(1 for c in cves_h if c.get('score') and 4.0 <= float(c['score']) < 7.0)
    host_risk = "CRITICO" if n_crit_h > 0 else ("MEDIO" if n_med_h > 0 else "BASSO")
    host_rc   = C_DANGER if n_crit_h > 0 else (C_WARNING if n_med_h > 0 else C_SAFE)

    # Host title bar
    story.append(KeepTogether([
        Paragraph(
            f'4.{idx}  &nbsp; <font color="{hx(C_WHITE)}">{ip}</font>'
            f'  <font size="9" color="{hx(C_GRAY_MID)}">— {os_info}</font>',
            sH2
        ),
    ]))

    # Properties table
    info_rows = [
        [Paragraph("<b>Proprietà</b>", S('ih', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
         Paragraph("<b>Valore</b>", S('ih2', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
         Paragraph("<b>Note</b>", S('ih3', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold'))],
        ["Indirizzo IP", ip, ""],
        ["Sistema Operativo", os_info if os_info != 'Unknown' else "Non rilevato", ""],
        ["Porte TCP aperte", str(len(ports_tcp)), ", ".join(str(p['port']) for p in ports_tcp[:8]) + ("…" if len(ports_tcp)>8 else "")],
        ["Porte UDP aperte", str(len(ports_udp)), ", ".join(str(p['port']) for p in ports_udp[:8]) + ("…" if len(ports_udp)>8 else "")],
        ["Rischio host", f'<font color="{hx(host_rc)}"><b>{host_risk}</b></font>',
         f"{len(cves_h)} CVE ({n_crit_h} critiche, {n_med_h} medie)"],
    ]
    ps8 = S('ps8', fontSize=8.5, textColor=C_GRAY_DARK)
    ps8g = S('ps8g', fontSize=8, textColor=C_GRAY)
    info_t_data = [info_rows[0]] + [
        [Paragraph(r[0], ps8), Paragraph(r[1], ps8), Paragraph(r[2], ps8g)]
        for r in info_rows[1:]
    ]
    info_t = Table(info_t_data, colWidths=[38*mm, 45*mm, 82*mm])
    info_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), C_BLUE_MID),
        ('LINEBELOW', (0,0), (-1,0), 0.8, C_ACCENT),
        ('FONTSIZE', (0,0), (-1,-1), 8.5),
        ('GRID', (0,0), (-1,-1), 0.3, C_GRAY_LINE),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_BLUE_LIGHT]),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(info_t)
    story.append(Spacer(1, 3*mm))

    # TCP ports table
    if ports_tcp:
        story.append(Paragraph("<b>Porte TCP:</b>", sH3))
        ph = [
            Paragraph("<b>Porta</b>", S('ph', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph("<b>Servizio</b>", S('ph2', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
            Paragraph("<b>Versione / Banner</b>", S('ph3', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
            Paragraph("<b>Note</b>", S('ph4', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
        ]
        port_rows = [ph]
        for p in ports_tcp[:20]:
            svc = p.get('service','?')
            is_web = svc.lower() in ('http','https','www','ssl/http')
            note = "⚠ HTTP esposto" if is_web and not p.get('ssl') else ""
            port_rows.append([
                Paragraph(str(p.get('port','?')), S('pc', fontSize=8, alignment=TA_CENTER, fontName='Helvetica-Bold', textColor=C_BLUE)),
                Paragraph(svc, S('ps', fontSize=8, fontName='Courier')),
                Paragraph(str(p.get('version',''))[:55], S('pv', fontSize=7.5, textColor=C_GRAY_DARK)),
                Paragraph(note, S('pn', fontSize=7.5, textColor=C_WARNING)),
            ])
        if len(ports_tcp) > 20:
            port_rows.append([Paragraph("…", S('pe', fontSize=8, textColor=C_GRAY, alignment=TA_CENTER)),
                              Paragraph(f"e altre {len(ports_tcp)-20} porte", S('pe2', fontSize=8, textColor=C_GRAY)),
                              Paragraph("", sSmall), Paragraph("", sSmall)])

        pt = Table(port_rows, colWidths=[16*mm, 28*mm, 80*mm, 41*mm])
        pt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), C_GRAY_DARK),
            ('LINEBELOW', (0,0), (-1,0), 0.8, C_ACCENT),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.3, C_GRAY_LINE),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_GRAY_LIGHT]),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(pt)
        story.append(Spacer(1, 2*mm))

    # UDP ports
    if ports_udp:
        story.append(Paragraph("<b>Porte UDP:</b>", sH3))
        ph_udp = [
            Paragraph("<b>Porta</b>", S('pu1', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph("<b>Servizio</b>", S('pu2', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
            Paragraph("<b>Versione</b>", S('pu3', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
        ]
        udp_rows = [ph_udp]
        for p in ports_udp[:10]:
            udp_rows.append([
                Paragraph(str(p.get('port','?')), S('upc', fontSize=8, alignment=TA_CENTER, fontName='Helvetica-Bold', textColor=C_BLUE)),
                Paragraph(p.get('service','?'), S('ups', fontSize=8, fontName='Courier')),
                Paragraph(str(p.get('version',''))[:55], S('upv', fontSize=7.5, textColor=C_GRAY_DARK)),
            ])
        udp_t = Table(udp_rows, colWidths=[16*mm, 28*mm, 121*mm])
        udp_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), C_GRAY_DARK),
            ('LINEBELOW', (0,0), (-1,0), 0.8, C_ACCENT),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.3, C_GRAY_LINE),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_GRAY_LIGHT]),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(udp_t)
        story.append(Spacer(1, 2*mm))

    # CVE per host
    if cves_h:
        story.append(Paragraph(f"<b>Vulnerabilità ({len(cves_h)}):</b>", sH3))
        cveh_hdr = [
            Paragraph("<b>CVE ID</b>", S('cvh1', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
            Paragraph("<b>CVSS</b>", S('cvh2', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph("<b>Severity</b>", S('cvh3', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
            Paragraph("<b>Priorità intervento</b>", S('cvh4', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
        ]
        cveh_rows = [cveh_hdr]
        for cv in sorted(cves_h, key=lambda x: float(x.get('score') or 0), reverse=True):
            sc = cv.get('score')
            sc_f = float(sc) if sc else 0
            col = score_color(sc)
            cveh_rows.append([
                Paragraph(cv.get('id','?'), S('cvi', fontSize=8, fontName='Courier', textColor=C_INK)),
                Paragraph(f"<b>{sc_f:.1f}</b>" if sc else "N/A",
                          S('cvs', fontSize=9, textColor=col, fontName='Helvetica-Bold', alignment=TA_CENTER)),
                Paragraph(f'<b><font color="{hx(col)}">● {score_label(sc)}</font></b>',
                          S('cvl', fontSize=8, fontName='Helvetica-Bold')),
                Paragraph(
                    "Patch immediata — CVSS critico" if sc_f >= 7 else
                    "Pianificare entro 30 giorni" if sc_f >= 4 else "Next review cycle",
                    S('cvp', fontSize=8, textColor=C_GRAY)
                ),
            ])
        cveh_t = Table(cveh_rows, colWidths=[42*mm, 18*mm, 35*mm, 70*mm])
        cveh_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), C_GRAY_DARK),
            ('LINEBELOW', (0,0), (-1,0), 0.8, C_ACCENT),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.3, C_GRAY_LINE),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_BLUE_LIGHT]),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(cveh_t)
        story.append(Spacer(1, 2*mm))

    # Web services
    if web:
        story.append(Paragraph("<b>Servizi Web rilevati:</b>", sH3))
        wh = [
            Paragraph("<b>Porta</b>", S('wh1', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph("<b>Server</b>", S('wh2', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
            Paragraph("<b>HSTS</b>", S('wh3', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph("<b>Osservazioni</b>", S('wh4', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
        ]
        w_rows = [wh]
        for ww in web:
            hsts = ww.get('hsts', False)
            w_rows.append([
                Paragraph(str(ww.get('port','?')), S('wp', fontSize=8, alignment=TA_CENTER, fontName='Helvetica-Bold', textColor=C_BLUE)),
                Paragraph(str(ww.get('server','?'))[:40], S('ws', fontSize=8, fontName='Courier')),
                Paragraph("✓ Sì" if hsts else "✗ No", S('whs', fontSize=8, alignment=TA_CENTER,
                          textColor=C_SAFE if hsts else C_DANGER, fontName='Helvetica-Bold')),
                Paragraph("" if hsts else "⚠ Header HSTS assente — rischio downgrade",
                          S('wo', fontSize=8, textColor=C_WARNING)),
            ])
        wt = Table(w_rows, colWidths=[16*mm, 48*mm, 18*mm, 83*mm])
        wt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), C_GRAY_DARK),
            ('LINEBELOW', (0,0), (-1,0), 0.8, C_ACCENT),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.3, C_GRAY_LINE),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_GRAY_LIGHT]),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(wt)

    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width="100%", color=C_GRAY_LINE, thickness=0.5))
    story.append(Spacer(1, 4*mm))

story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# 5. METODOLOGIA
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("5.  Metodologia", sH1))
story.append(Paragraph(
    "L'analisi è stata condotta utilizzando il framework <b>Recon Manager</b> "
    "sviluppato da Scotti Davide presso l'Università Statale degli Studi di Milano. "
    "Il processo è articolato in sei fasi sequenziali che garantiscono copertura "
    "progressiva e riduzione dei falsi positivi tramite scoring composito.",
    sBody
))
story.append(Spacer(1, 3*mm))

phases = [
    ("01", "Ricognizione", C_ACCENT,
     "Scansione TCP SYN full-port e UDP (top-1000) con nmap. Rilevamento "
     "versioni servizi e OS fingerprinting. Mappatura topologia di rete."),
    ("02", "Identificazione CVE", C_BLUE,
     "Esecuzione script vulners e vulscan di nmap per la correlazione dei "
     "banner rilevati con il database NVD/CVE. Rate limit gestito via API key."),
    ("03", "Scoring a 3 Livelli", C_WARNING,
     "Livello 1: verifica backporting (versione distro vs. upstream vanilla). "
     "Livello 2: CVSS Attack Vector e scope da NVD o cache locale. "
     "Livello 3: configurazione reale (SSH algorithms, HSTS, server-status)."),
    ("04", "Analisi Approfondita", C_BLUE_MID,
     "Nikto (web vulnerability scan), testssl.sh (SSL/TLS audit), "
     "enum4linux (SMB/Samba enumeration), snmpwalk (SNMP v1/v2c), "
     "Hydra (SSH credential bruteforce), WHOIS/PTR lookup."),
    ("05", "Priorizzazione", C_WARNING,
     "Calcolo score composito 0-100 basato su CVSS, exploitability, "
     "exposure e configurazione. Classificazione: Critica / Media / Bassa."),
    ("06", "Reporting", C_SAFE,
     "Generazione output: report.json (machine-readable), report.txt (plain), "
     "mappa_rete.png (topologia visuale), report_pdf.pdf (questo documento)."),
]

for num, title, color, desc in phases:
    row = Table([[
        Paragraph(f'<font color="{hx(C_WHITE)}"><b>{num}</b></font>',
                   S('pnum', fontSize=14, alignment=TA_CENTER, fontName='Helvetica-Bold')),
        Table([
            [Paragraph(f'<font color="{hx(color)}"><b>{title}</b></font>',
                       S('ptit', fontSize=10, fontName='Helvetica-Bold'))],
            [Paragraph(desc, S('pdesc', fontSize=8.5, textColor=C_GRAY_DARK, leading=12))],
        ], colWidths=[149*mm]),
    ]], colWidths=[16*mm, 153*mm])
    row.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), color),
        ('BACKGROUND', (1,0), (1,0), C_GRAY_LIGHT),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (1,0), (1,0), 8),
    ]))
    story.append(row)
    story.append(Spacer(1, 2*mm))

story.append(Spacer(1, 5*mm))

# Scoring legend
story.append(Paragraph("Legenda Scoring CVE:", sH3))
leg_data = [
    [Paragraph("<b>Score composito</b>", S('lh1', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
     Paragraph("<b>Livello</b>", S('lh2', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
     Paragraph("<b>Azione raccomandata</b>", S('lh3', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
     Paragraph("<b>SLA</b>", S('lh4', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold'))],
    ["≥ 70 / 100", f'<font color="{hx(C_DANGER)}"><b>VULNERABILITÀ CONCRETA</b></font>',
     "Patch / workaround immediato", "24-72 ore"],
    ["36 – 69 / 100", f'<font color="{hx(C_WARNING)}"><b>ZONA GRIGIA</b></font>',
     "Analisi manuale + piano remediation", "30 giorni"],
    ["≤ 35 / 100", f'<font color="{hx(C_SAFE)}"><b>PROBABILE FALSO POSITIVO</b></font>',
     "Monitorare al prossimo ciclo", "Prossimo assessment"],
]
ps8leg = S('ps8leg', fontSize=8.5, textColor=C_GRAY_DARK)
leg_rows = [leg_data[0]] + [[Paragraph(r[0], ps8leg), Paragraph(r[1], ps8leg),
                               Paragraph(r[2], ps8leg), Paragraph(r[3], ps8leg)]
                              for r in leg_data[1:]]
leg_t = Table(leg_rows, colWidths=[30*mm, 48*mm, 68*mm, 19*mm])
leg_t.setStyle(TableStyle([
    ('BACKGROUND', (0,0), (-1,0), C_BLUE),
    ('LINEBELOW', (0,0), (-1,0), 0.8, C_ACCENT),
    ('FONTSIZE', (0,0), (-1,-1), 8.5),
    ('GRID', (0,0), (-1,-1), 0.3, C_GRAY_LINE),
    ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_BLUE_LIGHT]),
    ('TOPPADDING', (0,0), (-1,-1), 5),
    ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ('LEFTPADDING', (0,0), (-1,-1), 6),
    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
]))
story.append(leg_t)
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# 6. ALLEGATI TECNICI
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("6.  Allegati Tecnici", sH1))
story.append(Paragraph(
    "La directory di output contiene i seguenti artefatti generati da Recon Manager. "
    "Per l'analisi approfondita di singole vulnerabilità fare riferimento ai log raw.",
    sBody
))

allegati = [
    ("report.json", "machine-readable", "Dati strutturati dell'intera sessione. Input per questo script."),
    ("report.txt", "plain text", "Output testuale completo con tutti i dettagli dei tool."),
    ("mappa_rete.png", "immagine", "Topologia visuale della rete scansionata."),
    ("host_<IP>/nikto_<port>.txt", "nikto", "Output raw di Nikto per ogni porta web rilevata."),
    ("host_<IP>/enum4linux.txt", "enum4linux", "Enumerazione SMB/SAMBA."),
    ("host_<IP>/snmpwalk_*.txt", "snmpwalk", "Dump SNMP v1/v2c public e private."),
    ("host_<IP>/hydra_ssh.txt", "hydra", "Risultati bruteforce SSH (se eseguito)."),
    (os.path.basename(sys.argv[1]), "JSON sorgente", "File di input usato per generare questo report."),
]

alleg_hdr = [
    Paragraph("<b>File</b>", S('ah1', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
    Paragraph("<b>Tipo</b>", S('ah2', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
    Paragraph("<b>Contenuto</b>", S('ah3', fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold')),
]
alleg_rows = [alleg_hdr]
for fname, ftype, fdesc in allegati:
    alleg_rows.append([
        Paragraph(fname, S('af', fontSize=8, fontName='Courier', textColor=C_INK)),
        Paragraph(ftype, S('at', fontSize=8, textColor=C_GRAY)),
        Paragraph(fdesc, S('ad', fontSize=8, textColor=C_GRAY_DARK)),
    ])
alleg_t = Table(alleg_rows, colWidths=[55*mm, 28*mm, 82*mm])
alleg_t.setStyle(TableStyle([
    ('BACKGROUND', (0,0), (-1,0), C_BLUE),
    ('LINEBELOW', (0,0), (-1,0), 0.8, C_ACCENT),
    ('FONTSIZE', (0,0), (-1,-1), 8),
    ('GRID', (0,0), (-1,-1), 0.3, C_GRAY_LINE),
    ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_BLUE_LIGHT]),
    ('TOPPADDING', (0,0), (-1,-1), 4),
    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ('LEFTPADDING', (0,0), (-1,-1), 6),
    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
]))
story.append(alleg_t)
story.append(Spacer(1, 5*mm))

story.append(HRFlowable(width="100%", color=C_GRAY_LINE, thickness=0.5))
story.append(Spacer(1, 4*mm))
story.append(Paragraph(
    f"Report generato il {REPORT_DATE} · Recon Manager v{version}",
    sFooter
))
story.append(Paragraph(f"{author}", sFooter))
story.append(Paragraph("Classificazione: CONFIDENZIALE", sFooter))
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
# 7. NOTE E LIMITAZIONI
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("7.  Note e Limitazioni", sH1))

notes = [
    ("Copertura",
     "L'analisi è limitata agli host e servizi rilevati durante la fase di ricognizione. "
     "Host non rispondenti, host protetti da firewall stateful o sistemi a scansione-attiva "
     "ridotta potrebbero non essere inclusi nel perimetro."),
    ("Falsi Positivi",
     "Il sistema di scoring a 3 livelli riduce ma non elimina la possibilità di falsi positivi. "
     "Le CVE classificate come 'zona grigia' richiedono verifica manuale prima di procedere "
     "con la remediation. Si consiglia conferma tramite exploit PoC in ambiente controllato."),
    ("Tempistiche",
     "Le vulnerabilità sono riferite alla data di scansione. Il panorama delle minacce evolve "
     "continuamente: nuove CVE vengono pubblicate quotidianamente. Si raccomanda di ripetere "
     "l'assessment su base periodica (mensile per sistemi critici, trimestrale per altri)."),
    ("Tool Opzionali",
     "Alcuni tool (nikto, enum4linux, hydra, testssl.sh) sono opzionali e la loro assenza "
     "riduce la copertura dell'analisi. In assenza di nikto il web application layer non "
     "è analizzato; in assenza di testssl.sh la configurazione SSL/TLS non è verificata."),
    ("Rate Limiting NVD",
     "Senza API key NVD il rate limit è di 5 req/30s. Con API key gratuita il limite "
     "sale a 50 req/30s, riducendo significativamente i tempi di scoring. "
     "Registrazione: https://nvd.nist.gov/developers/request-an-api-key"),
    ("Autorizzazione",
     "L'utilizzo di questo strumento su sistemi non autorizzati costituisce reato ai sensi "
     "dell'Art. 615-ter c.p. (accesso abusivo a sistema informatico). L'autore declina "
     "ogni responsabilità per utilizzi non autorizzati."),
]

for title, text in notes:
    block = Table([[
        Paragraph(f'<font color="{hx(C_ACCENT)}"><b>▸</b></font>', S('ni', fontSize=12, textColor=C_ACCENT)),
        Table([
            [Paragraph(f"<b>{title}</b>", S('nt', fontSize=9, textColor=C_BLUE, fontName='Helvetica-Bold'))],
            [Paragraph(text, S('nd', fontSize=8.5, textColor=C_GRAY_DARK, leading=12))],
        ], colWidths=[153*mm]),
    ]], colWidths=[8*mm, 157*mm])
    block.setStyle(TableStyle([
        ('BACKGROUND', (1,0), (1,0), C_GRAY_LIGHT),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (1,0), (1,0), 8),
        ('LINERIGHT', (1,0), (1,0), 0, C_WHITE),
    ]))
    story.append(block)
    story.append(Spacer(1, 2*mm))

story.append(Spacer(1, 8*mm))
story.append(HRFlowable(width="100%", color=C_BLUE, thickness=1))
story.append(Spacer(1, 4*mm))
story.append(Paragraph(
    f"Report generato il {REPORT_DATE} · Recon Manager v{version} · {author}",
    sFooter
))
story.append(Paragraph(
    "Classificazione: CONFIDENZIALE — Il presente documento è coperto da segreto professionale",
    sFooter
))

# ════════════════════════════════════════════════════════════════════
# BUILD
# ════════════════════════════════════════════════════════════════════
doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
print(f"[✓] PDF generato: {sys.argv[2]}")
print(f"    Host: {n_hosts} | CVE: {n_cves} | Critiche: {n_critical} | Medie: {n_medium} | Basse: {n_low}")
PYEOF