#!/usr/bin/env python3
# ============================================================================
#  mailgen.py — Kunden-Anschreiben (Sicherheitsvorfall) als .eml generieren
#  Vorlage: Marco Neubers Apple-Mail-Fassung (beispiel-kunde.de).
#  Reproduziert: multipart/alternative -> text/plain + multipart/related
#  (HTML + 2 inline-Banner NT-Forensik/NT-Repair), harte Zeilenumbrüche,
#  größere Absatz-Überschriften.
#
#  Aufruf:
#     python3 mailgen.py kunde.json          # Config aus JSON
#     python3 mailgen.py                     # eingebautes Beispiel (angermünder)
#
#  VARIABLE FELDER (alles andere ist fixer Text):
#     domain          Domain des Kunden (z.B. "beispiel-kunde.de")
#     has_shop        true/false -> "und Ihr Shop laufen" / "läuft"
#     affected_area   Ort des Fundes  (z.B. "Shop-Bereich")
#     finding_summary Kurzbeschreibung (z.B. "mehrere versteckte Hintertüren")
#     timeframe       Zeitbezug        (z.B. "erst in diesem Sommer")
#     recipients      [{name, email}]  (To-Header)
#     out             Ziel-.eml (optional; Default aus Domain)
# ============================================================================
import sys, json, pathlib, unicodedata
from email.message import EmailMessage
from email.utils import make_msgid, formatdate, formataddr
from email.headerregistry import Address

HERE = pathlib.Path(__file__).resolve().parent
ASSETS = HERE / "assets"

FROM_NAME  = "Marco Neuber"
FROM_EMAIL = "neuber@netztaucher.com"

# Fester Signatur-/Impressum-Block (aus der Vorlage)
SIGNATUR = [
    "-- ",
    "die netztaucher GmbH",
    "Digital einfach.",
    "",
    "Büro:\tAm Gutshof 36, 16278 Angermünde",
    "Web:\thttp://netztaucher.com",
    "fon:\t+49 (033 31) 25 25 20",
    "mobil:\t+49 (0151) 1578 9017",
    "",
    "Register:\tAG Neuruppin • HRB 10596",
    "GF:\tMarco Neuber",
    "UStID:\tDE291904918",
    "DSGVO:\thttps://netztaucher.com/datenschutz",
]

DEMO = {
    "domain": "beispiel-kunde.de",
    "has_shop": True,
    "affected_area": "Shop-Bereich",
    "finding_summary": "mehrere versteckte Hintertüren",
    "timeframe": "erst in diesem Sommer",
    "recipients": [
        {"name": "", "email": "kunde@beispiel-kunde.de"},
        {"name": "Frau/Herr Nachname", "email": "kunde2@beispiel-kunde.de"},
    ],
}

# ---------------------------------------------------------------------------
def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

def build_bodies(c):
    """Liefert (plain_lines, html_blocks). html_blocks: Liste von ('line'|'br'|'h'|'img', text)."""
    shop_run = "und Ihr Shop laufen" if c["has_shop"] else "läuft"
    dom  = c["domain"]
    area = c["affected_area"]
    find = c["finding_summary"]
    tf   = c["timeframe"]

    # (typ, inhalt) — 'line'=Textzeile, 'br'=Leerzeile, 'h'=große Überschrift, 'img'=Banner-cid-Key
    blocks = [
        ("line", "Hallo und Guten Tag,"),
        ("br", ""),
        ("line", f"hier ist Marco Neuber von netztaucher – ich betreibe den Server, auf dem Ihre Website <b>{esc(dom)}</b>"),
        ("line", f"{shop_run}. Kurz vorweg, damit das nicht wie Spam wirkt: Diese Mail ist echt, kein Fake – im Zweifel"),
        ("line", "rufen Sie mich einfach an."),
        ("br", ""),
        ("line", f"Der Anlass ist leider ernst: Ihre <b>Website ist damit nachweislich kompromittiert</b>. Beim Sicherheits-Monitoring"),
        ("line", f"des Servers sind im <b>{esc(area)}</b> Ihrer Seite {esc(find)} aufgetaucht, {esc(tf)}"),
        ("line", "platziert."),
        ("br", ""),
        ("line", "Bei einem Einbruch zählt jede Stunde, weil die Protokolle mit den entscheidenden Spuren nach kurzer"),
        ("line", "Zeit überschrieben werden. Ich kann sofort beginnen. Rufen Sie mich einfach zurück oder antworten"),
        ("line", "Sie kurz auf diese E-Mail. Ich muss sonst innerhalb von ein paar Stunden sperren."),
        ("br", ""),
        ("line", "Ich freue mich auf Ihre Rückmeldung."),
        ("line", "Viele Grüße, Marco Neuber"),
        ("br", ""),
        ("br", ""),
        ("h", "Details"),
        ("line", "Wichtig ist jetzt vor allem eins: <b>nichts vorschnell löschen</b>. Wer sofort Dateien entfernt, vernichtet die Spuren,"),
        ("line", "die zeigen, wie der Angreifer hereingekommen ist – und dann steht er zwei Wochen später wieder im System."),
        ("br", ""),
        ("line", "Solche Fälle sind mein Tagesgeschäft – die Analyse- und Bereinigungswerkzeuge dafür habe ich selbst"),
        ("line", "entwickelt und öffentlich gelegt. Ich arbeite in zwei klar getrennten Schritten:"),
        ("br", ""),
        ("h", "Schritt 1 – Forensik: erst verstehen, dann anfassen."),
        ("line", "Ich untersuche Ihre Website mit <i>NT-Forensik</i>, meinem Analyse-Werkzeug für genau solche Fälle. Es arbeitet"),
        ("line", "<b>ausschließlich lesend</b> – an Ihrer Seite wird nichts verändert. Sie bekommen einen verständlichen Bericht in"),
        ("line", "Klartext: was passiert ist, wie der Angreifer hereinkam und was zu tun ist – dazu vorbereitete Entwürfe für die"),
        ("line", "DSGVO-Meldung (72-Stunden-Frist) und, falls nötig, die BSI-Meldung."),
        ("img", "forensik"),
        ("line", "Das Werkzeug ist offen einsehbar, inklusive Beispielberichten – Sie kaufen keine Blackbox:"),
        ("line", '<a href="https://github.com/netztaucher/NT-Forensik">https://github.com/netztaucher/NT-Forensik</a>'),
        ("br", ""),
        ("h", "Schritt 2 – Bereinigung"),
        ("line", "Erst wenn klar ist, wo der Schadcode sitzt und wie er hereinkam, wird entfernt: Hintertüren, manipulierte Dateien,"),
        ("line", "fremde Zugänge. Passwörter werden erneuert, das Einfallstor geschlossen. Zum Schluss läuft die Analyse ein"),
        ("line", "zweites Mal – zur Kontrolle, dass nichts übrig bleibt."),
        ("img", "repair"),
        ("line", "Auch dafür nutze ich mein eigenes, dokumentiertes Werkzeug."),
        ("br", ""),
        ("h", "Kosten: 199 € pauschal"),
        ("line", "Analyse, Bericht, Melde-Entwürfe, Bereinigung, Abschlusskontrolle. Der Aufwand liegt typischerweise"),
        ("line", "bei 2–3 Stunden – Sie zahlen den Festpreis, egal wie lange es dauert. Kein Stundensatz, keine Überraschungen."),
        ("br", ""),
        ("br", ""),
    ]
    # Plain-Text-Fassung aus denselben Blöcken (ohne HTML-Tags)
    import re
    def strip(t): return re.sub("<[^>]+>", "", t).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    plain = []
    for typ, t in blocks:
        if typ == "br": plain.append("")
        elif typ == "img": continue
        elif typ == "h": plain.append(strip(t))
        else: plain.append(strip(t))
    plain += [""] + [l.replace("\t", "\t") for l in SIGNATUR]
    return blocks, plain

def render_html(blocks, cids):
    D = 'style="overflow-wrap:break-word;-webkit-nbsp-mode:space;line-break:after-white-space;"'
    out = [f'<html><head><meta http-equiv="content-type" content="text/html; charset=utf-8"></head><body {D}>']
    for typ, t in blocks:
        if typ == "br":
            out.append("<div><br></div>")
        elif typ == "h":
            out.append(f'<div style="font-size:1.28em;font-weight:700;margin-top:2px">{esc(t)}</div>')
        elif typ == "img":
            out.append(f'<div><img src="cid:{cids[t][1:-1]}" alt="{t}.png" style="max-width:100%;height:auto"></div>')
        else:
            out.append(f"<div>{t}</div>")
    # Signatur
    out.append("<div><br></div>")
    for line in SIGNATUR:
        safe = esc(line).replace("\t", '<span style="white-space:pre">\t</span>').replace("http://netztaucher.com", '<a href="http://netztaucher.com">http://netztaucher.com</a>').replace("https://netztaucher.com/datenschutz", '<a href="https://netztaucher.com/datenschutz">https://netztaucher.com/datenschutz</a>')
        out.append(f"<div>{safe if line else '<br>'}</div>")
    out.append("</body></html>")
    return "\n".join(out)

def build_eml(c):
    blocks, plain = build_bodies(c)
    cids = {"forensik": make_msgid(domain="netztaucher.com"),
            "repair":   make_msgid(domain="netztaucher.com")}
    html = render_html(blocks, cids)

    msg = EmailMessage()
    msg["From"] = formataddr((FROM_NAME, FROM_EMAIL))
    tos = []
    for r in c["recipients"]:
        tos.append(formataddr((r.get("name",""), r["email"])))
    msg["To"] = ", ".join(tos)
    msg["Subject"] = f'{c["domain"]} – Sicherheitsvorfall auf Ihrem Webhosting bei netztaucher (bitte heute kurz lesen)'
    msg["Date"] = formatdate(localtime=True)
    msg["Message-Id"] = make_msgid(domain="netztaucher.com")

    # multipart/alternative: text + (related: html + bilder)
    msg.set_content("\n".join(plain))
    msg.add_alternative(html, subtype="html")
    html_part = msg.get_payload()[1]
    for key in ("forensik", "repair"):
        data = (ASSETS / f"{key}.png").read_bytes()
        html_part.add_related(data, "image", "png",
                              cid=cids[key], filename=f"{key}.png",
                              disposition="inline")
    return msg

def write_preview(c, path):
    """Eigenständige HTML-Vorschau (Banner als data:-URI) zum Ansehen."""
    import base64
    blocks, _ = build_bodies(c)
    cids = {"forensik": "<forensik>", "repair": "<repair>"}
    html = render_html(blocks, cids)
    for key in ("forensik", "repair"):
        b64 = base64.b64encode((ASSETS / f"{key}.png").read_bytes()).decode()
        html = html.replace(f"cid:{key}", f"data:image/png;base64,{b64}")
    pathlib.Path(path).write_text(html)

def from_findings(path):
    """Liest malware_summary aus findings.json (schema >=1.3) -> Mail-Felder."""
    d = json.loads(pathlib.Path(path).read_text())
    ms = d.get("malware_summary") or {}
    area = ms.get("affected_area", "")
    return {
        "domain": d.get("domain", ""),
        "affected_area": area,
        "finding_summary": ms.get("finding_summary", ""),
        "timeframe": ms.get("timeframe", ""),
        "has_shop": "Shop" in area,
    }

def main():
    if len(sys.argv) > 1:
        c = json.loads(pathlib.Path(sys.argv[1]).read_text())
    else:
        c = DEMO
    # Auto-Befüllung aus findings.json: nur Felder, die NICHT explizit gesetzt sind.
    if c.get("findings"):
        auto = from_findings(c["findings"])
        for k, v in auto.items():
            if k not in c or c.get(k) in (None, ""):
                c[k] = v
    msg = build_eml(c)
    out = c.get("out") or f'anschreiben_{c["domain"].replace(".", "_")}.eml'
    outp = (HERE / out) if not pathlib.Path(out).is_absolute() else pathlib.Path(out)
    outp.write_bytes(bytes(msg))
    prev = outp.with_suffix(".preview.html")
    write_preview(c, prev)
    print(f"geschrieben: {outp}  ({outp.stat().st_size} bytes)")
    print(f"vorschau:    {prev}")

if __name__ == "__main__":
    main()
