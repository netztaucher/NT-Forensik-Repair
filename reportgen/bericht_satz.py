# bericht_satz.py - Satz und Pruefung fuer Kundendokumente im Berichtslayout NT Dokumente (WeasyPrint)
#
# Test:     ja - werkzeuge/kundenpaket-pruefstand.sh (Fixture, drei PDFs, Seitenzahl, Fuss, Ueberlauf) · NT-Forensik-Repair#160
# Rueckweg: entfaellt - schreibt nur HTML, PDF und PNG in die angegebenen Ordner
#
# Das Berichtslayout (Komponente Bericht im Designsystem NT Dokumente) setzt im
# Fluss: Briefkopf und Adress-Cards auf Seite 1, danach nummerierte Abschnitte,
# die frei umbrechen, Anhang auf eigener Seite. Den Geschaeftsfuss mit
# "Seite x von y" setzt WeasyPrint selbst in den Seitenrand (laufendes Element,
# reportgen/bericht/bericht.css). Freigegeben von Marco am 23.11.2026, nachdem
# das fruehere Layout (Kopfband, Statuskarten, feste Seiten) als nicht seriös
# abgelehnt wurde.
#
# Geprueft wird das gesetzte Dokument: Geschaeftsfuss auf jeder Seite, nichts
# ragt ueber den rechten Satzspiegel (lange Hashes, Pfade), feste Seitenzahl wo
# verlangt (DSGVO, BSI: 2), Sprachregeln. Seitenbilder (pdftoppm) muss danach
# ein Mensch ansehen.

import html as _html
import pathlib
import re
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
BERICHT = HERE / "bericht"
LOGO = (BERICHT / "nt-logo.svg").read_text(encoding="utf-8").strip()

FIRMA = "die netztaucher GmbH"
ANSCHRIFT = ["Am Gutshof 36", "16278 Angermünde"]
FUSS = (("die netztaucher GmbH · Am Gutshof 36 · 16278 Angermünde",
         "Geschäftsführer Marco Neuber · AG Neuruppin HRB 10596"),
        ("Tel. +49 3331 252520 · team@netztaucher.com", "www.netztaucher.com"))

PX_MM = 96 / 25.4


class SatzFehler(Exception):
    """Ein Dokument laesst sich nicht setzen (z. B. WeasyPrint fehlt)."""


# ── Text ────────────────────────────────────────────────────────────────────
def t(s):
    """Text fuer das Dokument: maskiert HTML, **fett** und `mono` werden Auszeichnung, \\n Umbruch."""
    if s is None:
        return ""
    s = _html.escape(str(s), quote=False)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"`(.+?)`", lambda m: f'<span class="mono{" kurz" if len(m.group(1)) < 30 else ""}">{m.group(1)}</span>', s)
    return s.replace("\n", "<br>")


def sichtbarer_text(html):
    s = re.sub(r"<style.*?</style>", " ", html, flags=re.S)
    s = re.sub(r"<svg.*?</svg>", " ", s, flags=re.S)
    s = re.sub(r"<[^>]+>", " ", s)
    return _html.unescape(s)


# Sprachregeln der Kundendokumente: keine Gedankenstriche, kein ß, keine
# geraden Anfuehrungszeichen, keine Emoji.
_REGELN = [
    ("Gedankenstrich –", "–"), ("Gedankenstrich —", "—"), ("ß statt ss", "ß"),
    ('gerades Anführungszeichen "', '"'),
]


def regelverstoesse(html):
    text = sichtbarer_text(html)
    funde = [name for name, z in _REGELN if z in text]
    if re.search("[\U0001F300-\U0001FAFF☀-➿]", text):
        funde.append("Emoji")
    return funde


# ── Bausteine ───────────────────────────────────────────────────────────────
def zelle(x):
    """Tabellenzelle: Text oder {"art": ok|warn|info, "text": ..., "nach": ...}."""
    if isinstance(x, dict):
        art = x.get("art", "info")
        art = art if art in ("ok", "warn", "info") else "info"
        return f'<span class="st-{art}">{t(x.get("text", ""))}</span>{t(x.get("nach", ""))}'
    return t(x)


def tabelle(kopf, zeilen, kv=False, erste_fest=False):
    if not zeilen:
        return ""
    k = "" if kv or not kopf else "<thead><tr>" + "".join(f"<th>{t(h)}</th>" for h in kopf) + "</tr></thead>"
    z = []
    for r in zeilen:
        zellen = []
        for i, c in enumerate(r):
            cls = ' class="fest"' if i == 0 and erste_fest else ""
            zellen.append(f"<td{cls}>{zelle(c)}</td>")
        z.append("<tr>" + "".join(zellen) + "</tr>")
    return f'<table class="data{" kv" if kv else ""}">{k}<tbody>{"".join(z)}</tbody></table>'


def h2(nr, titel, anhang=False):
    return f'<h2{" class=\"anhang\"" if anhang else ""}><span class="nr">{t(nr)}</span>{t(titel)}</h2>'


def absaetze(liste):
    return "".join(f"<p>{t(p)}</p>" for p in (liste or []) if p)


def karte(text, label=None, art="key"):
    kopf = f"<strong>{t(label)}.</strong> " if label else ""
    return f'<div class="card {art}"><p>{kopf}{t(text)}</p></div>'


def angebot(label, text):
    return f'<div class="offer"><b class="label">{t(label)}</b><br>{t(text)}</div>'


def liste(punkte):
    return "<ul>" + "".join(f"<li>{t(p)}</li>" for p in punkte) + "</ul>"


def unterschrift(links, rechts):
    return f'<div class="sig"><div>{t(links)}</div><div>{t(rechts)}</div></div>'


def adresskarte(label, name, zeilen, nebenzeilen=(), roh=""):
    z = "".join(f"{t(x)}<br>" for x in zeilen if x)
    n = "".join(f'<span class="sub">{t(x)}</span><br>' for x in nebenzeilen if x)
    return f'<div class="addr-card"><div class="addr-label">{t(label)}</div><b>{t(name)}</b><br>{z}{n}{roh}</div>'


def adresskarten(links, rechts):
    return f'<div class="addr-cards">{links}{rechts}</div>'


def _fuss():
    (l1, l2), (m1, m2) = FUSS
    return ('<div class="fuss"><div class="claim">Digital einfach.</div><div class="linie"></div>'
            f'<table><tr><td class="links">{t(l1)}<br>{t(l2)}</td><td class="mitte">{t(m1)}<br>{t(m2)}</td>'
            '<td class="rechts">Vertraulich<br><span class="seite"></span></td></tr></table></div>')


def dokument(titel, untertitel, vermerk, inhalt, entwurf=False):
    """Ganzes HTML-Dokument im Berichtslayout: Briefkopf, Haarlinie, Vermerk, Inhalt, Geschaeftsfuss."""
    return ('<!doctype html><html lang="de"><head><meta charset="utf-8">'
            f'<title>{t(titel)}</title><link rel="stylesheet" href="bericht.css"></head><body>'
            + _fuss()
            + f'<div class="brand"><div class="nt-brand">{LOGO}<span class="brand-word">netztaucher <span>| digital</span></span></div>'
            f'<div class="doc-label"><div class="doc-type">{t(titel)}</div><div class="doc-sub">{t(untertitel)}</div></div></div>'
            f'<div class="hair"></div><div class="vermerk{" entwurf" if entwurf else ""}">{t(vermerk)}</div>'
            + inhalt + "</body></html>")


# ── WeasyPrint ──────────────────────────────────────────────────────────────
def _render(html):
    try:
        from weasyprint import HTML
    except ImportError as e:  # pragma: no cover - Umgebung
        raise SatzFehler("WeasyPrint ist in diesem Python nicht installiert "
                         "(reportgen/README.md, Abschnitt Voraussetzungen)") from e
    return HTML(string=html, base_url=str(BERICHT) + "/").render()


def _boxen(box):
    yield box
    for k in getattr(box, "children", None) or []:
        yield from _boxen(k)


def _klassen(el):
    return (el.get("class") or "").split() if el is not None else []


def pruefen(render):
    """Prueft jede Seite: Geschaeftsfuss vorhanden, nichts rechts ueber dem Satzspiegel."""
    fehler = []
    for nr, seite in enumerate(render.pages, 1):
        pb = seite._page_box
        rechts = pb.content_box_x() + pb.width + 0.5
        fuss = False
        weiteste = None
        for kind in pb.children:
            if type(kind).__name__ == "MarginBox":
                if any("fuss" in _klassen(getattr(b, "element", None)) for b in _boxen(kind)):
                    fuss = True
                continue
            for b in _boxen(kind):
                if type(b).__name__ not in ("LineBox", "TextBox", "BlockBox", "TableBox", "TableCellBox"):
                    continue
                ende = b.position_x + b.margin_width()
                if ende > rechts and (weiteste is None or ende > weiteste[0]):
                    weiteste = (ende, getattr(b, "text", "") or "")
        if not fuss:
            fehler.append(f"Seite {nr}: kein Geschaeftsfuss")
        if weiteste:
            fehler.append(f"Seite {nr}: Inhalt ragt {(weiteste[0] - rechts) / PX_MM:.1f} mm rechts ueber den Satzspiegel"
                          + (f" ({weiteste[1][:40]})" if weiteste[1] else ""))
    return fehler


def schreiben(name, html, pdf_pfad, soll_seiten=None, png_ordner=None, png_dpi=70):
    """Setzt das Dokument, prueft es, schreibt PDF (und PNG je Seite). Liefert Pruefbericht (dict)."""
    render = _render(html)
    fehler = pruefen(render)
    if soll_seiten and len(render.pages) != soll_seiten:
        fehler.append(f"{name}: {len(render.pages)} Seiten statt {soll_seiten} (kuerzen)")
    pdf_pfad = pathlib.Path(pdf_pfad)
    pdf_pfad.parent.mkdir(parents=True, exist_ok=True)
    render.write_pdf(str(pdf_pfad))
    bericht = {"dokument": name, "pdf": pdf_pfad.name, "seiten": len(render.pages),
               "fehler": fehler, "regelverstoesse": regelverstoesse(html), "bilder": []}
    if png_ordner:
        png_ordner = pathlib.Path(png_ordner)
        png_ordner.mkdir(parents=True, exist_ok=True)
        for alt in png_ordner.glob(pdf_pfad.stem + "-*.png"):
            alt.unlink()
        try:
            subprocess.run(["pdftoppm", "-r", str(png_dpi), "-png", str(pdf_pfad), str(png_ordner / pdf_pfad.stem)],
                           check=True, capture_output=True)
            bericht["bilder"] = sorted(p.name for p in png_ordner.glob(pdf_pfad.stem + "-*.png"))
        except (OSError, subprocess.CalledProcessError) as e:
            bericht["fehler"].append(f"Seitenbilder nicht erzeugt (pdftoppm): {e}")
    return bericht
