# ntdocs_satz.py - Seitensatz fuer Dokumente im Designsystem NT Docs (WeasyPrint)
#
# Test:     ja - werkzeuge/kundenpaket-pruefstand.sh (Fixture, drei PDFs, Ueberlauf, Seitenzahl) · NT-Forensik-Repair#149
# Rueckweg: entfaellt - schreibt nur HTML, PDF und PNG in die angegebenen Ordner
#
# Warum es diese Datei gibt
# -------------------------
# NT Docs setzt jede Seite als feste A4-Seite (div.nt-page, 297 mm hoch,
# overflow hidden). Was nicht passt, schneidet WeasyPrint nicht sichtbar ab,
# sondern schiebt es auf zusaetzliche PDF-Seiten oder versteckt es. Im Vorfall
# vom 21.10.2026 wurden die Seiten darum von Hand umbrochen und jede Seite als
# Bild geprueft. Hier geschieht beides maschinell:
#
#   1. Messen: jeder Baustein wird einmal in Satzspiegelbreite gesetzt und
#      seine Hoehe gelesen (Tabellenzeilen und Listenpunkte einzeln).
#   2. Packen: die Bausteine werden auf Seiten verteilt. Tabellen und Listen
#      duerfen zwischen Zeilen umbrechen, der Tabellenkopf wird wiederholt.
#   3. Pruefen: das fertige PDF wird erneut gesetzt und je Seite geprueft:
#      gleiche Seitenzahl wie geplant, Inhalt mindestens 8 mm ueber der
#      Fusszeile, Titel einzeilig. Ueberlaeuft eine Seite trotzdem, wandert
#      ihr letzter Baustein auf die naechste Seite und es wird neu gesetzt.
#
# Nur Klassen aus reportgen/ntdocs/components/bundle.css. Keine Inline-Styles
# ausser @page.

import html as _html
import pathlib
import re
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
NTDOCS = HERE / "ntdocs"

PX_MM = 96 / 25.4            # WeasyPrint rechnet in CSS-Pixeln (96 dpi)
ABSTAND_FUSS_MM = 8          # Inhalt endet mindestens 8 mm ueber der Fusszeile
GAP_MM = {"": 0, "gap": 8, "gap-lg": 12}
SECTION_PAD_MM = 4           # .nt-section padding oben/unten

FUSS_LINKS = "die netztaucher GmbH · Am Gutshof 36 · 16278 Angermünde · netztaucher.com"

MARKE_BAND = ('<div class="nt-brand"><img src="img/nt-logo-rund.svg" alt="">'
              '<span class="nt-brand-word">netztaucher <span>| digital</span></span></div>')
MARKE_FOLGE = ('<div class="nt-brand"><img src="img/nt-logo.svg" alt="">'
               '<span class="nt-brand-word">netztaucher <span>| digital</span></span></div>')


class SatzFehler(Exception):
    """Ein Dokument laesst sich nicht regelgerecht setzen."""


# ── Text ────────────────────────────────────────────────────────────────────
def t(s):
    """Text fuer das Dokument: maskiert HTML, **fett** und `mono` werden Auszeichnung."""
    if s is None:
        return ""
    s = _html.escape(str(s), quote=False)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r'<span class="nt-mono">\1</span>', s)
    return s


def sichtbarer_text(html):
    s = re.sub(r"<style.*?</style>", " ", html, flags=re.S)
    s = re.sub(r"<[^>]+>", " ", s)
    return _html.unescape(s)


# Regeln aus NT Docs (Sprache und Register): keine Gedankenstriche, kein ss-Ersatz
# vergessen, keine geraden Anfuehrungszeichen, keine Emoji.
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
class Atom:
    """Unteilbarer Baustein (Absatz, Hinweis, Kacheln, Unterschrift ...)."""
    teilbar = False

    def __init__(self, html, gap="gap", mit_naechstem=False):
        self.html, self.gap, self.mit_naechstem = html, gap, mit_naechstem
        self.h = 0.0


class Zeilen:
    """Tabelle oder Liste, die zwischen Zeilen umbrechen darf.

    oeffnen/schliessen umgeben die Zeilen, kopf wird auf jeder Folgeseite
    wiederholt (bei Listen leer)."""
    teilbar = True

    def __init__(self, oeffnen, zeilen, schliessen, kopf="", gap="gap", davor=""):
        self.oeffnen, self.zeilen, self.schliessen = oeffnen, list(zeilen), schliessen
        self.kopf, self.gap, self.davor = kopf, gap, davor
        self.kopf_h, self.zeilen_h, self.davor_h, self.rahmen_h = 0.0, [], 0.0, 0.0
        self.mit_naechstem = False

    def html_teil(self, a, b, mit_davor=True):
        return ((self.davor if mit_davor else "") + self.oeffnen + self.kopf
                + "".join(self.zeilen[a:b]) + self.schliessen)


class Abschnitt:
    """NT-Docs-Abschnitt (.nt-section) mit Nummer, Titel und Inhalt.

    kinder: Atom oder Zeilen, gesetzt in der Breite von .nt-section-body."""
    teilbar = True

    def __init__(self, nummer, titel, kinder, gap="gap"):
        self.nummer, self.titel = nummer, titel
        self.kinder = [Atom(f'<h3 class="nt-h3">{t(titel)}</h3>', gap="", mit_naechstem=True)] + list(kinder)
        for k in self.kinder[1:]:
            k.gap = ""
        self.gap = gap
        self.mit_naechstem = False
        self.fortsetzung = False


class Kapitel:
    """Ein Teil des Dokuments, der auf einer neuen Seite beginnt."""

    def __init__(self, kicker, titel, bloecke, linie=False):
        self.kicker, self.titel, self.bloecke, self.linie = kicker, titel, list(bloecke), linie


# ── WeasyPrint ──────────────────────────────────────────────────────────────
def _weasy():
    try:
        from weasyprint import HTML  # noqa: F401
    except ImportError as e:  # pragma: no cover - Umgebung
        raise SatzFehler("WeasyPrint ist in diesem Python nicht installiert "
                         "(reportgen/README.md, Abschnitt Voraussetzungen)") from e
    from weasyprint import HTML
    return HTML


def _kopf(seite_css=""):
    return ('<!doctype html><html lang="de"><head><meta charset="utf-8">'
            '<link rel="stylesheet" href="tokens.css"><link rel="stylesheet" href="components/bundle.css">'
            f'<style>@page {{ size: A4; margin: 0 }}{seite_css}</style></head><body class="nt-doc">')


def _boxen(box):
    yield box
    for k in getattr(box, "children", None) or []:
        yield from _boxen(k)


def _klassen(el):
    return (el.get("class") or "").split() if el is not None else []


def _render(html):
    HTML = _weasy()
    return HTML(string=html, base_url=str(NTDOCS) + "/").render()


# ── Messen ──────────────────────────────────────────────────────────────────
def _mess_html(bloecke):
    """Ein langes Messdokument: jeder Baustein in Satzspiegelbreite."""
    teile = []
    for i, b in enumerate(bloecke):
        if isinstance(b, Atom):
            teile.append(f'<div class="nt-body" data-m="{i}">{b.html}</div>')
        elif isinstance(b, Zeilen):
            z = "".join(_markiere(r, f"{i}-{j}") for j, r in enumerate(b.zeilen))
            kopf = _markiere(b.kopf, f"{i}-k") if b.kopf else ""
            davor = f'<div data-d="{i}">{b.davor}</div>' if b.davor else ""
            teile.append(f'<div class="nt-body" data-m="{i}">{davor}{b.oeffnen}{kopf}{z}{b.schliessen}</div>')
        elif isinstance(b, Abschnitt):
            kin = []
            for j, k in enumerate(b.kinder):
                if isinstance(k, Atom):
                    kin.append(f'<div data-c="{i}-{j}">{k.html}</div>')
                else:
                    z = "".join(_markiere(r, f"{i}-{j}-{n}") for n, r in enumerate(k.zeilen))
                    kopf = _markiere(k.kopf, f"{i}-{j}-k") if k.kopf else ""
                    davor = f'<div data-d="{i}-{j}">{k.davor}</div>' if k.davor else ""
                    kin.append(f'<div data-c="{i}-{j}">{davor}{k.oeffnen}{kopf}{z}{k.schliessen}</div>')
            teile.append(f'<div class="nt-body" data-m="{i}"><div class="nt-section is-first">'
                         f'<div class="nt-section-no">{t(b.nummer)}</div><div class="nt-section-body">'
                         + "".join(kin) + '</div></div></div>')
    css = " .nt-body { break-before: page; }"
    return _kopf("@page { size: 210mm 4000mm; margin: 0 }" + css) + "".join(teile) + "</body></html>"


def _markiere(zeile, marke):
    """Setzt data-z an das erste Element einer Zeile (<tr ...> oder <li ...>)."""
    return re.sub(r"^(\s*<(tr|li|div)\b)", rf'\1 data-z="{marke}"', zeile, count=1)


def messen(bloecke):
    doc = _render(_mess_html(bloecke))
    hoehe = {}
    for seite in doc.pages:
        for b in _boxen(seite._page_box):
            el = getattr(b, "element", None)
            if el is None:
                continue
            for attr in ("data-m", "data-z", "data-c", "data-d"):
                v = el.get(attr)
                if v is not None and (attr, v) not in hoehe:
                    hoehe[(attr, v)] = b.margin_height()
    mm = lambda px: px / PX_MM  # noqa: E731
    for i, b in enumerate(bloecke):
        if isinstance(b, Atom):
            b.h = mm(hoehe.get(("data-m", str(i)), 0))
        elif isinstance(b, Zeilen):
            _zeilen_hoehen(b, str(i), hoehe, mm)
        elif isinstance(b, Abschnitt):
            for j, k in enumerate(b.kinder):
                if isinstance(k, Atom):
                    k.h = mm(hoehe.get(("data-c", f"{i}-{j}"), 0))
                else:
                    _zeilen_hoehen(k, f"{i}-{j}", hoehe, mm, gesamt=("data-c", f"{i}-{j}"))
    return bloecke


def _zeilen_hoehen(b, key, hoehe, mm, gesamt=None):
    b.kopf_h = mm(hoehe.get(("data-z", f"{key}-k"), 0))
    b.zeilen_h = [mm(hoehe.get(("data-z", f"{key}-{j}"), 0)) for j in range(len(b.zeilen))]
    b.davor_h = mm(hoehe.get(("data-d", key), 0))
    ganz = mm(hoehe.get(gesamt or ("data-m", key), 0))
    # Rahmen: was die Huelle selbst an Hoehe hat (Abstaende der Liste/Tabelle)
    b.rahmen_h = max(0.0, ganz - b.davor_h - b.kopf_h - sum(b.zeilen_h))


# ── Packen ──────────────────────────────────────────────────────────────────
MIN_ZEILEN = 2  # nie eine einzelne Zeile allein am Seitenende oder -anfang


def _min_hoehe(b):
    if isinstance(b, Atom):
        return b.h
    if isinstance(b, Zeilen):
        return b.davor_h + b.rahmen_h + b.kopf_h + sum(b.zeilen_h[:MIN_ZEILEN])
    if isinstance(b, Abschnitt):
        h = 2 * SECTION_PAD_MM + _min_hoehe(b.kinder[0])
        if len(b.kinder) > 1 and getattr(b.kinder[0], "mit_naechstem", False):
            h += _min_hoehe(b.kinder[1])
        return h
    return 0


def packen(kapitel, kap_hoehe, folge_hoehe, abzug=None):
    """Verteilt die Bausteine der Kapitel auf Seiten.

    kap_hoehe: nutzbare Hoehe (mm) auf der ersten Seite eines Kapitels,
    folge_hoehe: auf Folgeseiten. abzug: {seiten_index: mm} kuerzt einzelne
    Seiten, auf denen der Pruefer einen Ueberlauf gemessen hat (Tabellen mit
    automatischer Spaltenbreite setzen Teilstuecke etwas anders als im Ganzen).
    Ergebnis: Liste von Seiten, jede (kapitel, ist_erste, [teil, ...])."""
    abzug = abzug or {}
    seiten = []
    for kap in kapitel:
        offen = list(kap.bloecke)
        erste = True
        while offen or erste:
            frei = (kap_hoehe if erste else folge_hoehe) - abzug.get(len(seiten), 0)
            teile = []
            while offen:
                b = offen[0]
                vorher = teile[-1] if teile else None
                teil, rest, h = _nimm(b, frei, vorher)
                if teil is None:
                    if not teile:  # passt nicht einmal auf eine leere Seite
                        teil, rest, h = _nimm(b, 10 ** 6, None)
                    else:
                        break
                # Zusammenhalt: Ueberschrift-Baustein nicht allein am Seitenende
                if rest is None and getattr(b, "mit_naechstem", False) and len(offen) > 1:
                    nach = offen[1]
                    if h + GAP_MM.get(nach.gap, 0) + _min_hoehe(nach) > frei and teile:
                        break
                teile.append(teil)
                frei -= h
                if rest is None:
                    offen.pop(0)
                else:
                    offen[0] = rest
                    break
            seiten.append((kap, erste, teile))
            erste = False
            if not offen:
                break
    return seiten


class _Teil:
    def __init__(self, art, html, block):
        self.art, self.html, self.block = art, html, block


def _gap(b, vorher):
    if vorher is None:
        return 0.0
    if isinstance(b, Abschnitt) and vorher.art == "abschnitt":
        return 0.0
    return GAP_MM.get(b.gap, 0)


def _nimm(b, frei, vorher):
    g = _gap(b, vorher)
    if isinstance(b, Atom):
        if g + b.h <= frei:
            return _Teil("atom", _mit_gap(b.html, b.gap if vorher else ""), b), None, g + b.h
        return None, None, 0
    if isinstance(b, Zeilen):
        n, h = _zeilen_passend(b, frei - g, True)
        if n == 0:
            return None, None, 0
        html = b.html_teil(0, n)
        rest = None
        if n < len(b.zeilen):
            rest = Zeilen(b.oeffnen, b.zeilen[n:], b.schliessen, b.kopf, gap="", davor="")
            rest.kopf_h, rest.zeilen_h, rest.rahmen_h = b.kopf_h, b.zeilen_h[n:], b.rahmen_h
        return _Teil("atom", _mit_gap_html(html, b.gap if vorher else ""), b), rest, g + h
    if isinstance(b, Abschnitt):
        return _nimm_abschnitt(b, frei, vorher, g)
    raise TypeError(b)


def _zeilen_passend(b, frei, mit_davor):
    basis = (b.davor_h if mit_davor else 0) + b.rahmen_h + b.kopf_h
    h, n = basis, 0
    for zh in b.zeilen_h:
        if h + zh > frei:
            break
        h += zh
        n += 1
    rest = len(b.zeilen) - n
    if 0 < rest < MIN_ZEILEN and n > MIN_ZEILEN:   # keine Einzelzeile auf der Folgeseite
        n -= MIN_ZEILEN - rest
        h = basis + sum(b.zeilen_h[:n])
    if n < min(MIN_ZEILEN, len(b.zeilen)):
        return 0, 0
    return n, h


def _nimm_abschnitt(b, frei, vorher, g):
    folgt_abschnitt = vorher is not None and vorher.art == "abschnitt"
    oben = SECTION_PAD_MM if folgt_abschnitt else 0
    platz = frei - g - oben - SECTION_PAD_MM
    stuecke, h, rest_kinder = [], 0.0, None
    kinder = list(b.kinder)
    i = 0
    while i < len(kinder):
        k = kinder[i]
        if isinstance(k, Atom):
            if h + k.h > platz:
                break
            if k.mit_naechstem and i + 1 < len(kinder) and h + k.h + _min_hoehe(kinder[i + 1]) > platz:
                break
            stuecke.append(k.html)
            h += k.h
            i += 1
            continue
        n, kh = _zeilen_passend(k, platz - h, True)
        if n == 0:
            break
        stuecke.append(k.html_teil(0, n))
        h += kh
        if n < len(k.zeilen):
            r = Zeilen(k.oeffnen, k.zeilen[n:], k.schliessen, k.kopf, gap="")
            r.kopf_h, r.zeilen_h, r.rahmen_h = k.kopf_h, k.zeilen_h[n:], k.rahmen_h
            kinder[i] = r
            break
        i += 1
    if not stuecke:
        return None, None, 0
    if i < len(kinder):
        rest_kinder = kinder[i:]
    klasse = "nt-section" + ("" if folgt_abschnitt else " is-first")
    if vorher is not None and not folgt_abschnitt and b.gap:
        klasse += " nt-" + b.gap
    nummer = "" if b.fortsetzung else t(b.nummer)
    html = (f'<div class="{klasse}"><div class="nt-section-no">{nummer}</div>'
            f'<div class="nt-section-body">{"".join(stuecke)}</div></div>')
    rest = None
    if rest_kinder:
        rest = Abschnitt.__new__(Abschnitt)
        rest.nummer, rest.titel, rest.kinder, rest.gap = b.nummer, b.titel, rest_kinder, ""
        rest.mit_naechstem, rest.fortsetzung = False, True
    return _Teil("abschnitt", html, b), rest, g + oben + h + SECTION_PAD_MM


def _mit_gap(html, gap):
    return _mit_gap_html(html, gap)


def _mit_gap_html(html, gap):
    """Haengt nt-gap/nt-gap-lg an das erste Element des Bausteins."""
    if not gap:
        return html
    m = re.match(r'(\s*<[a-z0-9]+)([^>]*?)( class="([^"]*)")?([^>]*>)', html)
    if not m:
        return f'<div class="nt-{gap}">{html}</div>'
    if m.group(3):
        neu = f'{m.group(1)}{m.group(2)} class="{m.group(4)} nt-{gap}"{m.group(5)}'
    else:
        neu = f'{m.group(1)}{m.group(2)} class="nt-{gap}"{m.group(5)}'
    return neu + html[m.end():]


# ── Dokument ────────────────────────────────────────────────────────────────
class Dokument:
    """Ein NT-Docs-Dokument: Seite 1 fest, danach Kapitel, die frei umbrechen."""

    def __init__(self, name, runhead, seite1_html, kapitel, soll_seiten=None):
        self.name = name                # z. B. "Sicherheitsbericht" (Fusszeile)
        self.runhead = runhead          # Folgekopf rechts, z. B. "Sicherheitsbericht · Berger · 21.10.2026"
        self.seite1_html = seite1_html  # Inhalt der ersten Seite (Kopfband + nt-body)
        self.kapitel = kapitel
        self.soll_seiten = soll_seiten  # feste Seitenzahl (DSGVO, BSI: 2) oder None
        self.seiten = []

    def _seite(self, i, n, inhalt, erste_seite):
        kopf = ""
        if not erste_seite:
            kopf = (f'<div class="nt-runhead">{MARKE_FOLGE}'
                    f'<div class="nt-runhead-meta">{t(self.runhead)}</div></div>')
        fuss = (f'<footer class="nt-foot"><span>{FUSS_LINKS}</span>'
                f'<span>{t(self.name)} · Seite {i} von {n}</span></footer>')
        return f'<div class="nt-page" data-seite="{i}">{kopf}{inhalt}{fuss}</div>'

    @staticmethod
    def _pagehead(kap):
        cls = "nt-pagehead is-linie" if kap.linie else "nt-pagehead"
        return f'<div class="{cls}"><p class="nt-kicker">{t(kap.kicker)}</p><h1 class="nt-title">{t(kap.titel)}</h1></div>'

    def html(self):
        seiten = [self.seite1_html]
        for kap, erste, teile in self.seiten:
            inhalt = "".join(x.html for x in teile)
            if erste:
                seiten.append(f'{self._pagehead(kap)}<div class="nt-body">{inhalt}</div>')
            else:
                seiten.append(f'<div class="nt-body nt-gap">{inhalt}</div>')
        n = len(seiten)
        return (_kopf() + "\n".join(self._seite(i, n, s, i == 1) for i, s in enumerate(seiten, 1))
                + "</body></html>")


def _nutzhoehe():
    """Nutzbare Hoehe (mm) der Folgeseiten mit und ohne Seitentitel, gemessen."""
    probe = Kapitel("Kicker", "Titel", [])
    html = (_kopf()
            + f'<div class="nt-page"><div class="nt-runhead">{MARKE_FOLGE}<div class="nt-runhead-meta">x</div></div>'
            + Dokument._pagehead(probe) + '<div class="nt-body"><div data-p="a"></div></div>'
            + f'<footer class="nt-foot"><span>{FUSS_LINKS}</span><span>x</span></footer></div>'
            + f'<div class="nt-page"><div class="nt-runhead">{MARKE_FOLGE}<div class="nt-runhead-meta">x</div></div>'
            + '<div class="nt-body nt-gap"><div data-p="b"></div></div>'
            + f'<footer class="nt-foot"><span>{FUSS_LINKS}</span><span>x</span></footer></div></body></html>')
    doc = _render(html)
    oben, fuss = {}, []
    for seite in doc.pages:
        for b in _boxen(seite._page_box):
            el = getattr(b, "element", None)
            if el is None:
                continue
            if el.get("data-p"):
                oben[el.get("data-p")] = b.position_y
            if "nt-foot" in _klassen(el) and b.position_y > 0:
                fuss.append(b.position_y)
    grenze = min(fuss) - ABSTAND_FUSS_MM * PX_MM
    return (grenze - oben["a"]) / PX_MM, (grenze - oben["b"]) / PX_MM


# ── Pruefen ─────────────────────────────────────────────────────────────────
def pruefen(doc_html):
    """Setzt das Dokument und prueft jede Seite. Liefert (fehler, ueberlauf_seiten, pdf_seiten, render)."""
    doc = _render(doc_html)
    soll = doc_html.count('class="nt-page"')
    fehler, ueber = [], {}
    if len(doc.pages) != soll:
        fehler.append(f"PDF hat {len(doc.pages)} Seiten, geplant waren {soll} (Inhalt laeuft ueber)")
    for nr, seite in enumerate(doc.pages, 1):
        fuss_y, unten = None, 0.0
        for b in _boxen(seite._page_box):
            el = getattr(b, "element", None)
            k = _klassen(el)
            if "nt-foot" in k:
                fuss_y = b.position_y
            if "nt-display" in k or "nt-title" in k:
                zeilen = [c for c in (b.children or []) if type(c).__name__ == "LineBox"]
                if len(zeilen) > 1:
                    fehler.append(f"Seite {nr}: Titel bricht um ({''.join(el.itertext()).strip()[:60]})")
        for b in _boxen_im_body(seite._page_box, False):
            if type(b).__name__ in ("LineBox", "TextBox", "InlineBox"):
                continue
            unten = max(unten, b.position_y + b.margin_height() - b.margin_bottom)
        if fuss_y is None:
            fehler.append(f"Seite {nr}: keine Fusszeile (Seite laeuft ueber)")
            ueber[nr] = 20.0
        elif unten > fuss_y - ABSTAND_FUSS_MM * PX_MM + 0.5:
            fehler.append(f"Seite {nr}: Inhalt endet {(fuss_y - unten) / PX_MM:.1f} mm ueber der Fusszeile (mindestens {ABSTAND_FUSS_MM} mm)")
            ueber[nr] = (unten - (fuss_y - ABSTAND_FUSS_MM * PX_MM)) / PX_MM
    return fehler, ueber, len(doc.pages), doc


def _boxen_im_body(box, drin):
    """Alle Boxen unterhalb eines .nt-body (Seitenkopf und Fusszeile zaehlen nicht)."""
    if "nt-body" in _klassen(getattr(box, "element", None)) and type(box).__name__ == "BlockBox":
        drin = True
    if drin:
        yield box
    for k in getattr(box, "children", None) or []:
        yield from _boxen_im_body(k, drin)


def setzen(dok, versuche=8):
    """Packt, prueft und packt nach, bis jede Seite passt. Liefert (html, render)."""
    alle = [b for kap in dok.kapitel for b in kap.bloecke]
    messen(alle)
    kap_h, folge_h = _nutzhoehe()
    abzug = {}
    for _ in range(versuche):
        dok.seiten = packen(dok.kapitel, kap_h, folge_h, abzug)
        html = dok.html()
        fehler, ueber, _, render = pruefen(html)
        # Seite 1 ist fest gesetzt: Ueberlauf dort laesst sich nicht verschieben.
        if not ueber or 1 in ueber:
            return html, render, fehler
        for nr, fehlt in ueber.items():
            idx = nr - 2  # Seite 1 ist die feste Kopfband-Seite
            abzug[idx] = abzug.get(idx, 0) + fehlt + 1.0
    return html, render, fehler


def schreiben(dok, pdf_pfad, png_ordner=None, png_dpi=60):
    """Setzt das Dokument, schreibt PDF (und PNG je Seite). Liefert Pruefbericht (dict)."""
    html, render, fehler = setzen(dok)
    verstoesse = regelverstoesse(html)
    if dok.soll_seiten and len(render.pages) != dok.soll_seiten:
        fehler.append(f"{dok.name}: {len(render.pages)} Seiten statt {dok.soll_seiten} (kuerzen)")
    pdf_pfad = pathlib.Path(pdf_pfad)
    pdf_pfad.parent.mkdir(parents=True, exist_ok=True)
    render.write_pdf(str(pdf_pfad))
    bericht = {"dokument": dok.name, "pdf": pdf_pfad.name, "seiten": len(render.pages),
               "fehler": fehler, "regelverstoesse": verstoesse, "bilder": []}
    if png_ordner:
        png_ordner = pathlib.Path(png_ordner)
        png_ordner.mkdir(parents=True, exist_ok=True)
        stamm = png_ordner / pdf_pfad.stem
        try:
            subprocess.run(["pdftoppm", "-r", str(png_dpi), "-png", str(pdf_pfad), str(stamm)],
                           check=True, capture_output=True)
            bericht["bilder"] = sorted(p.name for p in png_ordner.glob(pdf_pfad.stem + "-*.png"))
        except (OSError, subprocess.CalledProcessError) as e:
            bericht["fehler"].append(f"Seitenbilder nicht erzeugt (pdftoppm): {e}")
    return bericht, html
