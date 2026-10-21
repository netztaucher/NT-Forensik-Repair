#!/usr/bin/env bash
# =============================================================================
# interna-waechter.sh — Kundendokumente gegen die Interna-Sperrliste prüfen
# =============================================================================
# Test:     ja - werkzeuge/interna_waechter_selbsttest.sh (CI) und kundenpaket-pruefstand.sh · NT-Forensik-Repair#150
# Rueckweg: entfällt - liest nur
#
#   werkzeuge/interna-waechter.sh <datei> [<datei> ...]
#
# Liest PDF (über pdftotext), HTML, E-Mail (.eml, alle Textteile) und Text und
# sucht jede Zeile gegen werkzeuge/interna-sperrliste.txt. Zusätzliche Muster
# (z. B. Namen anderer Kunden desselben Servers) über
#   NT_INTERNA_EXTRA=<datei>      gleiches Format wie die Sperrliste
#
# Warum: Im Vorfall vom 21.10.2026 standen im Kundenbericht Issue-Nummern,
# Werkzeugstände, Serverpfade der Quarantäne und Daten anderer Kunden. Sie
# mussten von Hand gesucht werden. Der Wächter sucht sie jetzt jedes Mal.
#
# Rückgabe: 0 = keine Interna, 1 = Treffer, 2 = Datei nicht lesbar oder
#           pdftotext fehlt (dann ist NICHTS geprüft — kein grünes Ergebnis).
# =============================================================================
set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LISTE="${NT_INTERNA_SPERRLISTE:-${SELF_DIR}/interna-sperrliste.txt}"

[[ $# -gt 0 ]] || { echo "Aufruf: $0 <datei> [<datei> ...]" >&2; exit 2; }
[[ -f "$LISTE" ]] || { echo "Sperrliste fehlt: $LISTE" >&2; exit 2; }

python3 - "$LISTE" "${NT_INTERNA_EXTRA:-}" "$@" <<'PY'
import email, email.policy, html, pathlib, re, shutil, subprocess, sys

liste, extra, dateien = sys.argv[1], sys.argv[2], sys.argv[3:]

def muster_lesen(pfad):
    m = []
    for z in pathlib.Path(pfad).read_text(encoding="utf-8").splitlines():
        if not z.strip() or z.lstrip().startswith("#"):
            continue
        rx, _, warum = z.partition("\t")
        m.append((re.compile(rx), warum.strip() or rx))
    return m

muster = muster_lesen(liste)
if extra:
    muster += muster_lesen(extra)

def text_aus(p):
    s = p.suffix.lower()
    if s == ".pdf":
        if not shutil.which("pdftotext"):
            raise RuntimeError("pdftotext fehlt (poppler-utils)")
        return subprocess.run(["pdftotext", "-enc", "UTF-8", str(p), "-"], check=True,
                              capture_output=True, text=True).stdout
    roh = p.read_bytes()
    if s == ".eml":
        msg = email.message_from_bytes(roh, policy=email.policy.default)
        teile = [msg.get("Subject", "")]
        for part in msg.walk():
            if part.get_content_maintype() == "text":
                teile.append(_ohne_tags(part.get_content()) if part.get_content_subtype() == "html" else part.get_content())
            fn = part.get_filename()
            if fn:
                teile.append(fn)
        return "\n".join(teile)
    t = roh.decode("utf-8", "replace")
    return _ohne_tags(t) if s in (".html", ".htm") else t

def _ohne_tags(t):
    t = re.sub(r"(?is)<(style|script).*?</\1>", " ", t)
    t = re.sub(r"(?i)<br\s*/?>|</(p|div|tr|li|h\d)>", "\n", t)
    return html.unescape(re.sub(r"<[^>]+>", " ", t))

treffer, fehler = 0, 0
for d in dateien:
    p = pathlib.Path(d)
    try:
        text = text_aus(p)
    except Exception as e:  # noqa: BLE001
        print(f"  ✗ {p.name}: nicht lesbar ({e})")
        fehler += 1
        continue
    eigen = 0
    for nr, zeile in enumerate(text.splitlines(), 1):
        for rx, warum in muster:
            m = rx.search(zeile)
            if m:
                print(f"  ✗ {p.name}:{nr}: „{m.group(0)}“ — {warum}")
                eigen += 1
    if eigen == 0:
        print(f"  ✓ {p.name}: keine Interna")
    treffer += eigen

if fehler:
    sys.exit(2)
sys.exit(1 if treffer else 0)
PY
