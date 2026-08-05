#!/usr/bin/env python3
# ============================================================
# NT-Forensik — build_report_html.py
# Baut das gebrandete Abschlussbericht-HTML (netztaucher-Vorlage) aus
# zwei HTML-Fragmenten (Teil 1/Teil 2) + Metadaten. Ausgabe → weasyprint → PDF.
#
# © 2026 netztaucher | digital — proprietär, kostenpflichtig.
# ============================================================
import argparse, base64, pathlib

NAVY = "#003a63"; ORANGE = "#ff8800"

CSS = f"""
@page {{ size:A4; margin:18mm 16mm 18mm 16mm;
  @bottom-left {{ content: element(fL); vertical-align:middle; }}
  @bottom-right {{ content: element(fR); vertical-align:middle; }} }}
@page cover {{ margin:0; @bottom-left{{content:none}} @bottom-right{{content:none}} }}
*{{box-sizing:border-box}}
body{{font-family:'Helvetica Neue',Arial,sans-serif;color:#1c2430;font-size:10.5pt;line-height:1.55;margin:0}}
p{{margin:0 0 10pt;orphans:2;widows:2}}
ul,ol{{margin:6pt 0 12pt;padding-left:18pt}} li{{margin-bottom:5pt}}
h1{{color:{NAVY};font-size:18pt;margin:0 0 8pt}}
h2{{color:{NAVY};font-size:13pt;margin:20pt 0 11pt;padding-bottom:4pt;border-bottom:2px solid {ORANGE}}}
h3{{color:{NAVY};font-size:11.5pt;margin:15pt 0 7pt}}
a{{color:{NAVY};text-decoration:none}}
table{{width:100%;border-collapse:collapse;margin:10pt 0 16pt;font-size:9.5pt}}
th,td{{border:1px solid #d4dae3;padding:6pt 8pt;text-align:left;vertical-align:top}}
th{{background:{NAVY};color:#fff;font-weight:600}} thead{{display:table-header-group}}
tr:nth-child(even) td{{background:#f6f8fb}}
blockquote{{border-left:3px solid {ORANGE};background:#fff8f0;margin:14pt 0;padding:9pt 14pt;color:#33404f}} blockquote p{{margin:0}}
code{{background:#eef2f7;padding:1px 4px;border-radius:3px;font-size:9pt}}
hr{{border:none;border-top:1px solid #d4dae3;margin:18pt 0}}
.fL{{position:running(fL);font-size:7.5pt;color:#8a95a3;white-space:nowrap}}
.fL img{{width:18px;vertical-align:middle;margin-right:7pt}}
.fR{{position:running(fR);font-size:7.5pt;color:{NAVY};font-weight:600;letter-spacing:.04em;white-space:nowrap}}
.coverpage{{page:cover;break-after:always;min-height:297mm;display:flex;flex-direction:column}}
.hero{{padding:34mm 20mm 22mm 22mm;background:{NAVY};color:#fff;position:relative}}
.hero .accent{{position:absolute;left:13mm;top:32mm;height:26mm;width:4px;background:{ORANGE}}}
.hero .eyebrow{{color:{ORANGE};font-weight:700;letter-spacing:.10em;text-transform:uppercase;font-size:9pt;margin-bottom:8pt}}
.hero .title{{font-size:30pt;font-weight:800;line-height:1.1;margin:0}}
.hero .uline{{width:110pt;height:4px;background:{ORANGE};margin:10pt 0 14pt}}
.hero .domain{{color:{ORANGE};font-size:13pt;font-weight:600}}
.hero .sub{{color:#c9d6e5;font-size:10.5pt;margin-top:3pt}}
.hero .meta{{margin-top:16pt;font-size:9pt;color:#dfe8f2}} .hero .meta span{{margin-right:20pt}} .hero .meta b{{color:#fff}}
.obar{{height:6px;background:{ORANGE}}}
.cbody{{flex:1;padding:20pt 16mm 0}} .intro{{max-width:150mm}}
.fragen{{border-left:3px solid {ORANGE};padding:4pt 14pt;margin:20pt 0;font-size:9.5pt;color:#33404f;line-height:1.7}} .fragen b{{color:{NAVY}}}
.coverfoot{{display:flex;align-items:center;gap:8pt;padding:6pt 16mm 11mm;border-top:1px solid #dfe4ea;font-size:7.5pt;color:#8a95a3;margin-top:10pt}}
.coverfoot img{{width:18px}} .coverfoot .c{{flex:1}} .coverfoot .v{{color:{NAVY};font-weight:600;letter-spacing:.04em}}
.partlabel{{background:{NAVY};color:#fff;font-weight:700;padding:7pt 12pt;font-size:11pt;margin:0 0 14pt;border-left:5px solid {ORANGE}}}
.part{{break-before:always}}
.kpigrid ul{{list-style:none;padding:0;margin:8pt 0 14pt;display:grid;grid-template-columns:repeat(4,1fr);gap:8pt}}
.kpigrid li{{background:#f6f8fb;border:1px solid #dbe3ec;border-top:3px solid {ORANGE};border-radius:5px;padding:9pt 10pt;font-size:8.6pt;color:#5a6675;margin:0}}
.kpigrid li strong{{display:block;color:{NAVY};font-size:17pt;line-height:1.1;margin-bottom:2pt}}
"""

def main():
    ap = argparse.ArgumentParser(description="Baut gebrandetes Abschlussbericht-HTML (netztaucher).")
    ap.add_argument("--out", required=True, help="Ausgabe-HTML")
    ap.add_argument("--logo", required=True, help="Pfad zu nt-logo.svg")
    ap.add_argument("--eyebrow", default="netztaucher | digital — Forensik")
    ap.add_argument("--title", required=True, help="Titel (\\n für Umbruch)")
    ap.add_argument("--domain", default="")
    ap.add_argument("--subtitle", default="")
    ap.add_argument("--meta", action="append", default=[], help="Label=Value (wiederholbar), im Deckblatt")
    ap.add_argument("--intro", default="", help="Intro-Absatz (optional, HTML/Text)")
    ap.add_argument("--kontakt-tel", default="03331 252520")
    ap.add_argument("--kontakt-mail", default="neuber@netztaucher.com")
    ap.add_argument("--teil1-label", default="Teil 1 — Kundenbericht")
    ap.add_argument("--teil1-html", required=True)
    ap.add_argument("--teil2-label", default="Teil 2 — Forensik-Protokoll")
    ap.add_argument("--teil2-html", default="")
    args = ap.parse_args()

    b64 = base64.b64encode(pathlib.Path(args.logo).read_bytes()).decode()
    IMG = f'<img src="data:image/svg+xml;base64,{b64}">'
    title = args.title.replace("\\n", "<br>")
    meta = "".join(f"<span>{m}</span>" for m in (
        f"<b>{p.split('=',1)[0]}:</b> {p.split('=',1)[1]}" for p in args.meta if "=" in p))
    t1 = pathlib.Path(args.teil1_html).read_text()
    t2 = pathlib.Path(args.teil2_html).read_text() if args.teil2_html else ""
    contact = f'{args.kontakt_mail}&nbsp;&nbsp;·&nbsp;&nbsp;{args.kontakt_tel}'
    intro = args.intro or "Dieser Bericht fasst die forensische Untersuchung des Sicherheitsvorfalls zusammen."

    teil2_block = (f'<div class="part"></div><div class="partlabel">{args.teil2_label}</div>{t2}') if t2 else ""

    html = f"""<!doctype html><html lang="de"><head><meta charset="utf-8"><style>{CSS}</style></head><body>
<div class="fL">{IMG}<span>{contact}</span></div>
<div class="fR">VERTRAULICH</div>
<div class="coverpage">
<div class="hero"><div class="accent"></div>
<div class="eyebrow">{args.eyebrow}</div>
<div class="title">{title}</div>
<div class="uline"></div>
<div class="domain">{args.domain}</div>
<div class="sub">{args.subtitle}</div>
<div class="meta">{meta}</div></div>
<div class="obar"></div>
<div class="cbody"><div class="intro"><p>{intro}</p>
<div class="fragen"><b>Bei Fragen:</b><br>{args.kontakt_tel}<br>{args.kontakt_mail}</div></div></div>
<div class="coverfoot">{IMG}<span class="c">{contact}</span><span class="v">VERTRAULICH</span></div>
</div>
<div class="partlabel">{args.teil1_label}</div>
{t1}
{teil2_block}
</body></html>"""
    pathlib.Path(args.out).write_text(html)
    print(f"HTML geschrieben: {args.out}")

if __name__ == "__main__":
    main()
