# Berichtslayout NT Dokumente — Kopie für reportgen

Quelle: Designsystem **NT Dokumente**, Artifact
`https://claude.ai/code/artifact/10558053-449f-4107-974f-93e35250aae5`, Datei
`project/components/Bericht/preview.html`, Fassung `1795345176-f8e0`, geholt am 23.11.2026.
Freigegeben von Marco am 23.11.2026 („passt“) am Kundenpaket zum Vorfall vom selben Tag.

| Hier | Herkunft |
|---|---|
| `bericht.css` | Stil aus `preview.html` (Farben, Schriftgrössen, Abstände, Klassen `brand`, `hair`, `addr-card`, `card key`, `offer`, `table.data`, `kv`, `note`) |
| `nt-logo.svg` | Logo (Taucher, navy) aus `preview.html` |
| `fonts/inter-latin-{300,400,600}-normal.woff2` | Inter 3.019 (SIL OFL 1.1), statische Schnitte aus der Variable-Font `Inter-VariableFont_slnt,wght.ttf` mit `fonttools varLib.instancer` (`wght`, `slnt=0`), Teilmenge Latin mit `pyftsubset --flavor=woff2` |
| `fonts/inter-tight-latin-700-normal.woff2` | Inter Tight 700 (SIL OFL 1.1), Fontsource, übernommen aus der früheren Kopie von NT Docs |
| `fonts/hack-regular.woff2` | Hack (MIT), ebenso |

Abweichungen von der Vorlage, alle für WeasyPrint:

- Schriften lokal per `@font-face` statt Google Fonts (die CI und der Arbeitsplatz setzen
  ohne Netz).
- Geschäftsfuss als laufendes Element (`position: running(fuss)`) im `@page`-Rand mit
  „Seite x von y“ statt des statischen Fusses am Seitenende; Inhalt wie im freigegebenen
  Kundenpaket (Anschrift, Handelsregister, Kontakt, „Vertraulich“, Claim).
- Seitenränder 14 mm, unten 27 mm für den Fuss.
- Abstände in Flex/Grid ohne `gap` (Adress-Cards über `grid-column-gap`).
- Zusätze: `.vermerk` (Vertraulichkeitsvermerk), `h2 .nr` (orange Ziffer), `.st-ok/-warn/-info`
  (Status in Tabellen), `.sig` (Unterschriftszeilen), `.box`, `.entwurf` (Entwurf-Kennzeichnung).

Geändert wird im Designsystem; danach `bericht.css` nachziehen, diese Tabelle und die
Prüfsummen anpassen und `werkzeuge/kundenpaket-pruefstand.sh` laufen lassen.

## Prüfsummen (SHA-256)

```
a1c76f81be23cce8fc44673f044eadd7318f38c786aedbeb197b6f695b5d1a63  bericht.css
463624a6d43278aa0418e527391f57ab64726ac87547cddc9da0c11e39aeee7b  nt-logo.svg
0b0ef254dfc7afc172528e3166eace813989e1cf77f576ddae5f5e8fb2897c06  fonts/hack-regular.woff2
a62eaefd5641ce79a4ccfb84da5fc17f0a0a14435884780736b359eb1b622084  fonts/inter-latin-300-normal.woff2
ee448f10fd75234bbf45c1ca6764dc2dc31d06746daea8e4b7f34d6759196e6e  fonts/inter-latin-400-normal.woff2
79a27bd7b05ca00fa7bf328930890adf71bc1ef024e53800737cd1566b3ab5a2  fonts/inter-latin-600-normal.woff2
9c4f02f38678f2628292d66c4f7a1a6a06af7ffac4d279359b09074e7d0f1fe0  fonts/inter-tight-latin-700-normal.woff2
```
