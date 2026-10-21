# NT Docs — Kopie für reportgen

Quelle: Designsystem **NT Docs**, Artifact `https://claude.ai/artifact/31zA5VudV5y25X8zxBRHPi`,
Fassung `1792574258-5595` (letzte Änderung 21.10.2026, 09:17 UTC: Rezepte Sicherheitsbericht,
DSGVO-Dokumentation, BSI-Einordnung, Interna-Regel, WeasyPrint-Fallen). Enthält die Korrekturen
aus Version 29/30 (Haarlinie der Kante, `.nt-doc .nt-gap`, `nt-state` als `inline-block`).
Geholt am 21.10.2026.

| Hier | Im Designsystem |
|---|---|
| `tokens.css` | `project/tokens.css` |
| `components/bundle.css` | `project/components/bundle.css` |
| `fonts/*.woff2` | `project/fonts/` (Inter 200, Inter Tight 700: SIL OFL 1.1; Hack: MIT) |
| `img/nt-logo.svg`, `img/nt-logo-rund.svg` | `assets/Logos/` |
| `img/status-*.svg`, `img/dot-*.svg`, `img/idea.svg`, `img/file.svg`, `img/shield.svg` | `assets/Icons/` |
| `img/kante.svg` | `assets/Formen/kante.svg` |

Regeln, Komponenten und Rezepte stehen im README des Designsystems (`project/README.md`), nicht
hier. Geändert wird dort; danach die Dateien neu holen, diese Tabelle und die Prüfsummen
unten nachziehen und `werkzeuge/kundenpaket-pruefstand.sh` laufen lassen.

## Prüfsummen (SHA-256)

```
5ae867cc9cd3ff030921b573b40f51962c3efa016da0368f3c24560a7414e10a  ./components/bundle.css
0b0ef254dfc7afc172528e3166eace813989e1cf77f576ddae5f5e8fb2897c06  ./fonts/hack-regular.woff2
a95c398b0d5b3d0521ac0a0436469bb0483603dde6c620e37e3005f7d967fbd0  ./fonts/inter-latin-200-normal.woff2
9c4f02f38678f2628292d66c4f7a1a6a06af7ffac4d279359b09074e7d0f1fe0  ./fonts/inter-tight-latin-700-normal.woff2
d4dbc5e252ff97a85ee41f78ed636c7a8284608f01a5ce977aca9ae42c9a430e  ./img/dot-ok.svg
20560b80d6fa97d06666472ec240e0aefa19c9bd6a4ee0f01e2af617d6ded404  ./img/dot-warn.svg
733408b86262fa7b856559216b9156e90f1a2c09cfc58466d2b7289a015fe866  ./img/file.svg
5826bbe806ae303302ee8e6400cc9e28c37e1c81714d1e403df6e36fbf37bf5f  ./img/idea.svg
5f5894e18b9ffbf54ebd94d9e4ab75aee83291eeea42d45c58ba3ffe791e19a7  ./img/kante.svg
663cf8d838251ae071fbb9339369c84a0e45d6d657bb445ca1b279619541f4b4  ./img/nt-logo-rund.svg
062276632fde7addb3af4eafc27cea488599cf368897732298b48805712c5b53  ./img/nt-logo.svg
30fcaa5af4cc91347a0136ef0dd9532d8134949a65242bcbe9152fb070d8ee1d  ./img/shield.svg
42a316e325b389a81104a2706e8100bffdd0ee814878240eff3e693f740bbfc7  ./img/status-info.svg
4f0949f14ed0666cec20ba7c99bc1e177cd02034f151b86654886fd7da0e9248  ./img/status-ok.svg
4e50151ab916bf592f646b4cbf9ba67cf1486445650e31a8e5d24471ab7dca89  ./img/status-warn.svg
e23eded240b14978f57430b4e2ea7acdc1ab68b8ab5a12a818cf348ab71bce70  ./tokens.css
```
