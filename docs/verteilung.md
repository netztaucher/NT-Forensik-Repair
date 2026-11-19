# Verteilung — wie das Werkzeug zum Kunden kommt (#126)

Kunden installieren mit `git clone` und aktualisieren mit `git pull --ff-only`.
Sie klonen **nicht** dieses Repo, sondern das öffentliche Verteil-Repo
[`netztaucher/NT-Forensik`](https://github.com/netztaucher/NT-Forensik). So kann
dieses Repo privat werden, ohne dass die Installation auf Kundenservern bricht
(Anlass: Privatstellung vom 2026-09-29 zurückgenommen, netztaucher/infra#690).

## Was hinausgeht

| Datei | Inhalt |
|---|---|
| [`verteilung/umfang.txt`](../verteilung/umfang.txt) | Einträge der obersten Ebene, die verteilt werden |
| [`verteilung/privat.txt`](../verteilung/privat.txt) | Einträge, die nie verteilt werden |

Jeder Eintrag der obersten Ebene steht in **genau einer** Liste, sonst bricht der
Bau ab. Ein neuer Ordner ist damit privat, bis ihn jemand ausdrücklich in
`umfang.txt` einträgt. Das ist Absicht: der Quelltext der Bereinigung darf nie
hinaus, ausgeliefert wird nur das verschlüsselte Paket unter `paket/`.

## Wie

| Schritt | Werkzeug |
|---|---|
| Stand bauen (`git archive` eines Refs, prüft die Listen) | [`werkzeuge/verteilung-bauen.sh`](../werkzeuge/verteilung-bauen.sh) `<ref> <ziel>` |
| Stand als einen Commit auf `main` des Verteil-Repos schreiben, optional Tag | [`werkzeuge/verteilung-schieben.sh`](../werkzeuge/verteilung-schieben.sh) `<stand> <url> [tag]` |
| beides in beide Richtungen prüfen, ohne Netz | [`werkzeuge/verteilung_selbsttest.sh`](../werkzeuge/verteilung_selbsttest.sh), in `pruefung.yml` |
| automatisch nach jeder grünen Prüfung auf `main` und bei Tags `v*` | [`.github/workflows/verteilung.yml`](../.github/workflows/verteilung.yml) |

Der Stand trägt eine Datei `VERTEILSTAND` mit Version und Quell-Commit. Im Support
lässt sich damit sagen, welcher Stand auf einem Server liegt.

Ins Verteil-Repo wird nur vorwärts geschrieben, nie mit `--force`, und ein
vorhandenes Tag wird nie verschoben. Sonst bräche `git pull --ff-only` beim Kunden.

## Zugang

Deploy-Key mit Schreibrecht, nur für `netztaucher/NT-Forensik`. Der private Teil
liegt ausschließlich als Actions-Secret `VERTEIL_DEPLOY_KEY` in diesem Repo, der
öffentliche als Deploy-Key „Verteilung aus NT-Forensik-Repair“ im Verteil-Repo.
Ein Tausch läuft nach dem Rotations-Ritual (Lex Clavis): neuen Key anlegen,
Secret setzen, Lauf von Hand starten, alten Deploy-Key löschen und prüfen, dass
er abgelehnt wird.

## Zurück

Ein falscher Stand ist ein normaler Commit im Verteil-Repo: dort `git revert`,
oder `verteilung.yml` von Hand auf einem älteren Ref starten.

> Im Verteil-Repo fehlen `verteilung/` und `.github/`: die Links auf die Listen und
> den Workflow führen dort ins Leere. Maßgeblich ist das Quell-Repo.
