# Schutzmodell — wie die Lizenzbindung technisch funktioniert

> Dieses Dokument beschreibt die **Technik**. Umfang, Bedingungen und Bezug der Lizenz
> stehen in [`lizenz.md`](lizenz.md).
>
> Es steht öffentlich, weil ein Sicherheitswerkzeug seine eigenen Grenzen benennen können
> muss. Wer wissen will, ob er den Aussagen dieses Werkzeugs trauen kann, findet hier die
> Antwort auf die härteste Frage zuerst.

## Was geschützt ist und was nicht

Dieses Repo enthält zwei Werkzeuge mit unterschiedlichem Status:

| | Lizenz | Netz nötig | Sichtbar |
|---|---|---|---|
| `wp_plesk_forensik.sh` — **Analyse** | keine | nein | vollständig, quelloffen |
| `nt_repair.sh` — **Bereinigung** | erforderlich | ja (mit Nachfrist) | Lader offen, Inhalt verschlüsselt |

Die Analyse bleibt frei. Das ist keine Werbeaussage, sondern der Punkt: wer ein
Werkzeug einsetzt, das als `root` auf seinem Server liest, soll nachlesen können,
was es tut. Und im Vorfall ist die Analyse der dringende Teil — sie muss auch dann
laufen, wenn kein Netz da ist und niemand einen Lizenzschlüssel zur Hand hat.

## Was Verschlüsselung hier leistet — und was nicht

**Nicht leistbar:** Schutz gegen den Ausführenden. Wer das entschlüsselte Skript
ausführt, hat es im selben Moment im Zugriff. Das gilt für jede interpretierte
Sprache; eine Doku, die etwas anderes behauptet, ist eine Falle für den, der ihr
glaubt.

**Leistbar — und das ist hier der Fall:** NT-Repair läuft nicht beim Kunden,
sondern vom Arbeitsplatz des Dienstleisters per SSH. Wer geschützt werden soll,
ist nicht der Anwender, sondern der Inhalt gegen jemanden, der das öffentliche
Repo klont. Dagegen wirkt Verschlüsselung vollständig: ohne Schlüssel ist
`paket/repair-*.enc` nicht lesbar und nicht ausführbar.

Dazu kommt die rechtliche Seite: eine wirksame technische Schutzmaßnahme zu
umgehen ist nach § 95a UrhG eigenständig rechtswidrig — unabhängig davon, wie
schwer die Umgehung technisch ist.

## Warum der Lader kein Geheimnis enthält

Naheliegend wäre, die Serverantwort per HMAC zu prüfen wie im WordPress-Plugin.
Das geht hier nicht: das Plugin liegt beim Kunden, sein Secret steht in dessen
`wp-config.php`. Der Lader liegt im **öffentlichen** Repo — ein Secret darin wäre
kein Secret.

Deshalb ist der Beweis nicht die Signatur, sondern die Entschlüsselung selbst.
Der Lader verankert `PAKET_SHA256`, die Prüfsumme des entschlüsselten Archivs.
Ein falscher oder erfundener Schlüssel erzeugt Datenmüll, und Datenmüll trifft
diese Prüfsumme nicht — der Lauf bricht ab, bevor irgendetwas ausgeführt wird.
Eine Prüfung, die nur `valid: true` auswertet, ließe sich aus dem offenen Lader
herauspatchen. Einen Schlüssel, den man nicht hat, nicht.

## Bindung an den Arbeitsplatz

Der Lizenzserver kennt ein Feld `domain`. NT-Repair hat keine Domain — es läuft
vom eigenen Rechner aus auf fremden Servern. An dessen Stelle tritt eine
Rechner-Kennung: Hardware-UUID (macOS `ioreg`, Linux `/etc/machine-id`) plus
Hostname, SHA-256, die ersten 32 Zeichen.

Neuen Arbeitsplatz freischalten:

```bash
bash nt_repair.sh --from /pfad/zum/lauf
```

Ohne hinterlegten Schlüssel gibt der Lader die Rechner-Kennung aus. Diese im
Admin-Panel des Lizenzservers als Domain-Lock eintragen, Produkt `nt-repair`,
und den erzeugten Schlüssel hinterlegen:

```bash
mkdir -p ~/.nt-repair && chmod 700 ~/.nt-repair
printf 'NT-XXXX-XXXX-XXXX\n' > ~/.nt-repair/lizenz.key
chmod 600 ~/.nt-repair/lizenz.key
```

## Wenn der Lizenzserver ausfällt

Der Lader fragt **immer zuerst den Server**. Eine gesperrte Lizenz wirkt damit
sofort, sobald der Rechner am Netz ist. Nur wenn der Server nicht erreichbar ist,
greift die Ausfallreserve unter `~/.nt-repair/lizenz.cache` — bis zu sieben Tage
(`NT_REPAIR_NACHFRIST_TAGE`).

Der Schlüssel liegt dort verschlüsselt, und zwar mit der Rechner-Kennung.
Auf einen anderen Rechner kopiert ist die Datei wertlos.

Danach: kein Repair. Die Analyse läuft weiter — Bereinigen kann warten, bis
wieder Netz da ist, Analysieren nicht.

## Eine Fassung ausliefern (nur Betreiber)

Die vier geschützten Dateien liegen im **privaten** Repo `NT-Repair`. Dort:

```bash
bash werkzeuge/paket-bauen.sh 0.4.0
```

Das Werkzeug erzeugt einen Schlüssel je Fassung, verschlüsselt, öffnet das Paket
zur Gegenprobe wieder und liefert drei zusammengehörige Dinge:

1. **den Bundle-Schlüssel** → in `dist/schluessel-<fassung>.txt`, Rechte `0600`,
   von `.gitignore` ausgeschlossen. Die Zeile daraus in die `config.php` des
   Lizenzservers unter `release_keys['nt-repair']`, dann die Datei löschen:

   ```bash
   pbcopy < dist/schluessel-0.4.0.txt
   rm -P dist/schluessel-0.4.0.txt
   ```

   Der Schlüssel wird **nicht** auf dem Bildschirm ausgegeben. Dort landet er
   sonst im Scrollback, im Terminal-Protokoll oder im Mitschnitt einer Sitzung —
   und ein Schlüssel, der irgendwo mitgeschrieben wurde, ist verbrannt, auch ohne
   böse Absicht.
2. **`PAKET_SHA256`** → in `nt_repair.sh` dieses Repos.
3. **`dist/repair-<fassung>.enc`** → nach `paket/` dieses Repos, einchecken.

Alle drei gehören zusammen. Wird nur eines davon getauscht, bricht der Lader ab —
sichtbar und mit Begründung, nicht still.

Ein Schlüssel je Fassung heißt: leakt einer, rotiert ihn die nächste Fassung weg,
ohne dass ein Kunden-Lizenzschlüssel getauscht werden muss.

## Wo nichts landet

Beim Lauf entsteht **keine** entschlüsselte Datei. Der Kern geht über `eval` in
die Shell, die Hilfsskripte über `/dev/fd` als FIFO in `bash`. Es gibt daher auch
nichts aufzuräumen, was bei `kill -9` liegenbleiben könnte.

Der Bundle-Schlüssel wird `openssl` über einen Dateideskriptor gereicht, nicht
über die Kommandozeile — sonst stünde er in der Prozessliste. Und nicht über
einen Here-String: den legt bash als reguläre Datei an, womit der Schlüssel kurz
auf der Platte läge. Gemessen mit `stat` auf `/dev/fd/3` — „Regular File" beim
Here-String, „Fifo File" bei Prozess-Substitution.
