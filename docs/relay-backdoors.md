# Relay-Backdoors & Prozess-Introspektion

Ergänzung zu [`erkennung.md`](erkennung.md). Beschreibt die in **v3.4** ergänzten
Prüfungen gegen eine Backdoor-Klasse, die von den Abschnitten 1–13 systematisch
übersehen wurde.

---

## Anlass

Auf einem betreuten System lag eine Datei namens `~/.ssh/id_rsa`. Sie war kein
Schlüssel, sondern eine 2,8 MB große, statisch gelinkte und gestrippte
ELF-Binary: **gs-netcat** aus dem gsocket-Toolkit (THC, `gs.thc.org`).

Der Tarnname ist gut gewählt: Eine Datei mit diesem Namen an diesem Ort prüft
niemand auf ihren Dateityp.

## Warum NT-Forensik v3.3 das nicht gefunden hätte

| Prüfung in v3.3 | Warum sie nicht greift |
|---|---|
| 8.1 Offene Ports | gsocket öffnet **keinen** Port. Beide Seiten verbinden sich ausgehend. |
| 8.2b Gelöschte Binaries | Die Datei liegt auf der Platte, sie ist nicht gelöscht. |
| 8.2c Prozesse aus tmp/Webspace | `~/.ssh/` steht nicht auf der Pfadliste. |
| 8.2d Reverse-Shell-Muster | Die Kommandozeile enthält keines der Muster. |
| 7.3 Webshell-Signaturen | Nur `--include="*.php"` — eine ELF-Binary wird nie gelesen. |
| 5.4 authorized_keys | Prüft Schlüsselinhalte, nicht den Dateityp der Nachbardateien. |

## Warum rkhunter und chkrootkit das nicht finden

Beide sind signatur- und baseline-basierte **Rootkit**-Scanner. gsocket fällt
durch jedes ihrer vier Raster:

1. **Rootkit-Signaturdatenbank** — gsocket ist kein Rootkit und steht in keiner
   dieser Listen.
2. **Trojanisierte System-Binaries** — gsocket ersetzt kein `ls`, `ps` oder
   `netstat`; es läuft als eigener Prozess daneben. (Die Baseline ist ohnehin
   nur etwas wert, wenn sie *vor* der Kompromittierung erstellt wurde.)
3. **Backdoor-Ports und Listening-Sockets** — der entscheidende Punkt: es gibt
   keinen lauschenden Port. Aus Netzwerksicht ist der Kanal eine gewöhnliche
   ausgehende HTTPS-Verbindung.
4. **LKM / `ld.so.preload` / versteckte PIDs** — reiner Userland-Code, kein
   Kernelmodul, kein Preload. Ein Prozess, der sich per `argv[0]` umbenennt,
   ist nicht *versteckt*, er lügt nur über seinen Namen — das ist kein
   Signatur-Mismatch, den diese Werkzeuge kennen.

Kurz: Ein „living off the land"-Backdoor ist für Signatur-Rootkithunter die
falsche Werkzeugklasse. Was hilft, sind YARA (Dateiebene), `/proc`-Introspektion
(Prozessebene) und auditd (Verhalten über die Zeit) — genau die drei Ebenen,
die v3.4 ergänzt.

---

## Funktionsweise von gsocket

Beide Seiten — Angreifer und Opfer — verbinden sich **ausgehend** per TLS zu
einem öffentlichen Relay (Global Socket Relay Network, GSRN) und finden sich
dort über ein gemeinsames Geheimnis. Konsequenzen:

- **NAT und Firewall werden vollständig umgangen.** Es muss nichts
  weitergeleitet und nichts geöffnet werden.
- **Portscans sehen nichts.** Von außen ist das System unauffällig.
- **Der Traffic ist gewöhnliches HTTPS auf 443.** Auffällig ist nicht der Port,
  sondern *welcher Prozess* die Verbindung hält.

Funktionsumfang der gefundenen Binary (aus den Strings): interaktive Shell mit
vollem PTY (`forkpty`, `pty_cmd`), Port-Forwarding, SOCKS5-Proxy (`socks.c`),
Dateitransfer (`GS_FT_data`), optionales TOR-Routing, Ende-zu-Ende-Verschlüsselung,
sowie Watchdog und Auto-Reconnect (`gs_watchdog`, `GS_daemonize`) für Persistenz.

> **Einordnung:** gsocket ist ein legitimes Dual-Use-Werkzeug; Pentester und
> Admins nutzen es für Fernzugriff durch Firewalls. Die Kombination aus
> Tarnname, `stripped`, statischem Linking und Relay-Fähigkeit ist jedoch das
> Profil des Einsatzes als Backdoor nach einer Kompromittierung.

---

## Neue Prüfungen in v3.4

| Nr.  | Prüfung | Signal |
|------|---------|--------|
| 5.6  | SSH-Login-Hooks | `~/.ssh/rc`, `/etc/ssh/sshrc` laufen bei **jedem** Login — taucht in keinem Cron und keiner Prozessliste auf |
| 5.7  | Erzwungene Kommandos | `command="…"` in `authorized_keys` |
| 6.9  | Exotische Persistenz | udev `RUN+=`, PAM `pam_exec.so`, APT `Pre-/Post-Invoke`, systemd `linger` |
| 7.10 | Getarnte Binaries | ELF-Magic in Dateien, die `id_rsa`, `*.pem`, `*.conf`, `*.png` … heißen |
| 7.11 | YARA-Signaturscan | `signaturen/gsocket-backdoors.yar`, sofern `yara` installiert |
| 8.7  | gsocket-Signaturen | Datei- und Prozessebene, ELF/Text getrennt bewertet |
| 8.8  | Fileless (memfd) | `/proc/PID/exe → /memfd:…` — Binary war nie auf der Platte |
| 8.9  | Kernel-Thread-Tarnung | Name `[kworker/…]`, aber PPID ≠ 2 **und/oder** vorhandenes `exe` |
| 8.10  | Verwaiste Interpreter | Shell mit PPID 1 und ohne TTY |
| 8.11  | Prozess-Umgebung | `GSOCKET_*`, `GS_ARGS`, `LD_PRELOAD`, `HISTFILE=/dev/null` |
| 8.12  | Ausgehende Verbindungen | 443/7350 durch Prozesse außerhalb der Whitelist; TOR-Ports |

### Warum die Prozess-Merkmale strukturell und nicht namensbasiert sind

Ein Name lässt sich frei wählen — `argv[0]` und `prctl(PR_SET_NAME)` kosten den
Angreifer nichts. Belastbar sind daher nur Merkmale, die er nicht ohne Weiteres
fälschen kann:

- **Echte Kernel-Threads haben PPID 2 (`kthreadd`) und kein `exe`.** Ein Prozess,
  der sich `[kworker/u8:2]` nennt und beides nicht erfüllt, ist enttarnt — das ist
  kein Verdacht, sondern ein Beweis.
- **`/proc/PID/exe` zeigt den echten Pfad**, unabhängig von der Kommandozeile.
- **`memfd:` im `exe`-Ziel** ist nicht fälschbar und bedeutet: kein Dateiscanner
  wird dieses Binary jemals finden.

---

## Verdikt

Analog zum bestehenden Root-Verdikt konsolidiert v3.4 die Befunde zu
`RELAY_VERDICT`:

| Punkte | Verdikt |
|---|---|
| ≥ 3 | 🔴 Interaktive Backdoor nachgewiesen |
| 1–2 | 🟡 Backdoor-Verdacht, manuell verifizieren |
| 0 | 🟢 Kein Hinweis auf eine Relay-Backdoor |

Gewichtung: gsocket-Binary, getarnte Binary und memfd-Prozess je 3 Punkte;
Kernel-Thread-Tarnung, YARA-Treffer und SSH-Login-Hook je 2; verdächtige
ausgehende Verbindung und verwaister Interpreter je 1.

---

## Grenzen

- **Ein sauberer Lauf ist kein Ausschluss.** Ist der Kanal zum Scanzeitpunkt
  nicht aktiv, existiert nur die Datei — und die kann beliebig heißen und
  liegen. Für dauerhafte Erkennung siehe `haertung/audit-backdoor.rules`.
- **Die 8.12-Whitelist ist heuristisch.** Systeme mit eigenen Agenten
  (Monitoring, Backup, VPN) erzeugen dort Fehlalarme; die Liste gehört an die
  jeweilige Umgebung angepasst.
- **8.11 braucht root.** `/proc/PID/environ` fremder Prozesse ist sonst nicht
  lesbar.
- **Signaturen sind umgehbar.** Wer die Strings aus dem Binary patcht, entgeht
  8.7 und der YARA-Regel — nicht aber 7.10, 8.8 und 8.9, die auf Struktur statt
  auf Inhalt prüfen. Deshalb laufen beide Ebenen parallel.

---

## Nachgelagerte Härtung

`haertung/audit-backdoor.rules` protokolliert das **Verhalten** laufend statt nur
Momentaufnahmen zu liefern: Ausführung aus `/tmp`, `/dev/shm` und dem Webroot,
`memfd_create`, Schreibzugriffe auf alle Persistenz-Orte, Kernel-Modul-Ladevorgänge
und die Kommandos des Webserver-Users.

Passt in Phase 7 (Härtung) des Playbooks in [`incident-response.md`](incident-response.md).

```bash
apt install auditd
cp haertung/audit-backdoor.rules /etc/audit/rules.d/50-backdoor.rules
augenrules --load && auditctl -s     # "lost" muss 0 bleiben
ausearch -k exec_tmp -i --start today
```

Die Abschnitte für vollständiges `execve`- und `connect`-Logging sind bewusst
auskommentiert — auf ausgelasteten Servern ist das Volumen sonst nicht tragbar.
Aktiv bleiben die auf `www-data` eingegrenzten Regeln: Jede Shell und jede
ausgehende Verbindung des Webserver-Users ist erklärungsbedürftig, und das
Volumen ist beherrschbar.
