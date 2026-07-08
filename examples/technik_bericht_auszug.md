# Forensik-Bericht (Technik) — Auszug

> **Beispiel mit fiktiven Daten.** Auszug aus dem maschinell erzeugten
> `technik_bericht.md`, gekürzt auf die aussagekräftigsten Abschnitte.

| | |
|---|---|
| **Lauf-ID** | 20260708_090000_server |
| **Domain** | Alle Domains |
| **Server** | srv-web01.hoster.example |
| **Erstellt durch** | wp_plesk_forensik.sh |

---

## 7. DATEISYSTEM-SCAN

### 7.3 Webshell-Muster (Inhalt) — zweistufig

- 🔴 **KRITISCH: Webshells/Dropper gefunden: 17 Datei(en) < 3000 B mit Obfuskation**

Betroffene Domains (Dropper-Cluster):

```
     17 beispiel-shop.example
```

**Dropper-Details (Auszug):**

```
=== /var/www/vhosts/beispiel-shop.example/httpdocs/img/social-icon.php ===
Größe: 214 B | mtime: 2024-12-08 00:20:02 | SHA256: 0f1e2d3c...aa11 (fiktiv)
Treffer: 1:${$m.$x.$s}  1:EvaL(base64_decode(

=== /var/www/vhosts/beispiel-shop.example/httpdocs/css/theme-cache.php ===
Größe: 238 B | mtime: 2024-03-19 14:27:22 | SHA256: 4b5c6d7e...bb22 (fiktiv)
Treffer: 1:${$a.$b.$c}  1:evAl(base64_decode(
```

- ⚠️ Obfuskations-Muster in 9 größeren Datei(en) — manuell prüfen (oft legitime Frameworks)

### 7.2 PHP-Dateien in Upload-Verzeichnissen

- ✅ Keine verdächtigen PHP-Dateien in Upload-Verzeichnissen (23 legitime Guard-/Plugin-Dateien gefiltert)

---

## 11. WORDPRESS-DATENBANK-PRÜFUNG

### 11.1 Gefundene WordPress-Installationen

  WordPress-Installationen: 12

#### beispiel-shop.example/httpdocs  (DB: `wp_beispielshop`, Prefix: `wp_`)

  Administrator-Konten: 2

- ✅ beispiel-shop.example/httpdocs: keine kürzlich angelegten Admins
- ✅ beispiel-shop.example/httpdocs: keine verdächtigen auto_prepend/eval-Optionen

### 11.9 WordPress-DB-Verdikt

🟢 **Keine Angreifer-Spuren in den WordPress-Datenbanken** (keine neuen Admins, keine manipulierten Optionen).

---

## 12. ROOT- & ESKALATIONS-PRÜFUNG

### 12.1 Erfolgreiche Root-Logins (IP + Auth-Methode)

  Distinct-IPs mit erfolgreichem Root-Login:

```
127.0.0.1
198.51.100.200   (Administrator, Key)
```

- ⚠️ Root-Login per PASSWORT aktiv — auf Key-only umstellen (`PermitRootLogin prohibit-password`)

### 12.3 Web-User-SSH-Keys serverweit (Fremd-Key-Persistenz?)

- ✅ Nur Plesk-eigene SSH-Keys bei Web-Usern (keine Fremd-Key-Persistenz)

### 12.4 Privilege-Escalation (sudo/su durch Nicht-Root)

- ✅ Keine sudo/su-Rechteausweitung durch Web-/Systemnutzer in Logs

### 12.6 Root-Verdikt

- ✅ ROOT-VERDIKT: keine Root-Kompromittierung nachweisbar

🟢 **Keine Hinweise auf Root-Kompromittierung.** Erfolgreiche Root-Logins nur von bekannten/legitimen Quellen, keine Fremd-SSH-Keys, keine Rechteausweitung durch Web-Nutzer, System-Binaries unverändert. Ein etwaiger Vorfall ist nach aktueller Beweislage auf Web-User-Ebene begrenzt.

---

## 13. ZUSAMMENFASSUNG

### Befund-Statistik

| Kategorie | Anzahl |
|---|---|
| 🔴 Kritische Befunde | 1 |
| ⚠️ Warnungen | 12 |
| ✅ Unauffällige Prüfungen | 230 |

---
*Auszug — Beispiel mit fiktiven Daten. wp_plesk_forensik.sh — netztaucher | digital*
