# Erkennungs-Referenz — Doorway-Injector & selbst-versteckende Persistenz

> Fallbasiert dokumentiert nach einem realen Plesk-WordPress-Kundenvorfall (2026-07). Diese
> Familie **entzieht sich dem Signatur-Webshell-Scan** (§7.3): goto-Obfuskation,
> als Nicht-PHP getarnte Payloads, `@include`-Core-Injektion und Admin-Verstecken
> via `pre_user_query`. `webshell_count = 0` bedeutet hier **nicht** „sauber".
>
> Alle Befehle read-only, bis auf explizit markierte Bereinigungsschritte.
> Siehe auch: [Erkennung](erkennung.md) · [Runbook](runbook.md) · [Incident-Response](incident-response.md).

---

## 1. Schadfamilie „open_cache_ruzhu" (RCE-Backdoor + SEO-Spam-Doorway)

**Merkmale**
- Rekursiv selbst-verschachtelte Verzeichnisse mit dupliziertem Namen
  (`images/images/images/…`, `tmp/tmp/…`) oder Zufallsnamen (`jFiEnGZcmhXkaYg/…`).
- Je Ebene: `cache.php` + `index.php` (Backdoor) + `.htaccess` + zufällige
  Mediendatei-Dropper (`.wbmp .xbm .m3u8 .zip .wmv .wma .gif .swf`), Inhalt `<?php goto …`.
- Backdoor: `filter_input(INPUT_GET, …)` → curl Remote-Payload → `eval()`, MD5-Gate;
  `?of=1` → `readfile(__FILE__)`.
- Cloaking-Doorway in Root-`index.php`: erkennt Googlebot/Bing/Yahoo, liefert Spam,
  schreibt gefälschte `robots.txt`/`sitemap.xml`.
- Persistenz: `@include base64_decode("…")` in Zeile 1 von 8+ Core-Dateien lädt als
  `.ttf/.png/.gif/.css` getarnte Dropper („$open_cache_ruzhu_phpcode").

**Detektion**
```bash
DOC=/var/www/vhosts/DOMAIN/httpdocs

# 1) Doorway-Verzeichnisse (Signatur im .htaccess) — der zuverlässigste Marker
find "$DOC" -name ".htaccess" -size -400c 2>/dev/null \
  | while read -r f; do grep -qF '(index.php|cache.php)' "$f" && dirname "$f"; done | sort

# 2) WordPress-Kern-Integrität (injizierte Core-Dateien + Doorways in Core-Dirs)
wp core verify-checksums --path="$DOC"        # "doesn't verify" + "should not exist"

# 3) Bootstrap-Injektion (Payload-Nachladung bei jedem Request)
grep -rlF 'include base64_decode' "$DOC" --include='*.php'

# 4) Getarnte Payloads (PHP in Nicht-PHP-Endung)
grep -rlF 'open_cache_ruzhu_phpcode' "$DOC/wp-includes" "$DOC/wp-admin" "$DOC/wp-content"

# 5) Dekodiertes @include-Ziel sichtbar machen
head -1 "$DOC/wp-load.php" | grep -oE 'base64_decode\("[^"]+"' | sed 's/.*"\(.*\)"/\1/' | base64 -d
```

**Bereinigung** (NT-Repair-Konvention: Quarantäne statt Löschen)
- Injizierte Core-Dateien: `wp core download --force --skip-content` (vorher Evidence-Kopie;
  ggf. `chattr -i` / `chmod u+w` — Malware setzt 444).
- Doorway-Dirs mit dupliziertem Namen: ganzen Baum quarantänisieren.
- Legit Datumsordner (z. B. `woocommerce_uploads/YYYY/MM/DD`): nur `cache.php`/`index.php`/`.htaccess` entfernen.

---

## 2. Selbst-versteckende Admin-Persistenz (Fake-„Author: WordPress"-Plugins)

> **Kritische Lehre:** `wp user list --role=administrator` ist **unzuverlässig**.
> Ein bösartiges Plugin kann Admins per `pre_user_query` vor UI **und** wp-cli
> verstecken und beim Löschen sofort neu anlegen. Persistenz **zuerst** entfernen,
> **dann** Admins löschen — sonst Recreation.

**Signatur der Fake-Plugins**
```
Plugin URI: http://wordpress.org/plugins/
Author: WordPress
```
Beobachtete Namen: `wp_configuration`, `armor-kubernetes-config`,
`erosion-broadcast-compat`; mu-plugin `vapor-balancer-run.php` (obfuskiert, Custom-
String-Decoder). Nicht in der sichtbaren aktiven Plugin-Liste (verstecken sich selbst).

**Funktionsbausteine**
- `add_action('init','create_admin')` + `wp_create_user()` + `set_role('administrator')` → Recreation je Request.
- `add_action('pre_user_query', …)` / `pre_user_search` + `avail_roles['administrator']--` → Verstecken.
- `ensure_plugin_active` auf `admin_init`/`shutdown` → Selbst-Reaktivierung.
- `base64_decode($_POST/$_REQUEST)` + `eval` via admin-ajax → RCE.

**Detektion**
```bash
DOC=/var/www/vhosts/DOMAIN/httpdocs

# Fake-Plugins per Header-Signatur
grep -rlE 'Author: WordPress$' "$DOC/wp-content/plugins" "$DOC/wp-content/mu-plugins" --include='*.php' \
  | xargs -r grep -lF 'wordpress.org/plugins/'

# Verhaltens-Signaturen
grep -rlE 'pre_user_query|create_admin|ensure_plugin_active|wp_create_user\(' \
  "$DOC/wp-content/plugins" "$DOC/wp-content/mu-plugins" 2>/dev/null

# mu-plugins laufen IMMER — jede Datei prüfen
ls -la "$DOC/wp-content/mu-plugins/"

# Admins AUTORITATIV über Roh-Meta (nicht wp user list --role!)
wp db query "SELECT u.ID,u.user_login,u.user_registered FROM PREFIX_users u
  JOIN PREFIX_usermeta m ON u.ID=m.user_id
  WHERE m.meta_key='PREFIX_capabilities' AND m.meta_value LIKE '%\"administrator\";b:1%';" \
  --skip-column-names --path="$DOC"
```

**Bereinigung (Reihenfolge zwingend)**
1. Alle Persistenz-Komponenten (Plugins + mu-plugin) quarantänisieren.
2. `active_plugins`-Option von den Fremd-Einträgen bereinigen
   (`wp eval '…array_filter(get_option("active_plugins")…)'`).
3. Rogue-Admins via Roh-SQL-Liste löschen (`wp user delete … --reassign=1`).
4. Alle Sessions invalidieren (`DELETE FROM …usermeta WHERE meta_key='session_tokens'`).
5. HTTP-Request auslösen und Roh-SQL-Admincheck **wiederholen** → keine Recreation.
6. Zugangsdaten **erneut** rotieren (die während aktiver RCE gesetzten Passwörter
   gelten als exponiert; DB-Passwort steht als Klartext in `wp-config.php`).

---

## 3. Merksätze

- `webshell_count = 0` ≠ sauber — immer `verify-checksums` + Doorway-Signatur + `@include`-Scan.
- DB-Prüfung nie stillschweigend überspringen — wp-cli-Fallback nutzen.
- `wp user list --role` kann lügen — Roh-`capabilities`-Meta ist die Wahrheit.
- Persistenz vor Symptomen entfernen — sonst heilt sich der Befund selbst.
- `wp-config.php` auf **auskommentierte** alte `define()`-Werte prüfen (falsche DB).
