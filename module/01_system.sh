# shellcheck shell=bash
# NT-Forensik — Abschnitt 1: System-Übersicht
#
# @nummer:  1
# @titel:   System-Übersicht
# @frage:   Auf welchem System läuft das, und was wurde zuletzt daran geändert?
# @kosten:  gering
# @ebene:   system
#
# Wird vom Runner eingebunden, nicht einzeln ausgefuehrt.
# Vorgabewerte der hier gefuellten Variablen: lib/befunde.sh

h1 "1. SYSTEM-ÜBERSICHT"
# ============================================================

h2 "1.1 Betriebssystem & Kernel"
OS_INFO=$(grep -E "^(NAME|VERSION)=" /etc/os-release 2>/dev/null | tr '\n' ' ')
KERNEL=$(uname -r)
info "OS: $OS_INFO"
info "Kernel: $KERNEL"
code "$(uname -a)"
evidence "system_info" "$(uname -a; echo; cat /etc/os-release 2>/dev/null)"

h2 "1.2 Plesk-Version"
if command -v plesk &>/dev/null; then
  PLESK_VER=$(plesk version 2>/dev/null | head -3)
  info "$PLESK_VER"
  code "$PLESK_VER"
  ok "Plesk gefunden"
else
  PLESK_VER="nicht gefunden"
  warn "Plesk-Binär nicht im PATH — manuell prüfen"
fi

h2 "1.3 PHP-Versionen"
if command -v php &>/dev/null; then
  PHP_VERS=$(php -v 2>/dev/null | head -1)
  info "$PHP_VERS"
  code "$PHP_VERS"
fi
if command -v plesk &>/dev/null; then
  PHP_HANDLERS=$(plesk bin php_handler --list 2>/dev/null || echo "Nicht abfragbar")
  code "$PHP_HANDLERS"
  evidence "php_handler" "$PHP_HANDLERS"
fi

h2 "1.4 Webserver"
if command -v apache2 &>/dev/null; then
  code "$(apache2 -v 2>/dev/null)"
elif command -v nginx &>/dev/null; then
  code "$(nginx -v 2>&1)"
fi

h2 "1.5 Uptime & Last-Reboot"
code "$(uptime && last reboot | head -5)"

h2 "1.6 Admin-Änderungsprotokoll (/root/changelog.md)"
# netztaucher-Konvention: dokumentierte Systemänderungen. Dient als Abgleich —
# ein Fund, der hier erklärt ist, ist meist gutartige Admin-Arbeit; fehlt der
# Eintrag, ist der Fund erklärungsbedürftig.
CHANGELOG="/root/changelog.md"
if [[ -f "$CHANGELOG" ]]; then
  ok "Änderungsprotokoll gefunden: $CHANGELOG (zuletzt geändert: $(stat -c %y "$CHANGELOG" 2>/dev/null | cut -d. -f1))"
  CHANGELOG_TAIL=$(tail -40 "$CHANGELOG" 2>/dev/null || true)
  info "Letzte Einträge (zum Abgleich mit den Befunden):"
  code "$CHANGELOG_TAIL"
  evidence "admin_changelog" "$(cat "$CHANGELOG" 2>/dev/null)"
else
  warn "Kein /root/changelog.md — Admin-Änderungen nicht dokumentiert. Befunde können nicht gegen dokumentierte Wartung abgeglichen werden. Empfehlung: Änderungsprotokoll führen."
fi

# ============================================================