#!/bin/bash
# start.sh — Prüfstand: MariaDB und Apache starten, beim ersten Start MySQL-admin anlegen.
# Werte nur in Dateien (600) und über stdin an mysql, nie als Argument.
set -u
install -d -o mysql -g mysql /run/mysqld
mysqld_safe >/dev/null 2>&1 &
for _ in $(seq 1 60); do mysqladmin ping >/dev/null 2>&1 && break; sleep 1; done
if [ ! -s /etc/psa/.psa.shadow ]; then
  umask 077; openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-32 > /etc/psa/.psa.shadow
  { printf "CREATE USER 'admin'@'localhost' IDENTIFIED BY '%s';\n" "$(cat /etc/psa/.psa.shadow)"
    echo "GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost' WITH GRANT OPTION;"; } | mysql
fi
apache2ctl start
exec sleep infinity
