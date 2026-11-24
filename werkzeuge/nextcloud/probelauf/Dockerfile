# Wegwerf-Prüfstand für werkzeuge/nextcloud (#165): echte Nextcloud 27 + MariaDB + Apache
# in Plesk-Anordnung (/var/www/vhosts/<domain>/httpdocs, Abo-Benutzer, /opt/plesk/php/8.2).
# Nachgebildet ist nur `plesk` (siehe plesk-attrappe). Gestartet von probelauf.sh, nie auf einem Kundenserver.
FROM debian:bookworm-slim
ARG NC_VERSION=27.1.11
ARG NC_SHA256=4edd2570f4c83442f8f0f0616fb774ed2663b11cf9f6ea49e795ab43aeef9645
ARG DOMAIN=nc.probe.test
ARG ABO=ncabo
ENV DEBIAN_FRONTEND=noninteractive DOMAIN=${DOMAIN} ABO=${ABO}
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      apache2 libapache2-mod-php8.2 php8.2-cli php8.2-mysql php8.2-gd php8.2-curl php8.2-mbstring \
      php8.2-intl php8.2-xml php8.2-zip php8.2-bcmath php8.2-gmp php-apcu \
      mariadb-server curl ca-certificates bzip2 procps ssl-cert openssl python3 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash "$ABO" \
    && install -d -m 755 "/var/www/vhosts/$DOMAIN" /opt/plesk/php/8.2/bin /etc/psa /etc/plesk-attrappe /etc/cron.d \
    && ln -s /usr/bin/php8.2 /opt/plesk/php/8.2/bin/php \
    && echo plesk-php82-fastcgi > /etc/plesk-attrappe/handler \
    && echo "$ABO" > /etc/cron.deny
RUN curl -fsSL -o /tmp/nc.tar.bz2 "https://download.nextcloud.com/server/releases/nextcloud-${NC_VERSION}.tar.bz2" \
    && echo "${NC_SHA256}  /tmp/nc.tar.bz2" | sha256sum -c - \
    && tar -C "/var/www/vhosts/$DOMAIN" -xjf /tmp/nc.tar.bz2 \
    && mv "/var/www/vhosts/$DOMAIN/nextcloud" "/var/www/vhosts/$DOMAIN/httpdocs" \
    && mkdir "/var/www/vhosts/$DOMAIN/httpdocs/data" \
    && chown -R "$ABO:$ABO" "/var/www/vhosts/$DOMAIN/httpdocs" && rm /tmp/nc.tar.bz2
# Apache läuft als Abo-Benutzer (wie PHP-FPM unter Plesk), TLS mit Schlangenöl-Zertifikat
RUN sed -i "s/^export APACHE_RUN_USER=.*/export APACHE_RUN_USER=$ABO/; s/^export APACHE_RUN_GROUP=.*/export APACHE_RUN_GROUP=$ABO/" /etc/apache2/envvars \
    && a2enmod -q ssl rewrite headers \
    && sed -i "s#DocumentRoot /var/www/html#DocumentRoot /var/www/vhosts/$DOMAIN/httpdocs\n\t<Directory /var/www/vhosts/$DOMAIN/httpdocs>\n\t\tAllowOverride All\n\t\tRequire all granted\n\t</Directory>#" /etc/apache2/sites-available/default-ssl.conf \
    && a2ensite -q default-ssl && a2dissite -q 000-default \
    && printf 'memory_limit=1024M\napc.enable_cli=1\n' > /etc/php/8.2/mods-available/probe.ini && phpenmod probe
COPY plesk-attrappe /usr/local/bin/plesk
COPY start.sh /usr/local/bin/start.sh
RUN chmod 755 /usr/local/bin/plesk /usr/local/bin/start.sh
CMD ["/usr/local/bin/start.sh"]
