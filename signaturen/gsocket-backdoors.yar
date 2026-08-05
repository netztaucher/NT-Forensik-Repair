/*
 * gsocket-backdoors.yar
 * -----------------------------------------------------------------------
 * YARA-Regelsatz zur Erkennung von THC gsocket / gs-netcat sowie
 * verwandter Backdoor-Muster (Reverse-Shells, PHP-Webshells, Droppers).
 *
 * Einsatz:
 *   Dateisystem:   yara -r -w -f gsocket-backdoors.yar /  2>/dev/null
 *   Nur Webroot:   yara -r -w gsocket-backdoors.yar /var/www
 *   Laufender PID: yara gsocket-backdoors.yar <PID>
 *   Alle PIDs:     for p in /proc/[0-9]*; do yara -w gsocket-backdoors.yar \
 *                    ${p##*(/)} 2>/dev/null; done
 *
 * Hinweis: Regeln mit Tag "heuristic" erzeugen naturgemaess auch
 * False Positives (z.B. auf Admin-Tools). Immer manuell verifizieren.
 * -----------------------------------------------------------------------
 */

import "hash"

/*
 * Externe Variable "filename" - wird bei Bedarf per  -d filename="..."
 * gesetzt. Wenn nicht gesetzt, muss beim Kompilieren ein Default
 * uebergeben werden (der Scanner erledigt das automatisch).
 */

/* =======================================================================
 * 1) EXAKTER TREFFER - die konkret gefundene Binary
 * ======================================================================= */

rule GSOCKET_KnownSample_id_rsa
{
    meta:
        description = "Exakter Hash der als 'id_rsa' getarnten gs-netcat Binary"
        severity    = "critical"
        date        = "2026-08-04"
    condition:
        filesize > 2MB and filesize < 4MB and
        hash.sha256(0, filesize) ==
          "d94f75a70b5cabaf786ac57177ed841732e62bdcc9a29e06e5b41d9be567bcfa"
}

/* =======================================================================
 * 2) GSOCKET / GS-NETCAT - Signaturbasiert, namensunabhaengig
 * ======================================================================= */

rule GSOCKET_Core
{
    meta:
        description = "THC gsocket / gs-netcat Backdoor (auch umbenannt/stripped)"
        reference   = "https://gs.thc.org"
        severity    = "critical"
    strings:
        $s1 = "gs.thc.org"                      ascii
        $s2 = "GSOCKET_ARGS"                    ascii
        $s3 = "4_gs-netcat.c"                   ascii
        $s4 = "GS_connect() == %d"              ascii
        $s5 = "gs_watchdog"                     ascii
        $s6 = "GS_daemonize"                    ascii
        $s7 = "GSOCKET_SOCKS_IP"                ascii
        $s8 = "Connection to TOR established"   ascii
        $s9 = "GSRN"                            ascii
        $s10 = "GS_gen_secret"                  ascii
        $s11 = "Enter Secret (or press Enter to generate)" ascii
    condition:
        uint32(0) == 0x464c457f and 2 of ($s*)
}

rule GSOCKET_Deploy_Script
{
    meta:
        description = "gsocket deploy.sh / Installer-Skript"
        severity    = "critical"
    strings:
        $a1 = "gsocket.io"        ascii nocase
        $a2 = "gs.thc.org"        ascii nocase
        $a3 = "GS_SECRET"         ascii
        $a4 = "gs-dbus"           ascii
        $a5 = "GSOCKET_SECRET"    ascii
        $b1 = "deploy.sh"         ascii
        $b2 = "curl"              ascii
        $b3 = "wget"              ascii
    condition:
        filesize < 200KB and 1 of ($a*) and 1 of ($b*)
}

rule GSOCKET_Masquerade_Names
{
    meta:
        description = "Von gsocket-Deploy typisch verwendete Tarnnamen"
        severity    = "high"
    strings:
        $m1 = "gs-dbus"                 ascii
        $m2 = "dbus-run-session.sh"     ascii
        $m3 = "[kworker/1:2]"           ascii
        $m4 = "gs-bd"                   ascii
    condition:
        any of them
}

/* =======================================================================
 * 3) GETARNTE BINARIES - ELF wo keine sein darf
 * ======================================================================= */

/*
 * Diese Regel BRAUCHT die externe Variable "filename", sonst feuert sie
 * auf jede ELF-Datei im System (100% False Positives).
 * Aufruf:  yara -d filename="$(basename "$f")" regel.yar "$f"
 * Der Scanner (gsocket-forensik.sh) setzt das automatisch.
 */
rule ELF_Masquerading_As_KeyFile
{
    meta:
        description = "ELF-Binary getarnt als Schluessel-/Zertifikatsdatei"
        severity    = "critical"
        requires    = "external var: filename"
    condition:
        uint32(0) == 0x464c457f and
        (
            filename matches /^id_(rsa|dsa|ecdsa|ed25519)/ or
            filename matches /\.(pem|key|crt|cer|pub|conf|cfg|log|txt|json)$/i or
            filename == "authorized_keys" or
            filename == "known_hosts"
        )
}

rule ELF_Static_Stripped_InTempDir : heuristic
{
    meta:
        description = "Statisch gelinkte, gestrippte ELF - typischer self-contained Drop"
        severity    = "medium"
    strings:
        $musl   = "MUSL_LOCPATH"   ascii
        $nolib  = "/lib/ld-linux"  ascii
    condition:
        uint32(0) == 0x464c457f and filesize > 500KB and
        $musl and not $nolib
}

/* =======================================================================
 * 4) REVERSE-SHELLS (Skript-basiert)
 * ======================================================================= */

rule Backdoor_Perl_ReverseShell
{
    meta:
        description = "Perl Reverse-Shell / Bind-Shell"
        severity    = "critical"
    strings:
        $p1 = "IO::Socket::INET"        ascii
        $p2 = "use Socket"              ascii
        $s1 = "/bin/sh -i"              ascii
        $s2 = "exec(\"/bin/sh"          ascii
        $s3 = "STDIN->fdopen"           ascii
        $s4 = "open(STDIN,\">&"         ascii
        $s5 = "dup2"                    ascii
        $c1 = "connect("                ascii
        $c2 = "sockaddr_in"             ascii
    condition:
        filesize < 500KB and 1 of ($p*) and 1 of ($s*) and 1 of ($c*)
}

rule Backdoor_Python_ReverseShell
{
    meta:
        description = "Python Reverse-Shell"
        severity    = "critical"
    strings:
        $i1 = "import socket"       ascii
        $i2 = "import pty"          ascii
        $i3 = "import subprocess"   ascii
        $a1 = "os.dup2"             ascii
        $a2 = "pty.spawn"           ascii
        $a3 = "subprocess.call([\"/bin/sh" ascii
        $a4 = "/bin/bash\"])"       ascii
        $c1 = ".connect(("           ascii
    condition:
        filesize < 500KB and 1 of ($i*) and 1 of ($a*) and $c1
}

rule Backdoor_Bash_DevTCP
{
    meta:
        description = "Bash /dev/tcp Reverse-Shell"
        severity    = "critical"
    strings:
        $t1 = "/dev/tcp/"   ascii
        $t2 = "/dev/udp/"   ascii
        $s1 = "bash -i"     ascii
        $s2 = "sh -i"       ascii
        $s3 = "0>&1"        ascii
        $s4 = "exec 5<>"    ascii
    condition:
        filesize < 500KB and 1 of ($t*) and 1 of ($s*)
}

rule Backdoor_Netcat_Socat_Exec
{
    meta:
        description = "netcat/socat mit Kommando-Ausfuehrung oder FIFO-Trick"
        severity    = "high"
    strings:
        $n1 = "nc -e "              ascii
        $n2 = "ncat -e "            ascii
        $n3 = "nc.traditional -e"   ascii
        $n4 = "socat "              ascii
        $n5 = "EXEC:'/bin/sh"       ascii
        $n6 = "EXEC:\"/bin/sh"      ascii
        $f1 = "mkfifo"              ascii
        $f2 = "rm -f /tmp/f"        ascii
    condition:
        filesize < 500KB and
        ( 1 of ($n1,$n2,$n3,$n5,$n6) or ($n4 and 1 of ($n5,$n6)) or
          ($f1 and $f2) )
}

/* =======================================================================
 * 5) PHP-WEBSHELLS  (relevant fuer WordPress-Fleet)
 * ======================================================================= */

rule Webshell_PHP_EvalUserInput
{
    meta:
        description = "PHP-Webshell: Code-Ausfuehrung aus Request-Parametern"
        severity    = "critical"
    strings:
        $e1 = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/       nocase
        $e2 = /assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/            nocase
        $e3 = /create_function\s*\(.{0,40}\$_(GET|POST|REQUEST)/      nocase
        $e4 = /(system|shell_exec|passthru|popen|proc_open|exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $e5 = /base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/     nocase
        $e6 = /preg_replace\s*\(\s*['"].*\/e['"]/                     nocase
        $php = "<?php"
    condition:
        filesize < 2MB and $php and 1 of ($e*)
}

rule Webshell_PHP_Obfuscated
{
    meta:
        description = "PHP: gepackte/obfuskierte Payload (typisch fuer Webshells)"
        severity    = "high"
    strings:
        $o1 = /gzinflate\s*\(\s*base64_decode/      nocase
        $o2 = /gzuncompress\s*\(\s*base64_decode/   nocase
        $o3 = /str_rot13\s*\(\s*base64_decode/      nocase
        $o4 = /eval\s*\(\s*gzinflate/               nocase
        $o5 = /\$\{[\"'][a-zA-Z_]+[\"']\}\s*\(/
        $o6 = "$GLOBALS['_'"                        ascii
        $php = "<?php"
    condition:
        filesize < 2MB and $php and 1 of ($o*)
}

rule Webshell_PHP_KnownFamilies
{
    meta:
        description = "Bekannte PHP-Webshell-Familien"
        severity    = "critical"
    strings:
        $w1 = "FilesMan"        ascii
        $w2 = "WSO "            ascii
        $w3 = "wso_version"     ascii
        $w4 = "c99shell"        ascii nocase
        $w5 = "r57shell"        ascii nocase
        $w6 = "b374k"           ascii nocase
        $w7 = "weevely"         ascii nocase
        $w8 = "IndoXploit"      ascii nocase
        $w9 = "AnonymousFox"    ascii nocase
        $w10 = "Marijuana Shell" ascii nocase
    condition:
        filesize < 3MB and any of them
}

rule Webshell_PHP_FileUploader : heuristic
{
    meta:
        description = "PHP mit Upload- + Ausfuehrungsfunktion (moegliche Dropper-Shell)"
        severity    = "medium"
    strings:
        $u1 = "move_uploaded_file"  ascii
        $u2 = "$_FILES"             ascii
        $x1 = "shell_exec"          ascii
        $x2 = "system("             ascii
        $x3 = "eval("               ascii
        $x4 = "passthru"            ascii
        $php = "<?php"
    condition:
        filesize < 1MB and $php and 1 of ($u*) and 1 of ($x*)
}

/* =======================================================================
 * 6) PERSISTENZ-ARTEFAKTE
 * ======================================================================= */

rule Persistence_Cron_Downloader
{
    meta:
        description = "Cron-/Shell-Eintrag der Code nachlaedt und ausfuehrt"
        severity    = "critical"
    strings:
        $d1 = /(curl|wget)[^\n]{0,120}\|\s*(ba)?sh/
        $d2 = /(curl|wget)[^\n]{0,120}-O\s*[^\n]{0,60}(\/tmp|\/dev\/shm|\/var\/tmp)/
        $d3 = /echo\s+[A-Za-z0-9+\/=]{40,}\s*\|\s*base64\s+-d/
        $d4 = /base64\s+-d[^\n]{0,40}\|\s*(ba)?sh/
        $c1 = "@reboot"     ascii
        $c2 = "* * * * *"   ascii
    condition:
        filesize < 200KB and ( 1 of ($d*) or (1 of ($c*) and 1 of ($d*)) )
}

rule Persistence_SSH_ForcedCommand : heuristic
{
    meta:
        description = "authorized_keys mit forced command (mgl. versteckte Persistenz)"
        severity    = "medium"
    strings:
        $k = "ssh-" ascii
        $f = "command=\"" ascii
    condition:
        filesize < 100KB and $k and $f
}

rule Persistence_LD_Preload_Rootkit
{
    meta:
        description = "Userland-Rootkit via LD_PRELOAD (Hooking von libc-Funktionen)"
        severity    = "critical"
    strings:
        $h1 = "readdir"     ascii
        $h2 = "readdir64"   ascii
        $h3 = "dlsym"       ascii
        $h4 = "RTLD_NEXT"   ascii
        $h5 = "__xstat"     ascii
        $h6 = "/etc/ld.so.preload" ascii
        $h7 = "getdents"    ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 500KB and 4 of ($h*)
}

/* =======================================================================
 * 7) IN-MEMORY / FILELESS
 * ======================================================================= */

rule Fileless_Memfd_Loader
{
    meta:
        description = "Loader der Binaries per memfd_create() nur im RAM ausfuehrt"
        severity    = "critical"
    strings:
        $m1 = "memfd_create"    ascii
        $m2 = "/proc/self/fd/"  ascii
        $m3 = "fexecve"         ascii
        $m4 = "MFD_CLOEXEC"     ascii
    condition:
        2 of them
}
