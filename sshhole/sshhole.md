# OpenSSH: Passwort-Bypass auf musl ohne PAM ("sshhole", CVE-2026-123158)

Stand: 06.11.2026

Der Entdecker nennt die Lücke "\*sshole" (Website sshhole.com, Repo `github.com/oz9un/sshole`), in der Presse heißt sie meist "SSHHole" oder "sshhole". sshd nimmt auf Linux-Systemen mit musl-libc und ohne PAM für Accounts mit `*` im Passwortfeld jedes Passwort mit 257 bis 1024 Bytes an. Betroffen sind vor allem Alpine Linux und Container- bzw. Cloud-Images auf Alpine-Basis. Systeme mit glibc (Debian, Ubuntu, RHEL, Fedora, SUSE) sind nicht betroffen.

## Worum es geht

Ohne PAM prüft sshd Passwörter selbst in `sys_auth_passwd()` (`auth-passwd.c`): Es hasht das eingegebene Passwort mit `crypt()` und vergleicht das Ergebnis per `strcmp()` mit dem Eintrag aus `/etc/shadow`. Drei Verhaltensweisen greifen dabei ineinander:

1. **OpenSSH seit 2016 (Fix für CVE-2016-6210):** Damit Angreifer gültige Benutzernamen nicht an der Antwortzeit erkennen, hasht sshd auch dann, wenn der gespeicherte Eintrag kein gültiger Hash ist (z. B. `*`). Das Salt dafür holt `pick_salt()` (`openbsd-compat/xcrypt.c`) von einem anderen Account mit echtem Hash, etwa `$6$...` (SHA-512).
2. **musl `crypt()` seit 2012:** Im Fehlerfall gibt musl den String `"*"` zurück, nicht `NULL`, wie POSIX es vorschreibt (musl-Commit `b3c4cc12`).
3. **musl SHA-256/SHA-512-crypt seit 2012:** Schlüssel über 256 Bytes werden abgelehnt (`KEY_MAX 256`, musl-Commit `88bf5a8a`). `crypt()` schlägt fehl und liefert `"*"`.

Ergebnis: Für einen Account mit `*` in `/etc/shadow` hasht sshd ein 257 Byte langes Passwort mit dem `$6$`-Salt eines anderen Accounts. musl liefert `"*"`, sshd vergleicht `"*"` mit `"*"`, und der Login ist erfolgreich. Über 1024 Bytes verwirft sshd das Passwort vorher (`MAX_PASSWORD_LEN 1024`), daher die Obergrenze.

Glibc bzw. libxcrypt geben im Fehlerfall `NULL` oder `"*0"` zurück, das passt nie auf `*`. Mit PAM prüft `pam_unix` und nicht `sys_auth_passwd()`.

### Der Fix

OpenSSH 10.6p2 vom 05.11.2026 enthält den Upstream-Commit `90f9c2f7` ("avoid password authn bypass", Damien Miller). sshd akzeptiert ein Passwort nur noch, wenn der gespeicherte Hash mindestens 4 Zeichen lang ist (`MIN_PASSWORD_HASH_LEN`). Einträge wie `*`, `!` oder `x` passen damit nie mehr. OpenSSH sieht die Ursache in musl, umgeht sie aber in sshd. Die Release Notes nennen es "critical security workaround".

### Bewertung

| Quelle | CVSS 3.1 | Vektor |
| --- | --- | --- |
| IONIX, OX Security | 8.1 (High) | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` |

Die hohe Angriffskomplexität kommt von den vielen Vorbedingungen (siehe unten). Ein Eintrag bei NVD und im Alpine-Security-Tracker war am 06.11. noch nicht abrufbar.

### Ausnutzung

- Gefunden hat die Lücke Özgün Kültekin (Wakefield). Er hat nach eigenen Angaben mit KI-Agenten rund 17.600 Login-Varianten gegen verschiedene sshd-Builds getestet. Nur musl ohne PAM fiel aus der Reihe.
- Öffentliche Labs zum Nachstellen gibt es laut OX Security bereits. Der Angriff braucht nur eine einzige Verbindung mit einem langen Passwort, kein Brute-Force.
- CISA führt die Lücke nicht im KEV-Katalog (Stand 05.11.2026). Aktive Angriffe sind nicht bekannt.

## Vorbedingungen

Alle Punkte müssen zutreffen:

| # | Bedingung | Bemerkung |
| --- | --- | --- |
| 1 | sshd ist gegen musl gelinkt | Alpine, OpenWrt mit `openssh-server`, Buildroot/Yocto mit musl, Void-musl usw. |
| 2 | sshd läuft ohne PAM | Standard bei Alpines `openssh-server` und OpenWrts `openssh-server`. Die `-pam`-Pakete setzen `UsePAM yes`. |
| 3 | `PasswordAuthentication yes` | OpenSSH-Standard, wenn nichts anderes konfiguriert ist |
| 4 | Ein Account hat `*` in `/etc/shadow` | siehe unten |
| 5 | Ein anderer Account hat einen `$5$`- oder `$6$`-Hash | liefert das Salt. Ohne ihn nimmt sshd das DES-Salt `xx`, DES kürzt auf 8 Zeichen und schlägt nicht fehl. |
| 6 | sshd lässt den `*`-Account zu | `PermitRootLogin prohibit-password` (Standard) sperrt root für Passwörter, `AllowUsers`/`DenyUsers` können ebenfalls schützen |

### Warum `*` auf Alpine so häufig ist

sshd ohne PAM behandelt `!` am Anfang des Hashes als gesperrten Account und lehnt dann auch Key-Logins ab. Wer auf Alpine einen reinen Key-Account braucht, setzt deshalb `*` (z. B. `echo "user:*" | chpasswd -e` oder `usermod -p '*'`). Das ist eine verbreitete Empfehlung für Alpine und steht so in vielen Dockerfiles.

- **root in Alpine-Images:** Seit Alpine 3.16 (2022) steht root in den Images auf `*` (Reaktion auf CVE-2019-5021). Mit dem Standard `PermitRootLogin prohibit-password` ist root per Passwort trotzdem nicht erreichbar.
- **`alpine`-User in den offiziellen AWS- und Azure-Images:** hat `*` und passwortloses `doas`. Kommt man als `alpine` rein, ist man root.
- **Key-only-Deploy-User, Git-User, LDAP-User:** typischerweise `*`.

## Was betroffen ist

### Betroffen

- **Alpine Linux** mit Paket `openssh-server` (ohne PAM) bis zum gefixten Paket, alle Releases ab 3.16. Ältere Releases sind nicht gepatcht, der Code ist dort ebenfalls verwundbar.
- **Container-Images auf Alpine-Basis, die einen sshd mitbringen**, z. B. SFTP-, Bastion-, Jump-Host- und Git-Server-Images. Das reine `alpine:*`-Basisimage enthält keinen sshd und ist nicht betroffen.
- **Alpine-Cloud-Images (AWS, Azure)** wegen des `alpine`-Users, sobald Passwort-Login an ist und ein weiterer Account einen `$6$`-Hash hat.
- **OpenWrt** nur mit nachinstalliertem Paket `openssh-server` (ohne PAM). Der Standard-SSH-Server von OpenWrt ist Dropbear.
- **Embedded-Systeme mit Buildroot oder Yocto**, wenn musl und OpenSSH ohne PAM gebaut wurden.

### Nicht betroffen

- glibc-Distributionen: Debian, Ubuntu, RHEL, CentOS, Rocky, Alma, Fedora, SUSE, Arch
- sshd mit `UsePAM yes` (z. B. Alpine `openssh-server-pam`, OpenWrt `openssh-server-pam`)
- `PasswordAuthentication no`
- Dropbear (auch auf musl), OpenBSD
- Accounts mit echtem Passwort-Hash: Für sie greift die Lücke nicht, ein falsches Passwort bleibt falsch.
- Accounts mit `!` statt `*`

### Beispiel Gitea und Forgejo

Die offiziellen Docker-Images von Gitea und Forgejo basieren auf `alpine:3.24`, installieren `openssh` und setzen `echo "git:*" | chpasswd -e`. Das sshd-Template von Gitea setzt aber `PasswordAuthentication no`. Im Standard sind sie damit nicht angreifbar. Wer die Template-Variable auf `yes` gestellt hat, sollte die Images trotzdem neu ziehen.

## Gefixte Versionen

### OpenSSH upstream

| Version | Status |
| --- | --- |
| 10.6p2 (05.11.2026) | gefixt |
| alle Portable-Versionen davor seit 2016 | verwundbar unter den oben genannten Bedingungen |

### Alpine Linux

Alpine hat am 05.11.2026 alle Branches ab 3.16 gepatcht, auch die nicht mehr unterstützten. Ältere Versionen (z. B. 9.3_p2) haben den Upstream-Commit als `pw.patch` bekommen. Geprüft am 06.11. in den `APKBUILD`-Dateien der aports-Branches:

| Branch | gefixt in `openssh` |
| --- | --- |
| edge | 10.6_p2-r0 |
| 3.24 | 10.3_p1-r2 |
| 3.23 | 10.2_p1-r1 |
| 3.22 | 10.0_p1-r11 |
| 3.21 | 9.9_p2-r1 |
| 3.20 | 9.7_p1-r6 |
| 3.19 | 9.6_p1-r3 |
| 3.18 | 9.3_p2-r4 |
| 3.17 | 9.1_p1-r7 |
| 3.16 | 9.0_p1-r6 |
| 3.15 und älter | kein Fix |

Wichtig für Scanner: Die `secfixes`-Liste im APKBUILD (Grundlage der Alpine-secdb) enthält CVE-2026-123158 am 06.11. noch nicht. Trivy, Grype und andere Scanner, die die secdb auswerten, melden die Lücke deshalb unter Umständen noch nicht. Bis dahin hilft nur ein Versionsvergleich mit der Tabelle.

### OpenWrt (Feed `packages`)

| Branch | `openssh-server` | Status |
| --- | --- | --- |
| master | 10.6_p2-1 | gefixt |
| openwrt-25.12 | 10.6_p2-1 | gefixt |
| openwrt-24.10 | 9.9_p2-2 | gefixt (Backport `0001-avoid-password-authn-bypass.patch`) |
| openwrt-23.05 | 9.8p1-2 | gefixt (Backport) |

OpenWrts Standard-`/etc/shadow` hat `*` bei `daemon`, `network` und `nobody` (Shell `/bin/false`). Erst wenn root ein Passwort mit `$5$`/`$6$`-Hash bekommt, ist Bedingung 5 erfüllt.

## Prüfen

Ist der sshd verwundbar? Auf dem Host bzw. im Container:

```sh
# 1. musl?
ldd --version 2>&1 | head -1            # "musl libc" → musl

# 2. Paketversion (Alpine) mit der Tabelle oben vergleichen
apk info -v openssh-server openssh-server-pam 2>/dev/null

# 3. Effektive sshd-Konfiguration
sshd -T | grep -Ei '^(usepam|passwordauthentication|permitrootlogin|allowusers|denyusers) '

# 4. Accounts mit "*" und Accounts mit $5$/$6$-Hash
awk -F: '$2=="*"{print "STERN:", $1} $2 ~ /^\$[56]\$/ {print "HASH: ", $1}' /etc/shadow
```

Verwundbar, wenn: musl, Paket älter als die gefixte Version, `usepam no`, `passwordauthentication yes`, mindestens ein `STERN`-Account, der sich anmelden darf, und mindestens ein `HASH`-Account.

Spuren eines Angriffs:

```sh
grep "Accepted password" /var/log/messages /var/log/auth.log 2>/dev/null
```

Ein `Accepted password` für einen Account mit `*` in `/etc/shadow` ist ein starker Hinweis, denn solche Accounts haben kein Passwort. Die Passwortlänge steht nicht im Log.

## Gegenmaßnahmen

1. **Patchen:** `apk upgrade -U -a` und danach `rc-service sshd restart`. Das Paket-Update allein ersetzt den laufenden Daemon nicht.
2. **Container- und Cloud-Images neu bauen**, die auf Alpine basieren und einen sshd enthalten. Ein laufender Container bekommt den Fix nicht durch ein neues Basisimage.
3. **Sofort, falls Patchen nicht geht:** Key-Login testen, eine Sitzung offen lassen, dann Passwort-Login abschalten:

   ```sh
   echo "PasswordAuthentication no" > /etc/ssh/sshd_config.d/00-sshhole.conf
   rc-service sshd restart
   ```

   Die Datei muss alphabetisch vor anderen Drop-ins liegen, weil bei sshd der erste Treffer gilt. Mit `sshd -T | grep passwordauthentication` prüfen.
4. **Härten:** nur Public-Key-Auth, SSH nicht ins Internet exponieren, `AllowUsers` setzen.

## Quellen

- [OpenSSH Release Notes 10.6p2](https://www.openssh.org/releasenotes.html)
- [sshhole.com](https://sshhole.com) (Entdecker, Hintergrund und Zeitleiste)
- [BleepingComputer: OpenSSH flaw lets attackers log into password-disabled Linux accounts](https://www.bleepingcomputer.com/news/security/openssh-flaw-lets-attackers-log-into-password-disabled-linux-accounts/)
- [OX Security: CVE-2026-123158](https://www.ox.security/blog/openssh-authentication-bypass-cve-2026-123158/)
- [IONIX Threat Center: CVE-2026-123158](https://www.ionix.io/threat-center/cve-2026-123158/)
- [Threat Landscape: sshhole on Alpine and OpenWrt](https://threatlandscape.io/blog/openssh-musl-linux-arbitrary-long-passwords-locked-accounts)
- Alpine aports, `main/openssh/APKBUILD` und `pw.patch` in den Branches `master` bis `3.16-stable`
- OpenWrt packages, `net/openssh/Makefile` in `master`, `openwrt-25.12`, `openwrt-24.10`, `openwrt-23.05`
- Gitea `Dockerfile` und `docker/root/etc/templates/sshd_config`, Forgejo `Dockerfile`
