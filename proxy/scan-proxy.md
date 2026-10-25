# scan-proxy.py

Stand: 25.10.2026

## Worum es geht

`scan-proxy.py` listet alle Proxy-Einstellungen auf, die ein Linux-System für den aktuellen Benutzer kennt. Das Skript liest Umgebungsvariablen und rund 70 Konfigurationspfade von Shell, Paketmanagern, Build-Tools, Docker, Podman und systemd. Es ändert nichts am System, braucht keine Root-Rechte und nutzt nur die Python-Standardbibliothek.

Typische Fragen, die es beantwortet:

- Warum geht `curl` über den Proxy, `pip` aber nicht?
- Hat der CI-Runner oder Build-Container überhaupt einen Proxy gesetzt?
- Hängt auf diesem Server noch ein alter Proxy-Eintrag in einer Datei, an die niemand mehr denkt?

## Distributionen und Python-Version

Das Skript läuft ab Python 3.6 und deckt die Pfade von Ubuntu, Debian, RHEL, CentOS und den RHEL-Klonen (Rocky, Alma) ab. Getestet ist es auf Rocky Linux 8 und 9, Debian 12 und Ubuntu 24.04.

| System | Python-Aufruf | Hinweis |
| --- | --- | --- |
| CentOS 7 / RHEL 7 | `python3` | Nicht vorinstalliert, `yum install python3` bringt 3.6. `python` ist dort Python 2 und funktioniert nicht. |
| RHEL / CentOS Stream / Rocky / Alma 8 | `python3` oder `/usr/libexec/platform-python` | `platform-python` (3.6) ist immer da, auch wenn `python3` fehlt. |
| RHEL / CentOS Stream / Rocky / Alma 9 und 10 | `python3` | vorinstalliert |
| Debian 11+, Ubuntu 20.04+ | `python3` | Auf Servern vorhanden. In schlanken Container-Images fehlt es, dort `apt-get install python3-minimal`. |

Was der Scanner je Distribution zusätzlich liest:

- **Debian / Ubuntu:** apt (`/etc/apt/apt.conf`, `apt.conf.d/`), `/etc/bash.bashrc`, `/etc/zsh/*`, `/etc/default/docker`, `/etc/xdg/pip/pip.conf`
- **RHEL / CentOS:** yum und dnf inklusive der Repo-Dateien in `/etc/yum.repos.d/`, subscription-manager (`/etc/rhsm/rhsm.conf`), `/etc/bashrc`, `/etc/zshenv` usw., `/etc/sysconfig/docker` (Docker aus den CentOS-7-Repos) und Podman (`containers.conf`)

Ab RHEL/CentOS 8 ist `/etc/yum.conf` ein Symlink auf `/etc/dnf/dnf.conf`. Der Scanner liest jede Datei nur einmal, auch über Symlinks. Der Eintrag erscheint deshalb nur einmal, unter `/etc/yum.conf`.

## Aufruf

Aus dem Repository-Root:

```bash
python3 proxy/scan-proxy.py

# Nur das Ergebnis
python3 proxy/scan-proxy.py | grep '^RESULT:'

# Auf einem entfernten Host, ohne das Skript dort abzulegen
ssh server01 'python3 -' < proxy/scan-proxy.py

# RHEL 8 ohne installiertes python3
ssh rhel8 '/usr/libexec/platform-python -' < proxy/scan-proxy.py
```

Es gibt keine Kommandozeilenargumente.

Das Skript sieht die Welt aus Sicht des Benutzers, der es startet. `~` zeigt auf dessen Home, und `ENV` sind die Variablen dieses Prozesses. Unter `sudo` fehlen meist die Proxy-Variablen des aufrufenden Benutzers, und statt `~/.bashrc` liest es `/root/.bashrc`. Wer wissen will, was ein Dienstbenutzer sieht, startet das Skript als dieser Benutzer:

```bash
sudo -u jenkins -i python3 /pfad/zu/proxy/scan-proxy.py
```

`./ansible.cfg` liest es relativ zum aktuellen Verzeichnis. Für ein Ansible-Projekt also im Projektordner starten.

## Ausgabe und Exit-Code

```text
=== PROXY SCAN REPORT: build01 ===
RESULT: PROXY_FOUND
SOURCE=/etc/apt/apt.conf.d/95proxy KEY=Acquire::http::Proxy VALUE=http://proxy.corp.example:3128
SOURCE=/etc/apt/apt.conf.d/95proxy KEY=Acquire::http::Proxy::deb.corp.example VALUE=DIRECT
SOURCE=/etc/systemd/system/docker.service.d/http-proxy.conf KEY=HTTPS_PROXY VALUE=http://proxy.corp.example:3128
SOURCE=/etc/systemd/system/docker.service.d/http-proxy.conf KEY=NO_PROXY VALUE=localhost,.corp.example
SOURCE=/home/ci/.m2/settings.xml KEY=proxy.host VALUE=proxy.corp.example
SOURCE=/home/ci/.m2/settings.xml KEY=proxy.nonProxyHosts VALUE=localhost|*.corp.example
SOURCE=/home/ci/.m2/settings.xml KEY=proxy.port VALUE=3128
SOURCE=ENV KEY=NO_PROXY VALUE=localhost,127.0.0.1,.corp.example
SOURCE=ENV KEY=https_proxy VALUE=http://proxy.corp.example:3128
```

Die Zeilen sind nach Quelle und Schlüssel sortiert. Ohne Treffer kommen nur Kopfzeile und `RESULT: NO_PROXY_FOUND`.

| RESULT | Exit-Code | Bedeutung |
| --- | --- | --- |
| `PROXY_FOUND` | 1 | Mindestens ein echter Proxy-Eintrag gefunden |
| `NO_PROXY_FOUND` | 0 | Kein Proxy, höchstens Ausnahmelisten oder abgeschaltete Einträge |

Exit-Code 1 bedeutet hier "Proxy gefunden", nicht "Fehler". In Skripten mit `set -e` und in CI-Jobs bricht der Aufruf sonst ab. Dort `|| true` anhängen oder das `RESULT:` auswerten. Ansibles `script`-Modul meldet den Host aus demselben Grund als `failed`.

Manche Einträge stehen im Report, lösen allein aber kein `PROXY_FOUND` aus:

- **Ausnahmelisten:** `no_proxy`, `NO_PROXY`, `noproxy` (npm, curl), `no-proxy` (Docker) und Mavens `nonProxyHosts`
- **Abgeschaltete Proxys:** der Wert `_none_` (yum/dnf, typisch in einer `.repo`-Datei für ein internes Repository) und `DIRECT` (apt, typisch als `Acquire::http::Proxy::<host> "DIRECT";`)

## Was der Scanner liest

| Bereich | Dateien / Quelle | Schlüssel |
| --- | --- | --- |
| Prozess-Umgebung | `os.environ` | `http_proxy`, `https_proxy`, `ftp_proxy`, `all_proxy`, `no_proxy`, jeweils klein und groß |
| System-Shell (bash, sh) | `/etc/environment`, `/etc/profile`, `/etc/bashrc` (RHEL), `/etc/bash.bashrc` (Debian), `/etc/profile.d/*.sh`, `/etc/sysconfig/proxy` | wie Umgebung, auch mit `export` davor |
| System-Shell (zsh) | `/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc` (RHEL), `/etc/zsh/zshenv`, `/etc/zsh/zprofile`, `/etc/zsh/zshrc` (Debian) | wie Umgebung |
| csh / tcsh | `/etc/profile.d/*.csh`, `/etc/csh.cshrc`, `/etc/csh.login`, `~/.cshrc`, `~/.tcshrc` | wie Umgebung, als `setenv NAME wert` |
| Benutzer-Shell | `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.profile`, `~/.zshenv`, `~/.zprofile`, `~/.zshrc` | wie Umgebung |
| systemd-Umgebung | `/etc/environment.d/*.conf`, `~/.config/environment.d/*.conf` | wie Umgebung |
| yum / dnf | `/etc/yum.conf`, `/etc/dnf/dnf.conf`, `/etc/yum.repos.d/*.repo` | `proxy`, `proxy_username`, `proxy_password` |
| subscription-manager | `/etc/rhsm/rhsm.conf` | `proxy_hostname`, `proxy_port`, `proxy_user`, `proxy_password`, `no_proxy` |
| apt | `/etc/apt/apt.conf`, `/etc/apt/apt.conf.d/*` | `Acquire::{http,https,ftp}::Proxy`, auch host-spezifisch (`…::Proxy::<host>`) und `…::Proxy-Auto-Detect` |
| wget | `/etc/wgetrc`, `~/.wgetrc` | `http_proxy`, `https_proxy`, `ftp_proxy`, `no_proxy` |
| curl | `/etc/curlrc`, `~/.curlrc`, `~/.config/.curlrc` | `proxy`, `noproxy`, `-x` in allen Schreibweisen (`proxy = …`, `proxy …`, `proxy: …`, `--proxy …`) |
| git | `/etc/gitconfig`, `~/.gitconfig`, `~/.config/git/config` | `proxy = …` in jeder Sektion |
| npm | `/etc/npmrc`, `~/.npmrc` | `proxy`, `https-proxy`, `noproxy` |
| pip | `/etc/pip.conf`, `/etc/xdg/pip/pip.conf`, `~/.pip/pip.conf`, `~/.config/pip/pip.conf` | `proxy` |
| Maven | `~/.m2/settings.xml`, `/etc/maven/settings.xml`, `/usr/share/maven/conf/settings.xml`, `/usr/local/maven/conf/settings.xml`, `$MAVEN_HOME/conf/settings.xml`, `$M2_HOME/conf/settings.xml` | `<proxies>/<proxy>`: host, port, protocol, username, nonProxyHosts |
| Ansible | `/etc/ansible/ansible.cfg`, `~/.ansible.cfg`, `./ansible.cfg` | `http_proxy`, `https_proxy`, `ftp_proxy`, `no_proxy`, `proxy` |
| Docker-Client | `~/.docker/config.json` | `proxies.<kontext>`: `httpProxy`, `httpsProxy`, `ftpProxy`, `noProxy` |
| Docker-Daemon | `/etc/docker/daemon.json` | `proxies`: `http-proxy`, `https-proxy`, `no-proxy` (ab Docker 23) |
| Docker-Daemon (alt) | `/etc/sysconfig/docker` (CentOS 7), `/etc/default/docker` (Debian/Ubuntu) | wie Umgebung |
| Podman / Buildah | `/usr/share/containers/containers.conf`, `/etc/containers/containers.conf`, `/etc/containers/containers.conf.d/*.conf`, `~/.config/containers/containers.conf`, `~/.config/containers/containers.conf.d/*.conf` | Proxy-Variablen in `env = ["…"]` |
| systemd | `/etc/systemd/system.conf`, `/etc/systemd/user.conf`, `/etc/systemd/system.conf.d/*.conf`, `/etc/systemd/user.conf.d/*.conf`, `/etc/systemd/system/*.service`, `/etc/systemd/system/*.service.d/*.conf`, `/etc/systemd/user/*.service.d/*.conf`, `~/.config/systemd/user/*.service.d/*.conf` | `Environment=` und `DefaultEnvironment=`, auch mehrere Variablen pro Zeile |

Welche Regel greift, hängt am Dateinamen. Endet der Pfad auf `yum.conf`, `dnf.conf`, `.repo`, `rhsm.conf`, `wgetrc`, `curlrc`, `gitconfig`, `git/config`, `npmrc`, `pip.conf`, `pip.ini`, `ansible.cfg` oder auf eine csh-Datei (`.csh`, `.cshrc`, `.tcshrc`, `csh.login`), nimmt der Scanner das Muster des jeweiligen Tools. Alles andere aus der Shell-Gruppe liest er wie eine Shell-Datei. Jede Datei liest er nur einmal, auch wenn sie in mehreren Listen steht oder per Symlink zweimal erreichbar ist.

Für den Docker-Daemon gibt es drei Stellen. Die übliche Anleitung legt den Proxy in `/etc/systemd/system/docker.service.d/http-proxy.conf` ab. Seit Docker 23 geht das auch in `/etc/docker/daemon.json`. Das Docker-Paket aus den CentOS-7-Repos liest zusätzlich `/etc/sysconfig/docker`. `~/.docker/config.json` betrifft dagegen nur die Proxy-Variablen, die der Docker-Client in Container und Builds durchreicht.

Bei Podman zählt nur `env = [...]` in `containers.conf`. Die Option `http_proxy = true` sagt nur, dass Podman die Proxy-Variablen des Hosts an Container weiterreicht. Der Scanner ignoriert sie.

subscription-manager auf RHEL hat einen eigenen Proxy für die Registrierung und den Zugriff auf das Red Hat CDN. `rhsm.conf` enthält ab Werk `proxy_scheme = http`. Diesen Schlüssel liest der Scanner deshalb nicht, sonst wäre jedes RHEL-System ein Treffer.

## Wie Maven bewertet wird

Maven nutzt einen `<proxy>`-Eintrag, solange `<active>` fehlt oder `true` ist. Der Scanner macht es genauso. Ein Eintrag mit `<active>false</active>` taucht nicht auf. Das ist Absicht, denn viele `settings.xml` enthalten deaktivierte Beispiel-Proxys. `<password>` gibt der Scanner nie aus.

## Zugangsdaten in der Ausgabe

Der Scanner gibt Werte unverändert aus. Steckt ein Passwort in der Proxy-URL (`http://user:pass@proxy:3128`) oder in `proxy_password` von yum/dnf bzw. subscription-manager, steht es im Klartext im Report. Vor dem Weitergeben in Tickets oder Chats schwärzen:

```bash
python3 proxy/scan-proxy.py | sed -E 's#//[^/@ ]+@#//***@#; s#(KEY=proxy_password VALUE=).*#\1***#'
```

Ein Proxy-Passwort in `/etc/environment` oder `/etc/profile.d/` ist für jeden Benutzer auf dem System lesbar. Findet der Scanner so etwas, ist das ein eigener Befund.

## Grenzen

Der Scanner liest Dateien Zeile für Zeile mit regulären Ausdrücken. Er führt keine Shell-Skripte aus und versteht keine Konfigurationssyntax. Daraus folgen ein paar blinde Flecken:

- Variablen wertet er nicht aus. Bei `export https_proxy=$http_proxy` steht `$http_proxy` als Wert im Report.
- Auskommentierte Zeilen ignoriert er, Bedingungen nicht. Ein `export http_proxy=…` innerhalb eines `if` zählt immer.
- `use_proxy = off` in wgetrc beachtet er nicht. Der Proxy steht trotzdem im Report.
- In apt-Konfiguration erkennt er nur die einzeilige Schreibweise `Acquire::http::Proxy "…";`. Die Blockschreibweise `Acquire { http { Proxy "…"; }; };` erkennt er nicht.
- `EnvironmentFile=` in systemd-Units verfolgt er nicht. Unit-Dateien unter `/lib/systemd/system/` und `/usr/lib/systemd/system/` liest er nicht, nur Units und Drop-ins unter `/etc/systemd/`.
- Bei yum/dnf zählt jeder `proxy=`-Eintrag, egal in welcher Sektion. Ein Repo mit `enabled=0` und Proxy löst trotzdem `PROXY_FOUND` aus.

Gar nicht abgedeckt sind:

- Java-Systemproperties (`-Dhttp.proxyHost` in `JAVA_TOOL_OPTIONS`, `MAVEN_OPTS` oder Startskripten) und Gradle (`~/.gradle/gradle.properties`)
- snapd auf Ubuntu. Den Proxy für Snaps zeigt `snap get system proxy`.
- RHN Classic auf RHEL/CentOS 7 (`/etc/sysconfig/rhn/up2date`) und containerd
- PAM-Umgebung (`/etc/security/pam_env.conf`, `~/.pam_environment`)
- yarn (`.yarnrc`, `.yarnrc.yml`), conda (`.condarc`) und weitere Paketmanager
- Desktop-Einstellungen (GNOME, KDE), PAC-Dateien und WPAD
- transparente Proxys per iptables/nftables oder Netzwerk-Gateway

Ein `NO_PROXY_FOUND` heißt also nur, dass in den oben gelisteten Quellen nichts steht. Ob der Traffic tatsächlich direkt rausgeht, zeigt erst ein Test wie `curl -v https://example.com`.

## Tests

```bash
uv run pytest tests/test_scan_proxy.py
```

Die Tests decken alle Muster ab, dazu das Routing nach Dateinamen, die Maven-`active`-Logik, apt (Kommentare, host-spezifische Einträge, `DIRECT`), systemd mit mehreren Variablen pro Zeile, Podman, Docker-`config.json` und `daemon.json`, das einmalige Lesen von Symlinks und den Exit-Code.
