# scan-proxy.py

Stand: 24.10.2026

## Worum es geht

`scan-proxy.py` listet alle Proxy-Einstellungen auf, die ein Linux-System für den aktuellen Benutzer kennt. Das Skript liest Umgebungsvariablen und rund 20 Konfigurationsdateien von Shell, Paketmanagern, Build-Tools, Docker und systemd. Es ändert nichts am System, braucht keine Root-Rechte und nutzt nur die Python-Standardbibliothek.

Typische Fragen, die es beantwortet:

- Warum geht `curl` über den Proxy, `pip` aber nicht?
- Hat der CI-Runner oder Build-Container überhaupt einen Proxy gesetzt?
- Hängt auf diesem Server noch ein alter Proxy-Eintrag in einer Datei, an die niemand mehr denkt?

## Aufruf

```bash
python3 scan-proxy.py

# Nur das Ergebnis
python3 scan-proxy.py | grep '^RESULT:'

# Auf einem entfernten Host, ohne das Skript dort abzulegen
ssh server01 'python3 -' < scan-proxy.py
```

Es gibt keine Kommandozeilenargumente.

Das Skript sieht die Welt aus Sicht des Benutzers, der es startet. `~` zeigt auf dessen Home, und `ENV` sind die Variablen dieses Prozesses. Unter `sudo` fehlen meist die Proxy-Variablen des aufrufenden Benutzers, und statt `~/.bashrc` liest es `/root/.bashrc`. Wer wissen will, was ein Dienstbenutzer sieht, startet das Skript als dieser Benutzer:

```bash
sudo -u jenkins -i python3 /pfad/zu/scan-proxy.py
```

`./ansible.cfg` liest es relativ zum aktuellen Verzeichnis. Für ein Ansible-Projekt also im Projektordner starten.

## Ausgabe und Exit-Code

```text
=== PROXY SCAN REPORT: build01 ===
RESULT: PROXY_FOUND
SOURCE=/etc/apt/apt.conf.d/95proxy KEY=Acquire::http::Proxy VALUE=http://proxy.corp.example:3128
SOURCE=/etc/systemd/system/docker.service.d/http-proxy.conf KEY=HTTPS_PROXY VALUE=http://proxy.corp.example:3128
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
| `NO_PROXY_FOUND` | 0 | Kein Proxy, höchstens Ausnahmelisten |

Exit-Code 1 bedeutet hier "Proxy gefunden", nicht "Fehler". In Skripten mit `set -e` und in CI-Jobs bricht der Aufruf sonst ab. Dort `|| true` anhängen oder das `RESULT:` auswerten. Ansibles `script`-Modul meldet den Host aus demselben Grund als `failed`.

Ausnahmelisten zählen nicht als Proxy. `no_proxy`, `NO_PROXY`, `noproxy` (npm), `no-proxy` und Mavens `nonProxyHosts` tauchen in der Liste auf, lösen aber allein kein `PROXY_FOUND` aus.

## Was der Scanner liest

| Bereich | Dateien / Quelle | Schlüssel |
| --- | --- | --- |
| Prozess-Umgebung | `os.environ` | `http_proxy`, `https_proxy`, `ftp_proxy`, `all_proxy`, `no_proxy`, jeweils klein und groß |
| System-Shell | `/etc/environment`, `/etc/profile`, `/etc/bashrc`, `/etc/bash.bashrc`, `/etc/sysconfig/proxy`, `/etc/profile.d/*.sh`, `/etc/environment.d/*.conf` | wie Umgebung, auch mit `export` davor |
| csh / tcsh | `/etc/profile.d/*.csh` | wie Umgebung, als `setenv NAME wert` |
| Benutzer-Shell | `~/.bashrc`, `~/.bash_profile`, `~/.profile` | wie Umgebung |
| yum / dnf | `/etc/yum.conf`, `/etc/dnf/dnf.conf` | `proxy`, `proxy_username`, `proxy_password` |
| apt | `/etc/apt/apt.conf`, `/etc/apt/apt.conf.d/*` | `Acquire::http::Proxy`, `Acquire::https::Proxy` |
| wget | `/etc/wgetrc`, `~/.wgetrc` | `http_proxy`, `https_proxy`, `ftp_proxy`, `no_proxy` |
| curl | `/etc/curlrc`, `~/.curlrc` | `proxy = …` |
| git | `/etc/gitconfig`, `~/.gitconfig` | `proxy = …` in jeder Sektion |
| npm | `/etc/npmrc`, `~/.npmrc` | `proxy`, `https-proxy`, `noproxy` |
| pip | `/etc/pip.conf`, `~/.pip/pip.conf`, `~/.config/pip/pip.conf` | `proxy` |
| Maven | `~/.m2/settings.xml`, `/etc/maven/settings.xml`, `/usr/share/maven/conf/settings.xml`, `/usr/local/maven/conf/settings.xml`, `$MAVEN_HOME/conf/settings.xml`, `$M2_HOME/conf/settings.xml` | `<proxies>/<proxy>`: host, port, protocol, username, nonProxyHosts |
| Ansible | `/etc/ansible/ansible.cfg`, `~/.ansible.cfg`, `./ansible.cfg` | `http_proxy`, `https_proxy`, `ftp_proxy`, `no_proxy`, `proxy` |
| Docker-Client | `~/.docker/config.json` | `proxies.<kontext>`: `httpProxy`, `httpsProxy`, `ftpProxy`, `noProxy` |
| systemd | `/etc/systemd/system/*.service.d/*.conf`, `/etc/systemd/system.conf.d/*.conf`, `~/.config/systemd/user/*.service.d/*.conf` | `Environment="HTTP_PROXY=…"` usw. |

Welche Regel greift, hängt am Dateinamen. Endet der Pfad auf `yum.conf`, `dnf.conf`, `wgetrc`, `curlrc`, `gitconfig`, `npmrc`, `pip.conf`, `pip.ini`, `ansible.cfg` oder `.csh`, nimmt der Scanner das Muster des jeweiligen Tools. Alles andere liest er wie eine Shell-Datei. Jede Datei liest er nur einmal, auch wenn sie in mehreren Listen steht.

Für den Docker-Daemon ist der systemd-Drop-in die wichtige Stelle. Die übliche Anleitung legt den Proxy in `/etc/systemd/system/docker.service.d/http-proxy.conf` ab, und genau dort sucht der Scanner. `~/.docker/config.json` betrifft dagegen nur die Proxy-Variablen, die der Docker-Client in Container und Builds durchreicht.

## Wie Maven bewertet wird

Maven nutzt einen `<proxy>`-Eintrag, solange `<active>` fehlt oder `true` ist. Der Scanner macht es genauso. Ein Eintrag mit `<active>false</active>` taucht nicht auf. Das ist Absicht, denn viele `settings.xml` enthalten deaktivierte Beispiel-Proxys. `<password>` gibt der Scanner nie aus.

## Zugangsdaten in der Ausgabe

Der Scanner gibt Werte unverändert aus. Steckt ein Passwort in der Proxy-URL (`http://user:pass@proxy:3128`) oder in `proxy_password` von yum/dnf, steht es im Klartext im Report. Vor dem Weitergeben in Tickets oder Chats schwärzen:

```bash
python3 scan-proxy.py | sed -E 's#//[^/@ ]+@#//***@#; s#(KEY=proxy_password VALUE=).*#\1***#'
```

Ein Proxy-Passwort in `/etc/environment` oder `/etc/profile.d/` ist für jeden Benutzer auf dem System lesbar. Findet der Scanner so etwas, ist das ein eigener Befund.

## Grenzen

Der Scanner liest Dateien Zeile für Zeile mit regulären Ausdrücken. Er führt keine Shell-Skripte aus und versteht keine Konfigurationssyntax. Daraus folgen ein paar blinde Flecken:

- Variablen wertet er nicht aus. Bei `export https_proxy=$http_proxy` steht `$http_proxy` als Wert im Report.
- Auskommentierte Zeilen ignoriert er, Bedingungen nicht. Ein `export http_proxy=…` innerhalb eines `if` zählt immer.
- In curlrc erkennt er nur `proxy = …`. Die Schreibweisen `proxy …`, `proxy: …`, `-x …` und `--proxy …` erkennt er nicht.
- `use_proxy = off` in wgetrc beachtet er nicht. Der Proxy steht trotzdem im Report.
- In apt-Konfiguration zählt auch `Acquire::http::Proxy "DIRECT";` als Proxy. Host-spezifische Einträge wie `Acquire::http::Proxy::repo.example "…";` erkennt er nicht.
- In systemd erkennt er nur `Environment=`. `DefaultEnvironment=` in `system.conf.d` erkennt er nicht. Stehen mehrere Variablen in einer `Environment=`-Zeile, landen alle im Wert der ersten.
- Unit-Dateien selbst (`/etc/systemd/system/*.service`, `/lib/systemd/system/`) liest er nicht, nur Drop-ins.

Gar nicht abgedeckt sind:

- Java-Systemproperties (`-Dhttp.proxyHost` in `JAVA_TOOL_OPTIONS`, `MAVEN_OPTS` oder Startskripten) und Gradle (`~/.gradle/gradle.properties`)
- `/etc/docker/daemon.json`, Podman (`containers.conf`) und containerd
- yarn (`.yarnrc`, `.yarnrc.yml`), conda (`.condarc`) und weitere Paketmanager
- Desktop-Einstellungen (GNOME, KDE), PAC-Dateien und WPAD
- transparente Proxys per iptables/nftables oder Netzwerk-Gateway

Ein `NO_PROXY_FOUND` heißt also nur, dass in den oben gelisteten Quellen nichts steht. Ob der Traffic tatsächlich direkt rausgeht, zeigt erst ein Test wie `curl -v https://example.com`.

## Tests

```bash
uv run pytest tests/test_scan_proxy.py
```

Die Tests decken alle Muster, das Routing nach Dateinamen, die Maven-`active`-Logik, Docker-`config.json` und den Exit-Code ab.
