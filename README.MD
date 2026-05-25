# scan-tools

Eine Sammlung einfacher Security-Scanner für Git-Repositories, Node.js-Projekte und Linux-Systeme. Alle Tools sind eigenständige Python-Skripte ohne externe Abhängigkeiten (Standardbibliothek genügt) und liefern strukturierte Berichte als Text oder JSON.

**Zielgruppe:** Entwickler, DevSecOps-Teams und Security-Analysten, die externe Endpunkte, Supply-Chain-Risiken und Proxy-Konfigurationen automatisiert prüfen möchten.

**Sprache / Laufzeit:** Python 3.11+  
**Paketmanager:** [uv](https://github.com/astral-sh/uv) (`pyproject.toml` vorhanden)

---

## Übersicht

| Tool | Zweck |
| ------ | ------- |
| [`scan-external-urls.py`](#1-scan-external-urlspy) | URLs, E-Mails, Hostnamen und IPs im Git-Repository aufspüren |
| [`scan-npm.py`](#2-scan-npmpy) | JS/NPM-Trojaner und Supply-Chain-Angriffe erkennen |
| [`scan-proxy.py`](#3-scan-proxypy) | Alle Proxy-Konfigurationen eines Systems inventarisieren |
| [`scan-secrets.py`](#4-scan-secretspy) | Credentials und Secrets im Git-Repository aufspüren |
| [`whitelist.json`](#5-whitelistjson) | Erlaubte Hosts/IPs/Domains für den URL-Scanner |
| [`test_scan_npm.py`](#6-test_scan_npmpy) | Unit-Tests für den NPM-Scanner (pytest / unittest) |
| [`testproject.sh`](#7-testprojectsh) | Test-Fixture, das alle NPM-Scanner-Regeln triggert |

---

## 1. `scan-external-urls.py`

### Zweck

Scannt ein komplettes Git-Repository nach externen Referenzen, die in Produktions- oder Testcode nichts verloren haben: URLs, E-Mail-Adressen, Hostnamen und IP-Adressen. Das Ziel ist es, unbeabsichtigte Datenabflüsse, hartcodierte Endpunkte und versehentlich committete persönliche Daten zu finden.

### Einsatzgebiet

- **CI/CD-Pipelines** — vor jedem Merge prüfen, ob neue externe Abhängigkeiten eingebracht wurden
- **Code-Reviews** — schnell einen Überblick verschaffen, welche Domains und IPs ein Repository kennt
- **Compliance-Audits** — sicherstellen, dass keine personenbezogenen Daten (E-Mails) im Code liegen
- **Infrastructure-as-Code** — Ansible-, Terraform- und Kubernetes-Manifeste auf unerwünschte externe Endpunkte prüfen

### Erkannte Kategorien

| Kategorie | Beschreibung | Beispiel |
| ----------- | ------------- | --------- |
| `url` | HTTP/HTTPS-URLs | `https://api.example.com/v2/data` |
| `email` | E-Mail-Adressen | `admin@company.com` |
| `hostname` | Vollqualifizierte Hostnamen mit bekannten TLDs | `internal.corp.io` |
| `ip` | IPv4-Adressen | `10.0.5.12` |

### Besonderheiten

- Nutzt `git ls-files` — prüft nur versionskontrollierte Dateien, respektiert `.gitignore`
- Binäre Dateien (Null-Byte-Erkennung) und Binär-Extensions (`.png`, `.jar`, `.lock` usw.) werden übersprungen
- **TLD-Allowlist**: Hostnamen werden nur gemeldet, wenn ihre TLD in einer kuratierten Liste bekannter TLDs steht — Python-Methodenaufrufe (`os.path`, `subprocess.run`) oder Java-Paketnamen werden dadurch nicht fälschlicherweise erkannt
- **Intelligente Ausschlusslogik**: Import-Statements (`from textual.app import`), Kubernetes-API-Groups (`rbac.authorization.k8s.io/`), YAML-Listenelemente und Dateipfad-Komponenten werden nicht als Hostnamen gewertet
- **Whitelist-System** (`whitelist.json`): IP-Ranges (CIDR), Hostnamen (Wildcard `*.domain.com`) und E-Mail-Domains können dauerhaft erlaubt werden — die Datei wird automatisch geladen

### Verwendung

```bash
# Aktuelles Repository scannen (alle Kategorien)
python3 scan-external-urls.py

# Bestimmten Pfad scannen
python3 scan-external-urls.py /pfad/zum/repo

# Nur URLs und E-Mails, JSON-Ausgabe für CI
python3 scan-external-urls.py --categories url email --format json

# Testdateien überspringen, interne Domain erlauben
python3 scan-external-urls.py --skip-tests --allow "mycompany\\.com"

# Alle IP-Adressen ignorieren (z. B. Ansible/Infrastruktur-Repos)
python3 scan-external-urls.py --ignore-all-ips

# Bestimmte IPs ignorieren
python3 scan-external-urls.py --ignore-ips 192.168.1.1 10.0.0.1

# IPs aus Datei ignorieren (eine pro Zeile)
python3 scan-external-urls.py --ignore-ips-file .scan-ignore-ips

# Externe Whitelist-Datei laden
python3 scan-external-urls.py --whitelist custom-whitelist.json

# Erlaubmuster aus Datei laden (ein Regex pro Zeile)
python3 scan-external-urls.py --allow-file .scan-allowlist

# Pfade überspringen (Regex)
python3 scan-external-urls.py --skip "docs/" "fixtures/"

# Bei Befunden nicht fehlschlagen (für Reporting ohne CI-Abbruch)
python3 scan-external-urls.py --no-fail
```

### Exit-Codes

| Code | Bedeutung |
| ------ | ----------- |
| `0` | Keine Befunde (oder `--no-fail` gesetzt) |
| `1` | Befunde gefunden |
| `2` | Skriptfehler (kein Git-Repo, ungültige Argumente) |

---

## 2. `scan-npm.py`

### NPM Funktion

Scannt Node.js-Projekte auf Indikatoren für bekannte JavaScript-Trojaner und Supply-Chain-Angriffe. Der Scanner erkennt sowohl Konfigurations-Level-Probleme (verdächtige `package.json`-Hooks) als auch Code-Level-Bedrohungen (Verschleierung, Exfiltration, Reverse Shells) direkt in JS/TS-Quelldateien. Optional kann er auch den lokalen npm-Cache auf kompromittierte Pakete prüfen.

### NPM Einsatzgebiet

- **Abhängigkeits-Audits** — vor dem Einbinden fremder npm-Pakete deren Code auf Schadsoftware prüfen
- **Supply-Chain-Security** — erkennen, ob ein Paket über einen Nicht-Standard-Registry-Mirror installiert wird
- **Entwickler-Workstations** — den lokalen npm-Cache auf kompromittierte Pakete untersuchen (`--scan-cache`)
- **Open-Source-Beiträge** — PRs von externen Kontributoren auf eingebrachte Backdoors prüfen
- **Post-Incident-Forensik** — nach einem Sicherheitsvorfall schnell alle JS-Dateien nach bekannten Angriffsvektoren durchsuchen

### Erkannte Bedrohungskategorien

#### `LIFECYCLE_HOOKS_FOUND` (INFO)

Inventarisiert alle npm-Lifecycle-Hooks (`preinstall`, `install`, `postinstall`, `prepare`, `prepack`, `postpack`). Diese Hooks werden bei `npm install` **automatisch ohne Benutzerbestätigung ausgeführt** — jeder Hook ist potenziell ein Angriffspunkt.

#### `INSTALL_SCRIPT` (HIGH / MEDIUM)

Prüft Lifecycle-Hooks auf gefährliche Muster:

- `curl` / `wget` — Download-Vektoren für Payloads (HIGH)
- `netcat` / `nc` / `ncat` — Hinweis auf Reverse Shell (HIGH)
- `eval()` im Shell-Skript (HIGH)
- `base64 --decode` — Verschleierung von Payloads (HIGH)
- `chmod` mit ausführbaren Bits (HIGH)
- `python3 -c` — Inline-Ausführung (HIGH)
- Zugriff auf `/etc/passwd` oder `~/.ssh/` (HIGH)
- Krypto-Mining-Keywords (`stratum+tcp://`, `xmrig`) (HIGH)
- HTTP-Aufrufe an Nicht-NPM-Registries (HIGH)
- `process.env` + HTTP-Aufruf im selben Skript-String (HIGH)
- `node -e` / `node --eval` — Inline-JavaScript-Ausführung (MEDIUM)
- **`binding.gyp`** — bloße Existenz löst MEDIUM aus, da npm automatisch `node-gyp rebuild` triggert (auch ohne `scripts`-Eintrag)
- **`"gypfile": true`** — ebenso ein versteckter Install-Hook (MEDIUM)

#### `OBFUSCATION` (HIGH / MEDIUM / LOW)

Erkennt JavaScript-Verschleierungstechniken:

- `eval(Buffer.from(..., 'base64'))` — klassisches Payload-Delivery-Muster (HIGH)
- Lange Hex-Strings via `Buffer.from(..., 'hex')` (32+ Zeichen) (HIGH)
- Lange Base64-Strings via `Buffer.from(..., 'base64')` (40+ Zeichen) (HIGH)
- `String.fromCharCode(115, 101, ...)` mit 6+ Argumenten — Zeichencode-Verschleierung (HIGH)
- Bracket-Notation mit String-Konkatenation: `obj["ex"+"ec"]` (HIGH)
- `require("child_"+"process")` — verschleierter Modulname (HIGH)
- Zweistufiges Muster: `var cp = 'child_'+'process'; require(cp)` (HIGH)
- `_0x`-Variablennamen — typische Ausgabe von JS-Obfuskatoren (MEDIUM)
- `eval()` eines zusammengesetzten String-Literals (MEDIUM)
- Dynamisches `import()` mit zusammengesetztem Pfad: `import(base + "/mod")` (MEDIUM)
- `unescape()` mit prozentkodierten Sequenzen (LOW)
- Zeilen > 1000 Zeichen — minimierter Code schränkt statische Analyse ein (LOW)

#### `EXFILTRATION` (HIGH / MEDIUM)

Kombinationen, die auf Credential- oder Datendiebstahl hinweisen:

- `process.env` + HTTP-Aufruf auf einer Zeile (HIGH)
- Sensitive Env-Vars (`GITHUB_TOKEN`, `AWS_SECRET`, `NPM_TOKEN`) neben Netzwerkaufrufen (HIGH)
- `readFileSync` auf SSH-Schlüssel-, AWS-, `.npmrc`-Pfaden (HIGH)
- `dns.resolve`/`dns.lookup` mit kodiertem oder `process.env`-basiertem Hostnamen — DNS-Exfiltration (HIGH)
- `dns.resolve`/`dns.lookup` mit dynamisch zusammengesetztem Hostnamen (`+`-Konkatenation) (HIGH)
- `os.homedir()` + `.ssh` / `.aws` (MEDIUM)
- `require('keytar')` — OS-Schlüsselbund-Zugriff (MEDIUM)
- Hardcodierte `_authToken` in `.npmrc`, `.yarnrc`, `.yarnrc.yml`, `pnpm-lock.yaml` (MEDIUM)
- `process.env` in Datei, die auch Netzwerkfunktionen enthält (MEDIUM, kontextsensitiv)
- `dns`-Modul-Import kombiniert mit `process.env` in derselben Datei (MEDIUM, kontextsensitiv)

#### `FILESYSTEM_ATTACK` (HIGH / MEDIUM)

Schreiben in kritische Systemdateien:

- `/etc/passwd`, `/etc/shadow`, `/etc/cron.*` (HIGH)
- `~/.ssh/authorized_keys` — SSH-Backdoor (HIGH)
- `~/.bashrc`, `~/.profile`, `~/.zshrc` — Persistenzmechanismus (MEDIUM)
- Cron-Verzeichnisse (MEDIUM)

#### `REMOTE_EXEC` (HIGH / MEDIUM)

Dynamische Code- und Befehlsausführung:

- `require('child_process').exec/spawn` (HIGH)
- `new Function()` mit Netzwerk-/Dekodierungsinhalt (HIGH)
- TCP-Socket an stdio weitergeleitet — Reverse Shell (HIGH)
- `/bin/sh -i` + Socket/Connect (HIGH)
- Dynamisches `import("https://...")` — direkter Remote-Code-Import (HIGH)
- Dynamisches `import(fetch(...))` / `import(Buffer.from(...))` — verschachtelter Netzwerk-/Decode-Aufruf (HIGH)
- `vm.runInNewContext()` / `vm.runInThisContext()` (MEDIUM)
- Remote-Code-Fetch + `eval` (MEDIUM)

#### `CRYPTOMINING` (HIGH / MEDIUM)

- `stratum+tcp://` — Mining-Protokoll (HIGH)
- Bekannte Miner-Binärnamen: `xmrig`, `xmr-stak`, `cpuminer` (HIGH)
- Bekannte Mining-Dienst-Domains: `coinhive.com`, `cryptoloot.pro` (HIGH)
- Mining-Algorithmusnamen + Mining-Keywords (MEDIUM)

#### `SUPPLY_CHAIN` (HIGH / MEDIUM / LOW)

- `Module._compile()` mit verschlüsseltem Buffer — Event-Stream-Angriffsmuster (HIGH)
- `require.extensions[]` / `Module._extensions[]` — require-Hook-Injektion (HIGH)
- Yarn-Plugins von externen URLs (HIGH)
- Externer IP-Ermittlungsdienst (`ipify.org`, `icanhazip.com` u. a.) — node-ipc-Muster 2022 (HIGH)
- IP-Präfix-Vergleich gegen Zahlenliteral (`ip.startsWith("5.")`) — geografisch bedingte Malware (HIGH)
- IP-Quelle (dns/networkInterfaces/externer Dienst) + destruktive FS-Operation in derselben Datei — node-ipc Co-Occurrence (HIGH)
- Git-URL-Abhängigkeiten in `package.json` (MEDIUM)
- Nicht-Standard-Registry in `.npmrc`, `.yarnrc`, `.yarnrc.yml`, `pnpm-lock.yaml` (MEDIUM)
- Nicht-Standard-resolved-URLs in `package-lock.json` (MEDIUM)
- Fehlender `integrity`-Hash (sha512) in `package-lock.json` — Hinweis auf Lockfile-Manipulation (MEDIUM)
- Nicht-Standard-tarball-URL in `pnpm-lock.yaml` (MEDIUM)
- Native `.node`-Addons — nicht statisch analysierbar (MEDIUM)
- `npm_lifecycle_event` + Netzwerkaufruf (MEDIUM)

### Gescannte Dateitypen

| Datei | Scanner |
| ------- | --------- |
| `package.json` | Lifecycle-Hooks, Git-URLs, gypfile |
| `package-lock.json` | Registry-URLs, fehlende integrity-Hashes (v1 + v2 Format) |
| `pnpm-lock.yaml` / `pnpm-lock.yml` | tarball-URLs, Registry-Overrides, hardcodierte Tokens |
| `binding.gyp` | Impliziter node-gyp Install-Hook + verdächtige Aktionen |
| `.npmrc` / `.npmrc.example` | Registry-Umleitungen, hardcodierte Auth-Tokens |
| `.yarnrc` | Yarn v1 Registry und Token |
| `.yarnrc.yml` / `.yarnrc.yaml` | Yarn v2/v3 Registry, Token, externe Plugin-URLs |
| `*.js`, `*.ts`, `*.cjs`, `*.mjs`, `*.jsx`, `*.tsx` | Alle CODE_THREAT_RULES |
| `*.node` | Native Addons — wird als SUPPLY_CHAIN MEDIUM markiert |

### npm-Cache-Scan

Mit `--scan-cache` wird zusätzlich der lokale npm-Cache (`~/.npm/_cacache/content-v2/`) gescannt. Jeder Blob im Cache ist ein gzip-komprimierter Tarball eines installierten Pakets — der Scanner entpackt diese on-the-fly und wendet alle Prüfungen an, ohne den Cache zu verändern.

### Verwendung npm

> **Wichtig:** Ohne `--include-modules` oder `--scan-cache` werden nur die eigenen Projektdateien gescannt, nicht die installierten Abhängigkeiten — der häufigste Ort für Supply-Chain-Angriffe. Der Scanner gibt beim Start einen Hinweis aus, wenn keiner der beiden Schalter aktiv ist.

```bash
# Aktuelles Repository scannen (Hinweis: nur eigene Dateien)
python3 scan-npm.py

# Vollständige Supply-Chain-Prüfung inkl. node_modules/ (langsam)
python3 scan-npm.py --include-modules

# npm-Cache ebenfalls scannen (~/.npm/_cacache) — Alternative zu --include-modules
python3 scan-npm.py --scan-cache

# Bestimmten Pfad scannen, JSON-Ausgabe
python3 scan-npm.py /pfad/zum/repo --format json

# Nur HIGH-Befunde, node_modules einschließen
python3 scan-npm.py --min-severity HIGH --include-modules

# Pfade via Regex überspringen
python3 scan-npm.py --skip "vendor/" "dist/"

# CI: Pipeline nicht fehlschlagen lassen
python3 scan-npm.py --no-fail
```

### Exit-Codes npm

| Code | Bedeutung |
| ------ | ----------- |
| `0` | Keine Befunde (oder `--no-fail` gesetzt) |
| `1` | Befunde gefunden |
| `2` | Skriptfehler |

### Schweregrad-Ausgabe

Die Textausgabe ist auf Terminals farbkodiert (ANSI): HIGH in Rot, MEDIUM in Orange. Die Ausgabe kann mit `NO_COLOR=1` deaktiviert werden.

---

## 3. `scan-proxy.py`

### Proxy Funktion

Inventarisiert alle Proxy-Einstellungen auf einem System. Der Scanner liest Umgebungsvariablen, Shell-Konfigurationsdateien, Paketmanager-Konfigurationen (yum, dnf, wget, curl), Maven-Settings und Ansible-Konfigurationen aus und erstellt eine konsolidierte Übersicht. Der Scanner hat keine Abhängigkeiten und keine Kommandozeilenargumente.

### Proxy Einsatzgebiet

- **Netzwerk-Debugging** — verstehen, warum ein Tool den falschen Proxy nutzt oder gar keinen
- **Onboarding** — schnell herausfinden, welche Proxy-Einstellungen auf einem neuen System oder in einem Container aktiv sind
- **CI/CD-Runner** — sicherstellen, dass Build-Agenten die richtigen Proxy-Einstellungen haben
- **Compliance** — nachweisen, dass kein unerlaubter Proxy für ausgehende Verbindungen konfiguriert ist
- **Infrastruktur-Audits** — Überblick über alle Proxy-Konfigurationen auf einem Server

### Gescannte Quellen

| Quelle | Dateien / Variablen |
| -------- | --------------------- |
| **Umgebungsvariablen** | `http_proxy`, `https_proxy`, `ftp_proxy`, `no_proxy`, `HTTP_PROXY`, `HTTPS_PROXY`, `FTP_PROXY`, `NO_PROXY`, `ALL_PROXY`, `all_proxy` |
| **System-Shell** | `/etc/environment`, `/etc/profile`, `/etc/bashrc`, `/etc/bash.bashrc`, `/etc/sysconfig/proxy` |
| **Benutzer-Shell** | `~/.bashrc`, `~/.bash_profile`, `~/.profile` |
| **Profile-Verzeichnis** | `/etc/profile.d/*.sh`, `/etc/profile.d/*.csh` |
| **systemd-Umgebung** | `/etc/environment.d/*.conf` |
| **yum / dnf** | `/etc/yum.conf`, `/etc/dnf/dnf.conf` (inkl. `proxy_username`, `proxy_password`) |
| **wget** | `/etc/wgetrc`, `~/.wgetrc` |
| **curl** | `/etc/curlrc`, `~/.curlrc` |
| **Maven** | `~/.m2/settings.xml`, `/etc/maven/settings.xml`, `$MAVEN_HOME/conf/settings.xml` — liest `<proxies>`-Block inkl. Host, Port, Protokoll, aktiv-Status, nonProxyHosts |
| **Ansible** | `/etc/ansible/ansible.cfg`, `~/.ansible.cfg`, `./ansible.cfg` |

### Proxy Aufruf

```bash
# Direkt ausführen — keine Argumente notwendig
python3 scan-proxy.py

# Nur das Ergebnis prüfen (für Shell-Skripte)
python3 scan-proxy.py | grep "RESULT:"
```

### Ausgabeformat

```bash
=== PROXY SCAN REPORT: mein-hostname ===
RESULT: PROXY_FOUND
SOURCE=ENV KEY=http_proxy VALUE=http://proxy.corp.example.com:8080
SOURCE=/etc/environment KEY=HTTPS_PROXY VALUE=http://proxy.corp.example.com:8080
SOURCE=/home/user/.m2/settings.xml KEY=proxy.host VALUE=proxy.corp.example.com
SOURCE=/home/user/.m2/settings.xml KEY=proxy.port VALUE=8080
```

Wenn keine Proxy-Konfiguration gefunden wird:

```bash
=== PROXY SCAN REPORT: mein-hostname ===
RESULT: NO_PROXY_FOUND
```

Das Format ist maschinenlesbar und eignet sich direkt für die Verarbeitung mit `grep`, `awk` oder anderen Shell-Tools.

---

## 4. `scan-secrets.py`

### Secrets Funktion

Scannt ein komplettes Git-Repository nach hartcodierten Credentials und Secrets: Basic-Auth-Zugangsdaten (in URLs und HTTP-Headern), Bearer- und OAuth-Token, OAuth-Secrets, API-Keys, SSH/TLS-Private-Keys, AWS-Credentials, GitHub-Token, JWT-Token, Artifactory/JFrog-Token sowie Bitbucket/Atlassian-Token.

### Secrets Einsatzgebiet

- **CI/CD-Pipelines** — vor jedem Merge prüfen, ob Secrets versehentlich in den Code aufgenommen wurden
- **Security-Audits** — systematisch alle Repositories auf geleakte Credentials untersuchen
- **Pre-commit-Checks** — Entwickler frühzeitig warnen, bevor Secrets den Server erreichen
- **Incident Response** — nach einem Leakage-Verdacht gezielt nach exponierten Credentials suchen

### Secrets Kategorien

| Kategorie | Beschreibung | Erkennungsbeispiel |
| ----------- | ------------- | ------------------- |
| `private_key` | PEM-Private-Keys (RSA, EC, DSA, OpenSSH, PGP, PKCS#8 encrypted) | `-----BEGIN RSA PRIVATE KEY-----` |
| `jwt_token` | JSON Web Tokens (drei Base64url-Teile) | `eyJ...eyJ...` |
| `basic_auth_url` | Credentials in URLs | `https://user:pass@host` |
| `basic_auth_header` | Base64-kodierter Authorization-Header | `Authorization: Basic dXNlcjpwYXNz` |
| `bearer_token` | Bearer-Token im Authorization-Header | `Authorization: Bearer ya29.abc...` |
| `oauth_token` | OAuth Access-/Refresh-/ID-Token in Code | `access_token = "ya29.real..."` |
| `oauth_secret` | OAuth Client-/App-/Consumer-Secret | `client_secret = "ab12cd34..."` |
| `password` | Passwörter in Konfiguration oder Code | `password = "MyR3alP@ss"` |
| `generic_secret` | Allgemeine Secret-/Credential-Zuweisungen | `signing_key = "abc123..."` |
| `artifactory_token` | Artifactory/JFrog API-Keys und Token | `ARTIFACTORY_TOKEN=...`, `_authToken=...` |
| `bitbucket_token` | Bitbucket/Atlassian Token | `ATBB...`, `ATCTT...`, `ATATT...`, `BITBUCKET_TOKEN=...` |

### Secrets Besonderheiten

- **Platzhalter-Filter**: Template-Werte wie `<your-token>`, `${TOKEN}`, `changeme`, `example`, `{{secret}}` werden automatisch herausgefiltert
- **Einzelzeichen-Wiederholung**: Werte wie `aaaaaaaaaa` oder `11111111` werden ignoriert
- Nutzt `git ls-files` — prüft nur versionskontrollierte Dateien, respektiert `.gitignore`
- Binäre Dateien und Lock-Files werden übersprungen
- Kompatibel mit Python 2.7 und 3.x

### Secrets Verwendung

```bash
# Aktuelles Repository scannen (alle Kategorien)
python scan-secrets.py

# Bestimmten Pfad scannen, Testdateien überspringen
python scan-secrets.py /pfad/zum/repo --skip-tests

# Nur bestimmte Kategorien prüfen
python scan-secrets.py --categories oauth_secret api_key artifactory_token

# JSON-Ausgabe für CI-Pipelines
python scan-secrets.py --format json

# Bekannte sichere Muster unterdrücken
python scan-secrets.py --allow "example\\.com" "localhost"

# Erlaubmuster aus Datei laden (ein Regex pro Zeile)
python scan-secrets.py --allow-file .secrets-allowlist

# Bei Befunden nicht fehlschlagen (für Reporting ohne CI-Abbruch)
python scan-secrets.py --no-fail
```

### Secrets Exit-Codes

| Code | Bedeutung |
| ------ | ----------- |
| `0` | Keine Befunde (oder `--no-fail` gesetzt) |
| `1` | Befunde gefunden |
| `2` | Skriptfehler (kein Git-Repo, ungültige Argumente) |

---

## 5. `whitelist.json`

### Whitelist

Zentrale Konfigurationsdatei für `scan-external-urls.py`. Wird automatisch geladen, wenn sie sich im selben Verzeichnis wie das Scanner-Skript befindet. Über `--whitelist` kann auch eine externe Datei angegeben werden.

### Struktur

```json
{
  "ip_ranges":     ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "hostnames":     ["localhost", "github.com", "download.docker.com"],
  "email_domains": ["example.com"],
  "urls":          ["http://10.100.0.100"]
}
```

| Feld | Typ | Wirkung |
| ------ | ----- | --------- |
| `ip_ranges` | CIDR-Strings | Alle IP-Adressen in diesen Netzen werden nicht gemeldet |
| `hostnames` | Hostname-Strings | Exakte Hostnamen oder Wildcard-Basis (`*.domain.com`). Betrifft auch den Host-Teil von URLs. |
| `email_domains` | Domain-Strings | Domain-Teile von E-Mail-Adressen, die ignoriert werden sollen |
| `urls` | URL-Präfixe | Vollständige URL-Präfixe, die erlaubt sind |

Die mitgelieferte `whitelist.json` enthält:

- Private IP-Ranges nach RFC 1918 (10.x, 172.16.x, 192.168.x) sowie Loopback
- Standard-Infrastruktur-Hosts (GitHub, Docker, Helm, k3s, Proxmox, HashiCorp usw.)
- Projektspezifische lokale Adressen

---

## 6. `test_scan_npm.py`

Unit-Tests für `scan-npm.py` auf Basis von `pytest` / `unittest`. Prüft alle Erkennungsregeln isoliert gegen kontrollierte Eingabe-Strings.

```bash
uv run pytest test_scan_npm.py -v
```

---

## 7. testproject.sh

### Beschreibung

Bash-Skript, das in `/tmp/npm-scan-testproject` ein vollständiges Test-Node.js-Projekt aufbaut, das **alle** Erkennungsregeln von `scan-npm.py` triggert. Die Inhalte sind inerte Testdaten ohne echten Schadcode.

Das Skript initialisiert ein Git-Repository, erstellt alle relevanten Konfigurations- und Quelldateien mit kontrollierten Mustern, committet alles und startet dann den Scanner gegen das erzeugte Projekt. Am Ende kann das Testprojekt auf Wunsch gelöscht werden.

### Aufruf

```bash
bash testproject.sh
```

### Erzeugte Testdateien

| Datei | Getriggerte Kategorien |
| ------- | ------------------------ |
| `package.json` | LIFECYCLE_HOOKS_FOUND, INSTALL_SCRIPT (curl, wget, chmod, python3-c, base64, node-e, stratum, xmrig, .ssh, process.env+net), SUPPLY_CHAIN (Git-URL-Deps), INSTALL_SCRIPT (gypfile) |
| `.npmrc` | SUPPLY_CHAIN (Nicht-Standard-Registry), EXFILTRATION (hardcodierter Token) |
| `.yarnrc` | SUPPLY_CHAIN (Nicht-Standard-Registry), EXFILTRATION (Token) |
| `.yarnrc.yml` | SUPPLY_CHAIN (Registry, externe Plugin-URL HIGH), EXFILTRATION (Token) |
| `package-lock.json` | SUPPLY_CHAIN (Non-Standard-resolved-URL, fehlender integrity-Hash) |
| `pnpm-lock.yaml` | SUPPLY_CHAIN (Non-Standard-tarball-URL), EXFILTRATION (Token) |
| `binding.gyp` | INSTALL_SCRIPT MEDIUM (impliziter Hook), INSTALL_SCRIPT HIGH (curl + nc in Actions) |
| `src/evil.js` | Alle CODE_THREAT_RULES: OBFUSCATION (inkl. dynamic import), EXFILTRATION (inkl. DNS), FILESYSTEM_ATTACK, REMOTE_EXEC, CRYPTOMINING, SUPPLY_CHAIN (inkl. IP-Conditional) |
| `src/native_addon.node` | SUPPLY_CHAIN MEDIUM (nicht analysierbarer Nativer Code) |

---

## Schnellentscheidung: Welcher Scanner für welchen Zweck?

| Frage | Scanner |
| ------- | --------- |
| Hat dieses Repository externe URLs/IPs/E-Mails, die nicht dort sein sollten? | `scan-external-urls.py` |
| Enthält dieses npm-Paket oder JS-Projekt Schadsoftware oder Supply-Chain-Risiken? | `scan-npm.py` |
| Welche Proxy-Einstellungen sind auf diesem System aktiv? | `scan-proxy.py` |
| Liegen Passwörter, API-Keys oder OAuth-Secrets im Code? | `scan-secrets.py` |
| Welche Hosts und IPs sind für den URL-Scanner dauerhaft erlaubt? | `whitelist.json` |

---

## Entwicklung

```bash
# Abhängigkeiten installieren (nur Dev-Tools: pytest, ruff, pyright)
uv sync --dev

# Tests ausführen
uv run pytest test_scan_npm.py -v

# Linting
uv run ruff check .

# Typprüfung
uv run pyright scan-npm.py scan-external-urls.py
```
