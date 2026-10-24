# `scan-secrets.py`

## Funktion

`scan-secrets.py` durchsucht ein Git-Repository nach hartcodierten Credentials und Secrets. Erkannt werden unter anderem Basic-Auth-Zugangsdaten (in URLs und HTTP-Headern), Bearer- und OAuth-Token, API-Keys, Private Keys, JWTs, Passwörter sowie anbieterspezifische Token von AWS, GitHub, Slack, Artifactory/JFrog und Bitbucket/Atlassian.

Das Skript nutzt nur die Python-Standardbibliothek und braucht keine Installation.

## Einsatzgebiet

- **CI/CD-Pipelines**: vor jedem Merge prüfen, ob Secrets in den Code gelangt sind (Exit-Code `1` bricht den Build ab)
- **Security-Audits**: viele Repositories auf geleakte Credentials prüfen, zusammen mit [`scan-all-repos.sh`](scan-all-repos.sh) und [`bb-pull-project.sh`](bitbucket-parse.md)
- **Pre-commit-Checks**: Secrets finden, bevor sie auf dem Server landen
- **Incident Response**: nach einem Leak-Verdacht gezielt nach einzelnen Token-Typen suchen (`--categories`)

## Voraussetzungen

- Python 3.7+ (nur Standardbibliothek)
- `git` im `PATH`
- Das Zielverzeichnis muss das **Root** eines Git-Repositories sein (dort muss `.git` liegen). Worktrees und Submodule, bei denen `.git` eine Datei ist, werden unterstützt.

## Verwendung

```bash
# Aktuelles Verzeichnis scannen (alle Kategorien)
python3 scan-secrets.py

# Bestimmtes Repository scannen, Testdateien überspringen
python3 scan-secrets.py /pfad/zum/repo --skip-tests

# Nur bestimmte Kategorien prüfen
python3 scan-secrets.py --categories aws_access_key aws_secret_key github_token

# JSON-Ausgabe für CI-Pipelines
python3 scan-secrets.py --format json

# Treffer per Regex unterdrücken
python3 scan-secrets.py --allow "localhost" "example\\.com"

# Allow-Muster aus Datei laden (ein Regex pro Zeile, # für Kommentare)
python3 scan-secrets.py --allow-file .secrets-allowlist

# Strukturierte JSON-Whitelist verwenden
python3 scan-secrets.py --whitelist secrets-whitelist.json

# Pfade überspringen (Regex auf den relativen Dateipfad)
python3 scan-secrets.py --skip "docs/" "fixtures/"

# Reporting ohne CI-Abbruch
python3 scan-secrets.py --no-fail

# Alle Repositories unter ~/projects scannen
./scan-all-repos.sh scan-secrets.py ~/projects results.txt --whitelist secrets-whitelist.json
```

### Optionen

| Option | Beschreibung |
| -------- | -------------- |
| `repo` | Pfad zum Repository-Root (Default: `.`) |
| `--categories CAT ...` | Nur die angegebenen Kategorien prüfen (Default: alle) |
| `--allow PATTERN ...` | Regex-Muster; ein Treffer wird unterdrückt, wenn der **gefundene Text** darauf passt |
| `--allow-file FILE` | Datei mit einem Allow-Muster pro Zeile; Leerzeilen und `#`-Kommentare werden ignoriert |
| `--whitelist FILE` | JSON-Whitelist mit strukturierten Einträgen (siehe [Whitelist](#whitelist)) |
| `--skip PATTERN ...` | Regex-Muster; Dateien, deren relativer Pfad darauf passt, werden nicht gelesen |
| `--skip-tests` | Typische Testdateien und -verzeichnisse überspringen (siehe [Dateiauswahl](#dateiauswahl)) |
| `--format text\|json` | Ausgabeformat (Default: `text`) |
| `--no-fail` | Immer mit `0` beenden, auch bei Funden |

`--allow`- und `--skip`-Muster werden ohne Beachtung der Groß-/Kleinschreibung ausgewertet. Ist ein Muster kein gültiger Regex, wird es als einfacher Teilstring verglichen.

## Kategorien

| Kategorie | Erkennt | Beispiel |
| ----------- | --------- | ---------- |
| `private_key` | PEM-Header von RSA-, EC-, DSA-, OpenSSH-, PGP- und verschlüsselten Private Keys | `-----BEGIN RSA PRIVATE KEY-----` |
| `jwt_token` | JSON Web Tokens (drei Base64url-Teile, beginnend mit `eyJ`) | `eyJhbGci...eyJzdWIi...SflKxw...` |
| `basic_auth_url` | Benutzer und Passwort in einer HTTP(S)-URL | `https://deploy:S3cr3t@git.corp` |
| `basic_auth_header` | Base64-kodierter `Authorization: Basic`-Header | `Authorization: Basic dXNlcjpwYXNz` |
| `bearer_token` | `Authorization: Bearer`-Header (Token ab 20 Zeichen) | `Authorization: Bearer ya29.a0Af...` |
| `oauth_token` | `access_token`, `refresh_token`, `id_token`, `oauth_token` usw. | `access_token = "ya29.a0AfH6..."` |
| `oauth_secret` | `client_secret`, `consumer_secret`, `app_secret`, `api_secret` usw. | `client_secret: 8f3k2LmQ9x` |
| `password` | `password`, `passwd`, `pwd` mit Wert ab 4 Zeichen | `password: "Xk9mQ2vL7pR!"` |
| `generic_secret` | `secret`, `credential`, `auth_token`, `signing_key`, `encryption_key`, `hmac_key` usw. | `signing_key = "a8Fj3kLq..."` |
| `api_key` | `api_key`, `api-key`, `apikey` mit Wert ab 16 Zeichen | `API_KEY=4f8a9c2e1b7d6f3a` |
| `artifactory_token` | `:_authToken=` in `.npmrc`/`.yarnrc` sowie `ARTIFACTORY_*`/`JFROG_*`-Variablen | `//npm.corp/:_authToken=AKCp8...` |
| `bitbucket_token` | Präfixe `ATBB`, `ATCTT`, `ATATT` sowie `BITBUCKET_TOKEN`, `BITBUCKET_APP_PASSWORD` usw. | `ATBB3xY...` |
| `github_token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + mindestens 36 Zeichen | `ghp_1a2B3c...` |
| `aws_access_key` | Access Key IDs mit `AKIA` (dauerhaft), `ASIA` (STS) oder `ABIA` | `AKIAIOSFODNN7EXAMPLE` |
| `aws_secret_key` | 40-stelliger Secret Key, nur neben `aws_secret_access_key` o. ä. | `aws_secret_access_key = wJalr...` |
| `slack_token` | Slack-Token `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` | `xoxb-123456789012-...` |

## Falsch-Positive vermeiden

### Eingebauter Platzhalter-Filter

Bevor ein Treffer gemeldet wird, prüft der Scanner den eigentlichen Secret-Wert (bei `basic_auth_url` das Passwort, sonst den erfassten Wert bzw. den ganzen Treffer). Verworfen werden:

- Werte mit weniger als 4 Zeichen
- Werte, die nur aus einem wiederholten Zeichen bestehen (`aaaaaaaa`, `11111111`)
- Maskierungen: `****`, `xxx`, `0000`, `...`, `????`, `____`
- Template- und Variablensyntax: `<your-key>`, `${TOKEN}`, `$API_KEY`, `{{token}}`, `%(key)s`
- Werte, die Platzhalter-Wörter enthalten: `your-`, `todo`, `changeme`, `example`, `placeholder`, `fake`, `dummy`, `test`, `sample`, `insert`, `n/a`, `undefined`, `null`, `none`, `empty`, `missing`, `replace`, `edit this`
- Werte, die selbst nur ein Feldname sind: `password`, `passwd`, `secret`, `token`, `apikey`, `api_key`

Der Wort-Filter greift auch innerhalb längerer Werte. Ein echtes Passwort wie `MyExamplePass1` würde deshalb nicht gemeldet.

### `--allow`

Allow-Muster werden gegen den **gefundenen Text** geprüft, nicht gegen die ganze Zeile. Für `basic_auth_url` ist das zum Beispiel `https://user:pass@host`, für `password` etwa `password: "geheim123"`.

### Whitelist

Mit `--whitelist` lassen sich Funde gezielt und dokumentiert unterdrücken. Die Datei ist entweder ein JSON-Array oder ein Objekt mit dem Schlüssel `entries`. Eine kommentierte Vorlage liegt in [`secrets-whitelist.json`](secrets-whitelist.json).

```json
{
  "entries": [
    { "file": "config/example.yml",
      "comment": "Beispielkonfiguration ohne echte Credentials" },
    { "category": "jwt_token", "file_pattern": "fixtures/|testdata/",
      "comment": "Synthetische Test-JWTs" },
    { "value_pattern": "localhost|127\\.0\\.0\\.1",
      "comment": "Loopback-URLs" }
  ]
}
```

| Feld | Vergleich | Geprüft gegen |
| ------ | ----------- | --------------- |
| `category` | exakt | Kategorie-Name, z. B. `password` |
| `file` | exakt | relativer Dateipfad, z. B. `config/app.yml` |
| `file_pattern` | Regex (Teiltreffer, ohne Groß-/Kleinschreibung) | relativer Dateipfad |
| `value` | exakt | gefundener Text |
| `value_pattern` | Regex (Teiltreffer, ohne Groß-/Kleinschreibung) | gefundener Text |
| `comment` | – | nur Dokumentation |

Regeln:

- Ein Eintrag greift nur, wenn **alle** angegebenen Felder passen (UND-Verknüpfung).
- Ein Eintrag ohne eines der Vergleichsfelder (z. B. nur `comment`) wird ignoriert.
- Ein ungültiger Regex in `file_pattern` oder `value_pattern` passt nie.
- `value` vergleicht mit dem **ganzen gefundenen Text** aus dem Report (Feld `Value` bzw. `value` im JSON), also inklusive Schlüsselname und Anführungszeichen, z. B. `password: "Xk9mQ2vL7pR!"`. Um nur den Secret-Wert zu treffen, ist `value_pattern` meist die bessere Wahl.
- `file` gilt nur für genau eine Datei. Für Verzeichnisse `file_pattern` verwenden, z. B. `"file_pattern": "^k8s/overlays/dev/"`.

### Dateiauswahl

Gescannt werden alle Dateien, die `git ls-files --cached --others --exclude-standard` liefert: versionierte Dateien plus neue, noch nicht versionierte Dateien, die nicht in `.gitignore` stehen.

Immer übersprungen werden:

- Binärdateien (Null-Byte in den ersten 8 KB)
- Bilder, Archive, Java-Artefakte (`.jar`, `.war`, `.class`), kompilierte Dateien, Fonts, Audio/Video
- Lock-Files mit der Endung `.lock` (`package-lock.json` wird dagegen gescannt)

Mit `--skip-tests` zusätzlich:

- Dateien unter `test/`, `tests/`, `__tests__/`
- Dateinamen, die mit `test_` beginnen
- Dateinamen auf `_test.py`, `_test.go`, `.test.{js,jsx,ts,tsx}`, `.spec.{js,jsx,ts,tsx}`, `_spec.rb`, `Test.java`, `Tests.java`

## Ausgabe

### Text (Default)

Funde werden nach Kategorie gruppiert. `Value` wird auf 80 Zeichen gekürzt, `Context` (die Quellzeile) auf 120 Zeichen.

```text
Scanning 1 tracked file(s) in "/pfad/zum/repo" ...

======================================================================
  Secrets scan -- 2 finding(s)
======================================================================

  Basic Auth in URL (1)
  ----------------------------------------
  config/app.yml:3
    Value  : https://deploy:S3cr3tPw@git.internal.corp
    Context: url: https://deploy:S3cr3tPw@git.internal.corp/repo.git

  Password (1)
  ----------------------------------------
  config/app.yml:2
    Value  : password: "Xk9mQ2vL7pR!"
    Context: password: "Xk9mQ2vL7pR!"

======================================================================
  Total: 2 finding(s) in 1 file(s)
======================================================================
```

Ohne Funde erscheint nur `No secrets found.`

### JSON

`--format json` gibt ein Array aus, ein Objekt pro Fund, in der Reihenfolge der Dateien. Die Zeile `Scanning ...` entfällt, damit die Ausgabe direkt mit `jq` verarbeitet werden kann.

```json
[
  {
    "category": "password",
    "label": "Password",
    "value": "password: \"Xk9mQ2vL7pR!\"",
    "file": "config/app.yml",
    "line": 2,
    "context": "password: \"Xk9mQ2vL7pR!\""
  }
]
```

> **Achtung:** Beide Formate geben die gefundenen Secrets im Klartext aus. In CI-Pipelines sollte der Report deshalb nicht in öffentlich lesbaren Build-Logs landen.

Warnungen (z. B. nicht lesbare Dateien) und Fehler gehen auf `stderr`.

## Exit-Codes

| Code | Bedeutung |
| ------ | ----------- |
| `0` | Keine Funde (oder `--no-fail` gesetzt) |
| `1` | Funde vorhanden |
| `2` | Skriptfehler: kein Git-Repository-Root, `git ls-files` fehlgeschlagen, Allow-File oder Whitelist nicht lesbar bzw. ungültiges JSON |

## Grenzen

- **Nur der aktuelle Stand**: Die Git-Historie wird nicht durchsucht. Ein Secret, das in einem früheren Commit entfernt wurde, bleibt unentdeckt, ist aber weiterhin abrufbar. Für die Historie eignen sich Tools wie `gitleaks` oder `trufflehog`.
- **Zeilenbasiert**: Secrets, die über mehrere Zeilen verteilt sind, werden nicht erkannt. Bei Private Keys reicht der PEM-Header als Treffer.
- **`#` beendet den Wert**: Bei schlüsselbasierten Kategorien (`password`, `api_key`, `oauth_secret` usw.) wird `#` als Kommentarbeginn gewertet. Aus `password: "Xk9#mQ2v"` wird nur `Xk9` gelesen; das ist kürzer als 4 Zeichen, also gibt es keinen Fund. Leerzeichen, Anführungszeichen, Kommas sowie `[]{}` beenden den Wert ebenfalls.
- **Platzhalter-Filter**: Echte Secrets, die zufällig ein Platzhalter-Wort wie `test` oder `example` enthalten, werden verworfen.
- **Kein Entropie-Check**: Secrets ohne bekannten Schlüsselnamen oder Präfix (z. B. ein nacktes Token in einer Variablen namens `x`) werden nicht gefunden.
