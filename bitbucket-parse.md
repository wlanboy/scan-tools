# `bb_parse.py` und `bb-pull-project.sh`

## Funktion

`bb-pull-project.sh` klont alle Repositories eines Bitbucket-Projekts (Server / Data Center) bzw. eines Workspaces (Cloud) in ein Zielverzeichnis. Bereits vorhandene Repositories werden per `git pull --ff-only` aktualisiert.

`bb_parse.py` ist ein Hilfsskript für `bb-pull-project.sh`. Es liest eine JSON-Antwort der Bitbucket-REST-API von `stdin` und gibt genau einen Wert bzw. eine Liste von Werten zeilenweise auf `stdout` aus. Damit braucht das Shell-Skript weder `jq` noch eigenes JSON-Parsing.

## Einsatzgebiet

- **Massen-Scans** — alle Repositories eines Projekts lokal bereitstellen, um anschließend `scan-secrets.py`, `scan-npm.py` oder `scan-external-urls.py` darüber laufen zu lassen
- **Spiegelung** — einen lokalen Stand aller Repos eines Projekts aktuell halten (z. B. per Cronjob)
- **Audits** — schneller Überblick, welche Repositories in einem Projekt existieren

## Voraussetzungen

- `bash`, `curl`, `xargs`, `base64`
- `git` 2.31+ (für die Übergabe der Zugangsdaten per `GIT_CONFIG_*`)
- Python 3.6+ (nur Standardbibliothek)
- Bitbucket-Zugang mit Leserechten auf das Projekt:
  - **Server / Data Center**: HTTP Access Token oder Personal Access Token
  - **Cloud**: App-Passwort bzw. API-Token

`bb_parse.py` muss im selben Verzeichnis wie `bb-pull-project.sh` liegen. Das Skript prüft das beim Start.

## Verwendung `bb-pull-project.sh`

```bash
# Bitbucket Server / Data Center
BB_URL=https://bitbucket.example.com \
BB_USER=myuser \
BB_TOKEN=mytoken \
BB_PROJECT=MYPROJECT \
TARGET_DIR=/opt/repos \
./bb-pull-project.sh

# Bitbucket Cloud
BB_CLOUD=1 \
BB_USER=myuser \
BB_TOKEN=myapppassword \
BB_PROJECT=myworkspace \
TARGET_DIR=/opt/repos \
./bb-pull-project.sh
```

### Umgebungsvariablen

| Variable | Pflicht | Default | Beschreibung |
| ---------- | --------- | --------- | -------------- |
| `BB_USER` | ja | – | Bitbucket-Benutzer oder Service-Account |
| `BB_TOKEN` | ja | – | Access Token (Server) bzw. App-Passwort (Cloud) |
| `BB_PROJECT` | ja | – | Projekt-Key (Server) bzw. Workspace-Slug (Cloud) |
| `BB_URL` | nein | `https://bitbucket.example.com` | Basis-URL des Bitbucket Servers |
| `BB_CLOUD` | nein | `0` | `1` = Bitbucket-Cloud-API verwenden |
| `TARGET_DIR` | nein | `./repos` | Zielverzeichnis für die Klone |
| `PARALLEL` | nein | `4` | Anzahl paralleler `git clone` / `git pull` |
| `BB_GIT_USER` | nein | `BB_USER` | Benutzername für `git clone` / `git pull`, falls er vom API-Login abweicht |

### Ablauf

1. **Preflight** — prüft, ob `bb_parse.py` vorhanden ist, und legt `TARGET_DIR` an
2. **Repo-Liste sammeln** — ruft die Bitbucket-API seitenweise ab (100 Repos pro Seite) und extrahiert die Clone-URLs über `bb_parse.py`
3. **Klonen / Aktualisieren** — für jede URL parallel:
   - `TARGET_DIR/<repo>/.git` existiert → `git pull --ff-only`
   - sonst → `git clone`

Der Verzeichnisname ergibt sich aus der Clone-URL ohne `.git`.

### Verwendete API-Endpunkte

| Modus | Endpunkt | Paginierung |
| ------- | ---------- | ------------- |
| Server | `GET {BB_URL}/rest/api/1.0/projects/{BB_PROJECT}/repos?start=N&limit=100` | `isLastPage` / `nextPageStart` |
| Cloud | `GET https://api.bitbucket.org/2.0/repositories/{BB_PROJECT}?pagelen=100` | `next` (vollständige URL der nächsten Seite) |

### Authentifizierung beim Klonen

Die API-Aufrufe laufen mit `BB_USER:BB_TOKEN` (HTTP Basic Auth). Für `git clone` / `git pull` setzt das Skript die Zugangsdaten `BB_GIT_USER:BB_TOKEN` als `Authorization: Basic`-Header, beschränkt auf den Bitbucket-Host (`https://bitbucket.org/` bzw. `BB_URL`):

```bash
GIT_CONFIG_COUNT=1
GIT_CONFIG_KEY_0="http.<host>/.extraHeader"
GIT_CONFIG_VALUE_0="Authorization: Basic <base64(user:token)>"
GIT_TERMINAL_PROMPT=0
```

- Die Übergabe läuft nur über Umgebungsvariablen. Das Token erscheint weder in der Prozessliste noch in `.git/config` der geklonten Repos.
- `GIT_TERMINAL_PROMPT=0` verhindert Passwortabfragen. Fehlende oder falsche Zugangsdaten führen zu einem Fehler statt zu hängenden `xargs`-Prozessen.
- Bei Bitbucket Cloud mit API-Token kann der Git-Benutzer vom API-Login (E-Mail-Adresse) abweichen. Dann `BB_GIT_USER` setzen, z. B. auf den Bitbucket-Benutzernamen oder `x-bitbucket-api-token-auth`.

### Exit-Codes `bb-pull-project.sh`

| Code | Bedeutung |
| ------ | ----------- |
| `0` | Alle Repositories geklont bzw. aktualisiert |
| `1` | `bb_parse.py` fehlt, API-Aufruf fehlgeschlagen, keine Repositories gefunden oder mindestens eine Git-Operation fehlgeschlagen |

Bei einem API-Fehler (z. B. 401/404 oder Host nicht erreichbar) steht der Exit-Code von `curl` zusammen mit der URL in der Fehlermeldung:

```text
[16:54:45] ERROR: API request failed (curl exit 22): https://bitbucket.example.com/rest/api/1.0/projects/P/repos?start=0&limit=100
```

## Verwendung `bb_parse.py`

```bash
curl -fsSL -u "$BB_USER:$BB_TOKEN" "<api-url>" | python3 bb_parse.py <command>
```

### Kommandos

| Kommando | API | Liest Feld | Ausgabe |
| ---------- | ----- | ------------ | --------- |
| `cloud-urls` | Cloud | `values[].links.clone[name=https].href` | Eine HTTPS-Clone-URL pro Repository und Zeile |
| `cloud-next` | Cloud | `next` | URL der nächsten Seite, leer auf der letzten Seite |
| `server-urls` | Server | `values[].links.clone[name=http].href` | Eine HTTP(S)-Clone-URL pro Repository und Zeile |
| `server-islast` | Server | `isLastPage` | `true` oder `false` |
| `server-nextstart` | Server | `nextPageStart` | Startindex der nächsten Seite als Zahl |

Bitbucket Server benennt den HTTP-Clone-Link immer `http`, auch wenn die URL mit `https://` beginnt. Bitbucket Cloud verwendet `https`. SSH-Links werden in beiden Fällen ignoriert.

### Beispiele

```bash
# Bitbucket Cloud: Clone-URLs einer Seite
echo '{"values":[{"links":{"clone":[
        {"name":"https","href":"https://user@bitbucket.org/ws/repo-a.git"},
        {"name":"ssh","href":"git@bitbucket.org:ws/repo-a.git"}]}}],
      "next":"https://api.bitbucket.org/2.0/repositories/ws?page=2"}' \
  | python3 bb_parse.py cloud-urls
# https://user@bitbucket.org/ws/repo-a.git

# Bitbucket Server: Paginierung prüfen
echo '{"values":[],"isLastPage":false,"nextPageStart":100}' | python3 bb_parse.py server-islast
# false
echo '{"values":[],"isLastPage":false,"nextPageStart":100}' | python3 bb_parse.py server-nextstart
# 100
```

### Verhalten bei fehlenden Feldern

| Situation | Ausgabe |
| ----------- | --------- |
| Repository ohne passenden Clone-Link | Leerzeile (wird von `bb-pull-project.sh` verworfen) |
| `values` fehlt | Keine Ausgabe |
| `next` fehlt oder `null` (letzte Cloud-Seite) | Leerzeile → Schleife endet |
| `isLastPage` fehlt | `true` → Schleife endet, um Endlosschleifen zu vermeiden |
| `nextPageStart` fehlt | `0` |

### Exit-Codes `bb_parse.py`

| Code | Bedeutung |
| ------ | ----------- |
| `0` | Erfolgreich geparst |
| `1` | Unbekanntes oder fehlendes Kommando (Usage-Hinweis auf `stderr`) oder ungültiges JSON auf `stdin` (Python-Traceback) |

### Hinweise

- Jedes Kommando liest `stdin` komplett ein. Für mehrere Werte aus derselben Antwort muss die Antwort zwischengespeichert und mehrfach übergeben werden, wie in `bb-pull-project.sh` über `$RESPONSE`.
