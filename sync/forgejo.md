# `fj_parse.py` und `fj-pull-org.sh`

## Funktion

`fj-pull-org.sh` klont alle Repositories einer Forgejo-Organisation oder eines Forgejo-Benutzers in ein Zielverzeichnis. Bereits vorhandene Repositories werden per `git pull --ff-only` aktualisiert. Es ist das Gegenstück zu [`bb-pull-project.sh`](bitbucket.md) für Bitbucket und funktioniert genauso mit Gitea und Codeberg, die dieselbe API (`/api/v1`) haben.

`fj_parse.py` ist ein Hilfsskript für `fj-pull-org.sh`. Es liest eine JSON-Antwort der Forgejo-REST-API von `stdin` und gibt die Clone-URLs bzw. die Anzahl der Repositories auf `stdout` aus. Damit braucht das Shell-Skript weder `jq` noch eigenes JSON-Parsing.

## Einsatzgebiet

- **Massen-Scans** — alle Repositories einer Organisation lokal bereitstellen, um anschließend `scan-secrets.py`, `scan-npm.py` oder `scan-external-urls.py` darüber laufen zu lassen
- **Spiegelung** — einen lokalen Stand aller Repos einer Organisation aktuell halten (z. B. per Cronjob)
- **Migration** — Repositories von Bitbucket nach Forgejo umgezogen? Beide Skripte in getrennte Zielverzeichnisse laufen lassen und die Stände vergleichen

## Voraussetzungen

- `bash`, `curl` 7.55+, `xargs`, `base64`
- `git` 2.31+ (für die Übergabe der Zugangsdaten per `GIT_CONFIG_*`)
- Python 3.6+ (nur Standardbibliothek)
- Forgejo-Access-Token mit Leserechten, angelegt unter *Einstellungen → Applikationen → Access Token*:

| Scope | Wofür |
| ------- | ------- |
| `read:repository` | private Repositories sehen und klonen |
| `read:organization` | Repo-Liste einer Organisation (`FJ_OWNER_TYPE=org`) |
| `read:user` | Repo-Liste eines Benutzers (`FJ_OWNER_TYPE=user`) |

Beide Dateien liegen im Ordner `sync/`. `fj_parse.py` muss im selben Verzeichnis wie `fj-pull-org.sh` liegen. Das Skript prüft das beim Start.

## Verwendung `fj-pull-org.sh`

Aus dem Repository-Root:

```bash
# Organisation auf einer eigenen Forgejo-Instanz
FJ_URL=https://forgejo.example.com \
FJ_USER=myuser \
FJ_TOKEN=mytoken \
FJ_OWNER=myorg \
TARGET_DIR=/opt/repos \
sync/fj-pull-org.sh

# Alle Repositories eines Benutzers auf Codeberg
FJ_URL=https://codeberg.org \
FJ_USER=myuser \
FJ_TOKEN=mytoken \
FJ_OWNER=myuser \
FJ_OWNER_TYPE=user \
TARGET_DIR=/opt/repos \
sync/fj-pull-org.sh
```

### Umgebungsvariablen

| Variable | Pflicht | Default | Beschreibung |
| ---------- | --------- | --------- | -------------- |
| `FJ_USER` | ja | – | Forgejo-Benutzer oder Service-Account, wird für `git clone` / `git pull` verwendet |
| `FJ_TOKEN` | ja | – | Access Token (siehe Scopes oben) |
| `FJ_OWNER` | ja | – | Name der Organisation bzw. des Benutzers |
| `FJ_URL` | nein | `https://forgejo.example.com` | Basis-URL der Forgejo-Instanz, ohne `/api/v1` |
| `FJ_OWNER_TYPE` | nein | `org` | `org` = Organisation, `user` = Benutzer |
| `TARGET_DIR` | nein | `./repos` | Zielverzeichnis für die Klone |
| `PARALLEL` | nein | `4` | Anzahl paralleler `git clone` / `git pull` |

### Ablauf

1. **Preflight** — prüft, ob `fj_parse.py` vorhanden ist und `FJ_OWNER_TYPE` gültig ist, und legt `TARGET_DIR` an
2. **Repo-Liste sammeln** — ruft die Forgejo-API seitenweise ab und extrahiert die Clone-URLs (`clone_url`) über `fj_parse.py`
3. **Klonen / Aktualisieren** — für jede URL parallel:
   - `TARGET_DIR/<repo>/.git` existiert → `git pull --ff-only`
   - `TARGET_DIR/<repo>/.git` existiert, hat aber noch keinen Commit (Klon eines leeren Repos) → statt `git pull` ein `git fetch`; hat das Remote inzwischen Inhalt, checkt das Skript den Default-Branch aus
   - sonst → `git clone`

Der Verzeichnisname ergibt sich aus der Clone-URL ohne `.git`. Archivierte Repositories und Pull-Mirrors klont das Skript mit, Forks ebenfalls.

Schlägt ein `git clone` oder `git pull` fehl, erscheint `FAILED (git exit N)` in der Ausgabe. Die übrigen Repositories laufen weiter, am Ende endet das Skript mit Exit-Code `1`.

### Verwendete API-Endpunkte

| `FJ_OWNER_TYPE` | Endpunkt | Paginierung |
| ----------------- | ---------- | ------------- |
| `org` | `GET {FJ_URL}/api/v1/orgs/{FJ_OWNER}/repos?page=N&limit=50` | `page` ab 1, bis eine leere Seite kommt |
| `user` | `GET {FJ_URL}/api/v1/users/{FJ_OWNER}/repos?page=N&limit=50` | wie oben |

Forgejo begrenzt die Seitengröße auf `[api] MAX_RESPONSE_ITEMS` aus der `app.ini` (Default 50). Eine Instanz mit kleinerem Wert liefert weniger Einträge pro Seite, als `limit` verlangt. Eine kurze Seite ist deshalb kein sicheres Ende. Das Skript fragt so lange weiter, bis eine Seite leer ist. Das kostet einen zusätzlichen API-Aufruf.

Welche Repositories in der Liste stehen, hängt am Token: Private Repositories einer Organisation erscheinen nur, wenn der Token-Benutzer Mitglied eines Teams mit Zugriff ist. Fehlt der Scope `read:repository`, kommen nur öffentliche Repositories.

### Unterschiede zu `bb-pull-project.sh`

| | Bitbucket | Forgejo |
| --- | ----------- | --------- |
| Gruppierung | Projekt (Server) bzw. Workspace (Cloud) | Organisation oder Benutzer |
| API-Auth | HTTP Basic `BB_USER:BB_TOKEN` | Header `Authorization: token <FJ_TOKEN>` |
| Git-Auth | HTTP Basic `BB_GIT_USER:BB_TOKEN` | HTTP Basic `FJ_USER:FJ_TOKEN` |
| Paginierung | `isLastPage` / `next` | leere Seite |
| Antwort | Objekt mit `values` | JSON-Array |
| Clone-Link | `links.clone[name=http\|https]` | `clone_url` |

### Authentifizierung

Die API-Aufrufe laufen mit dem Header `Authorization: token <FJ_TOKEN>`. `curl` liest den Header von `stdin` (`-H @-`), damit das Token nicht in der Prozessliste steht.

Für `git clone` / `git pull` setzt das Skript die Zugangsdaten `FJ_USER:FJ_TOKEN` als `Authorization: Basic`-Header, beschränkt auf `FJ_URL`:

```bash
GIT_CONFIG_COUNT=1
GIT_CONFIG_KEY_0="http.<FJ_URL>/.extraHeader"
GIT_CONFIG_VALUE_0="Authorization: Basic <base64(user:token)>"
GIT_TERMINAL_PROMPT=0
```

- Die Übergabe läuft nur über Umgebungsvariablen. Das Token erscheint weder in der Prozessliste noch in `.git/config` der geklonten Repos.
- `GIT_TERMINAL_PROMPT=0` verhindert Passwortabfragen. Fehlende oder falsche Zugangsdaten führen zu einem Fehler statt zu hängenden `xargs`-Prozessen.
- Die `clone_url` baut Forgejo aus `ROOT_URL` in der `app.ini`. Weicht sie von `FJ_URL` ab (anderer Hostname, `http` statt `https`, Port), greift der Header nicht und `git` scheitert mit einem Auth-Fehler. Dann `FJ_URL` auf genau den Anfang der `clone_url` setzen.

### Exit-Codes `fj-pull-org.sh`

| Code | Bedeutung |
| ------ | ----------- |
| `0` | Alle Repositories geklont bzw. aktualisiert |
| `1` | `fj_parse.py` fehlt, `FJ_OWNER_TYPE` ungültig, API-Aufruf fehlgeschlagen, keine Repositories gefunden oder mindestens eine Git-Operation fehlgeschlagen |

Bei einem API-Fehler (z. B. 401 bei falschem Token, 404 bei falschem Namen oder falschem `FJ_OWNER_TYPE`) steht der Exit-Code von `curl` zusammen mit der URL in der Fehlermeldung:

```text
[09:12:45] ERROR: API request failed (curl exit 22): https://forgejo.example.com/api/v1/users/myorg/repos?page=1&limit=50
```

## Verwendung `fj_parse.py`

```bash
printf 'Authorization: token %s\n' "$FJ_TOKEN" \
  | curl -fsSL -H @- "<api-url>" \
  | python3 sync/fj_parse.py <command>
```

### Kommandos

| Kommando | Liest Feld | Ausgabe |
| ---------- | ------------ | --------- |
| `urls` | `[].clone_url` | Eine HTTP(S)-Clone-URL pro Repository und Zeile |
| `count` | Länge des Arrays | Anzahl der Repositories auf dieser Seite, `0` auf der Seite nach der letzten |

SSH-URLs (`ssh_url`) werden ignoriert.

### Beispiele

```bash
echo '[{"name":"repo-a","clone_url":"https://forgejo.example.com/org/repo-a.git",
        "ssh_url":"ssh://git@forgejo.example.com/org/repo-a.git"}]' \
  | python3 sync/fj_parse.py urls
# https://forgejo.example.com/org/repo-a.git

echo '[]' | python3 sync/fj_parse.py count
# 0
```

### Verhalten bei fehlenden Feldern

| Situation | Ausgabe |
| ----------- | --------- |
| Repository ohne `clone_url` | Leerzeile (wird von `fj-pull-org.sh` verworfen) |
| Leeres Array (Seite nach der letzten) | `count` → `0`, `urls` → keine Ausgabe |
| Objekt statt Array (Forgejo-Fehlermeldung, z. B. `{"message":"GetOrgByName",…}`) | Meldung auf `stderr`, Exit-Code `1` |

### Exit-Codes `fj_parse.py`

| Code | Bedeutung |
| ------ | ----------- |
| `0` | Erfolgreich geparst |
| `1` | Unbekanntes oder fehlendes Kommando (Usage-Hinweis auf `stderr`), Antwort ist kein Array oder ungültiges JSON auf `stdin` (Python-Traceback) |

### Hinweise

- Jedes Kommando liest `stdin` komplett ein. Für mehrere Werte aus derselben Antwort muss die Antwort zwischengespeichert und mehrfach übergeben werden, wie in `fj-pull-org.sh` über `$RESPONSE`.

## Tests

```bash
uv run pytest tests/test_sync_parse.py
```
