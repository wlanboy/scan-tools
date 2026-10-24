# scan-external-urls.py

Der Scanner durchsucht ein Git-Repository nach URLs, E-Mail-Adressen, Hostnamen und IP-Adressen. Gemeint sind Stellen, an denen Code oder Tests ungewollt nach außen telefonieren, hartcodierte Endpunkte stehen oder persönliche Daten mitcommittet wurden.

Das Skript braucht nur die Python-Standardbibliothek (Python 3.9+) und ein installiertes `git`.

## Schnellstart

```bash
# Aktuelles Verzeichnis scannen, alle Kategorien
python3 scan-external-urls.py

# Anderes Repository, Tests auslassen, eigene Domain erlauben
python3 scan-external-urls.py /pfad/zum/repo --skip-tests --allow mycompany.com

# CI: nur URLs und E-Mails, JSON-Ausgabe
python3 scan-external-urls.py --categories url email --format json
```

Der Pfad muss auf das Wurzelverzeichnis des Repositories zeigen, also auf den Ordner mit `.git`. Das darf ein Verzeichnis sein (normaler Clone) oder eine Datei (Git-Worktree, Submodul).

## Welche Dateien gescannt werden

Die Dateiliste kommt aus `git ls-files --cached --others --exclude-standard`. Das sind alle versionierten Dateien plus neue, noch nicht committete Dateien, sofern `.gitignore` sie nicht ausschließt. Ein frisch angelegtes `config.yaml` landet also schon vor dem ersten Commit im Scan.

Übersprungen werden:

- Dateien mit Binär-Endungen wie `.png`, `.pdf`, `.zip`, `.jar`, `.class`, `.pyc`, `.so`, `.woff`, `.mp4` und alle `.lock`-Dateien
- Dateien mit einem Null-Byte in den ersten 8 KB
- Pfade, die auf ein `--skip`-Muster passen
- Testdateien, wenn `--skip-tests` gesetzt ist

Als Testdatei gilt alles unter `test/`, `tests/` oder `__tests__/`, außerdem `test_*`, `*_test.py`, `*_test.go`, `*.test.{js,jsx,ts,tsx}`, `*.spec.{js,jsx,ts,tsx}`, `*_spec.rb`, `*Test.java`, `*Tests.java` und `Test*.java`.

## Kategorien

| Kategorie | Was erkannt wird | Beispiel |
| --- | --- | --- |
| `url` | `http://` und `https://` URLs | `https://api.example.com/v2/data` |
| `email` | E-Mail-Adressen mit bekannter TLD | `admin@company.com` |
| `hostname` | Hostnamen mit mindestens einem Punkt und bekannter TLD | `internal.corp.io` |
| `ip` | IPv4- und IPv6-Adressen | `10.0.5.12`, `2001:db8::1` |

Pro Zeile laufen die Kategorien in dieser Reihenfolge. Was schon als URL erkannt wurde, meldet der Scanner nicht noch einmal als E-Mail oder Hostname. Aus `https://api.example.com/x` wird also ein Befund, nicht zwei.

### Hostnamen und False Positives

Hostnamen sind die Kategorie mit dem meisten Rauschen, weil `os.path`, `request.json` oder `foo.bar.de` syntaktisch gleich aussehen. Der Scanner filtert deshalb ziemlich aggressiv:

- Die letzte Komponente muss in einer festen TLD-Liste stehen (`KNOWN_TLDS` im Skript). `sh` und `id` fehlen dort mit Absicht, sonst wären `deploy.sh` und `this.id` Treffer.
- Jede Komponente braucht mindestens zwei Zeichen, damit `p.name` nicht matcht.
- Folgt direkt eine Klammer (`subprocess.run(`), ist es ein Funktionsaufruf.
- Folgt direkt `.wort` (`a.b.meshConfig.ca.address`), ist es ein Pfad in JSON oder YAML.
- Steht davor ein `/` oder dahinter ein `/`, ist es ein Dateipfad oder eine Kubernetes-API-Group (`networking.istio.io/v1`). Ausnahme ist der Host direkt nach `://`.
- Komplett großgeschriebene Namen (`MOUSE.COM`) gelten als Konstanten oder DOS-Dateinamen.
- `from x.y import` und `import x.y` werden ignoriert.
- `apiGroup: rbac.authorization.k8s.io` und reine YAML-Listeneinträge wie `- containerd.io` werden ignoriert.

E-Mails mit unbekannter TLD fallen ebenfalls raus. `foo@bar.py` ist kein Befund.

### IP-Adressen

IPv4 erkennt ein Regex. Für IPv6 sucht ein grobes Muster Kandidaten, und `ipaddress.ip_address()` prüft jeden davon. So fallen Uhrzeiten, CSS-Werte und Hashes raus. Ein alleinstehendes `::` meldet der Scanner nicht, das ist fast immer C++-Syntax oder eine Regex-Gruppe `(?::`.

Vierteilige Versionsnummern sehen aus wie IPv4. Der Scanner überspringt sie, wenn der Kontext eindeutig ist:

- Davor steht ein Versions-Schlüsselwort: `version = "1.2.3.4"`, `"version": "1.2.3.4"`, `APP_VERSION=1.2.3.4`, `Version 7.1.1.6`
- Davor steht ein Pin-Operator aus pip oder npm: `==`, `>=`, `<=`, `~=`, `!=`, `^`, `~`
- Die Zahl ist Teil einer längeren Punktkette: `25.0.5.0.9`, OIDs wie `1.3.6.1.4.1.2021`

Mehr rät der Scanner nicht. Kapitelnummern in Kommentaren (`# 7.1.1.6 Proxy`) oder Fließtext (`auf 1.2.1.0 aktualisieren`) bleiben Befunde, weil sich das nicht zuverlässig von `# 10.0.0.1 Gateway` unterscheiden lässt. Für solche Zeilen gibt es `scan:ignore` (siehe unten).

## Erlauben und Ignorieren

Es gibt vier Wege, bekannte Werte auszublenden. Sie wirken zusammen.

### `scan:ignore` in der Zeile

Steht `scan:ignore` irgendwo in einer Zeile, meldet der Scanner für diese Zeile nichts. Groß-/Kleinschreibung spielt keine Rolle. Meist kommt der Marker in einen Kommentar:

```python
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"  # scan:ignore
```

```yaml
endpoint: https://partner.example.com/api  # scan:ignore, vertraglich vereinbart
```

Der Marker gilt nur für seine eigene Zeile. In Formaten ohne Kommentare wie JSON geht das nicht, dort helfen `--allow` oder die Whitelist. Ein kurzer Grund hinter dem Marker hilft beim nächsten Review.

### `--allow` und `--allow-file`

Muster für einzelne Läufe oder repo-spezifische Ausnahmen. `--allow-file` liest ein Muster pro Zeile, Zeilen mit `#` am Anfang sind Kommentare.

Wie ein Muster greift, hängt von seiner Form ab:

- **Reine Domain** wie `mycompany.com` oder `mycompany\.com`. Der Scanner vergleicht sie mit dem Host des Befunds (bei URLs, Hostnamen und E-Mails). Erlaubt sind die Domain selbst und ihre Subdomains. `evil-mycompany.com.attacker.net` bleibt ein Befund.
- **Alles andere** gilt als Regex und wird im kompletten Wert gesucht, ohne Groß-/Kleinschreibung. Ist das Muster kein gültiger Regex, sucht der Scanner es als einfachen Text.

```bash
python3 scan-external-urls.py --allow mycompany.com "localhost" "^https://intern\."
```

Regex-Muster sind mächtig, aber auch leicht zu weit gefasst. `example` erlaubt auch `example.attacker.net`. Für Domains also lieber die reine Domain-Form nehmen.

### `whitelist.json`

Dauerhafte Ausnahmen, die ein Team pflegt. Das Skript lädt automatisch eine `whitelist.json` aus dem Wurzelverzeichnis des **gescannten Repositories** und meldet das auf stderr. Mit `--whitelist DATEI` gibt man eine andere Datei an, dann entfällt die automatische Suche.

```json
{
  "ip_ranges":     ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "hostnames":     ["localhost", "github.com", "*.docker.com"],
  "email_domains": ["example.com"],
  "urls":          ["http://10.100.0.100"]
}
```

| Feld | Wirkung |
| --- | --- |
| `ip_ranges` | CIDR-Netze oder einzelne Adressen, IPv4 und IPv6. Gilt für Befunde der Kategorie `ip` und für URLs mit IP als Host (`http://10.0.0.5:8080/api`). Ungültige Einträge erzeugen eine Warnung und werden übersprungen. |
| `hostnames` | Domain plus alle Subdomains. Ein führendes `*.` wird entfernt, `*.docker.com` und `docker.com` wirken also gleich. Gilt für Hostnamen und für den Host-Teil von URLs. |
| `email_domains` | Exakter Vergleich mit dem Teil nach dem `@`. Subdomains zählen nicht. |
| `urls` | URL-Präfixe. Eine URL ist erlaubt, wenn sie mit einem Eintrag beginnt und danach `/`, `?`, `#`, `:` oder nichts mehr folgt. `http://10.100.0.100` erlaubt also `http://10.100.0.100:8080/x`, aber nicht `http://10.100.0.100.evil.net/x`. Endet der Eintrag selbst auf `/`, `?` oder `#`, reicht der Präfix. |

Alle Vergleiche ignorieren Groß-/Kleinschreibung.

### IP-Adressen ignorieren

- `--ignore-all-ips` schaltet die IP-Erkennung komplett ab. Sinnvoll für Ansible- oder Netzwerk-Repos, in denen IPs gewollt sind.
- `--ignore-ips 192.168.1.1 10.0.0.0/8 fe80::/10` ignoriert einzelne Adressen und ganze Netze.
- `--ignore-ips-file DATEI` liest einen Eintrag pro Zeile, `#` für Kommentare.

Der Vergleich läuft über `ipaddress`, `fe80:0:0::1` und `fe80::1` gelten also als gleich. Ungültige Einträge erzeugen eine Warnung auf stderr und werden übersprungen. Anders als `ip_ranges` in der Whitelist wirken diese Optionen nur auf die Kategorie `ip`, nicht auf URLs.

## Alle Optionen

| Option | Bedeutung |
| --- | --- |
| `repo` | Pfad zum Repository-Wurzelverzeichnis, Standard `.` |
| `--categories KAT ...` | Nur diese Kategorien: `url`, `email`, `hostname`, `ip` |
| `--allow MUSTER ...` | Erlaubte Muster, siehe oben |
| `--allow-file DATEI` | Erlaubte Muster aus Datei |
| `--skip MUSTER ...` | Regex auf den relativen Pfad, passende Dateien werden übersprungen (z. B. `docs/` `fixtures/`) |
| `--skip-tests` | Testdateien überspringen |
| `--format text\|json\|sarif` | Ausgabeformat, Standard `text` |
| `--no-fail` | Immer mit Exit-Code 0 beenden |
| `--ignore-all-ips` | Keine IP-Adressen melden |
| `--ignore-ips IP ...` | Diese IPs oder CIDR-Netze nicht melden |
| `--ignore-ips-file DATEI` | IPs oder CIDR-Netze aus Datei nicht melden |
| `--whitelist DATEI` | Whitelist-Datei statt `<repo>/whitelist.json` |

## Ausgabe

Die Textausgabe gruppiert nach Kategorie und zeigt Datei, Zeile, Wert und die Zeile selbst (gekürzt auf 120 Zeichen):

```text
Scanning 42 tracked file(s) in '/pfad/zum/repo' …

======================================================================
  External reference scan — 2 finding(s)
======================================================================

  URLs (1)
  ----------------------------------------
  src/client.py:17
    Value  : https://api.example.com/v2
    Context: BASE_URL = "https://api.example.com/v2"

  Emails (1)
  ----------------------------------------
  README.md:88
    Value  : admin@company.com
    Context: Kontakt: admin@company.com
...
```

Mit `--format json` kommt ein Array, eine Zeile pro Befund. Die Zeile "Scanning ..." entfällt dann, damit die Ausgabe gültiges JSON bleibt:

```json
[
  {
    "category": "url",
    "value": "https://api.example.com/v2",
    "file": "src/client.py",
    "line": 17,
    "context": "BASE_URL = \"https://api.example.com/v2\""
  }
]
```

Mit `--format sarif` kommt ein SARIF-2.1.0-Log, das GitHub Code Scanning, GitLab und viele IDE-Plugins direkt lesen. Jede Kategorie ist eine Regel (`url`, `email`, `hostname`, `ip`), jeder Befund ein Result mit Level `warning`, relativem Dateipfad und Zeile. Auch hier entfällt die Zeile "Scanning ...".

## Exit-Codes

| Code | Bedeutung |
| --- | --- |
| `0` | Keine Befunde, oder `--no-fail` ist gesetzt |
| `1` | Befunde gefunden |
| `2` | Fehler: kein Repository-Wurzelverzeichnis, Datei nicht lesbar, ungültiges Whitelist-JSON, `git ls-files` fehlgeschlagen |

## CI-Beispiel

```yaml
# GitLab CI
external-urls:
  stage: test
  script:
    - python3 scan-tools/scan-external-urls.py . --skip-tests --format json > external-urls.json
  artifacts:
    when: always
    paths: [external-urls.json]
```

Der Job schlägt bei Befunden fehl. Für einen reinen Report ohne Abbruch `--no-fail` anhängen.

```yaml
# GitHub Actions mit Code Scanning
- name: Scan external URLs
  run: python3 scan-tools/scan-external-urls.py . --skip-tests --format sarif --no-fail > external-urls.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: external-urls.sarif
```

Hier sorgt `--no-fail` dafür, dass der Upload trotz Befunden läuft. Die Befunde erscheinen dann im Security-Tab und als Annotation im Pull Request.

## Viele Repositories auf einmal

`scan-all-repos.sh` ruft den Scanner für jedes Git-Repository eine Ebene unter einem Verzeichnis auf. Optionen nach `--` gehen an den Scanner:

```bash
./scan-all-repos.sh scan-external-urls.py ~/projects --whitelist whitelist.json -- --skip-tests
```

Ohne `--whitelist` würde jedes Repository seine eigene `whitelist.json` suchen. Mit der Option gilt die zentrale Datei für alle.

## Bekannte Grenzen

Stand 24.10.2026:

- **Versionsnummern ohne Kontext.** Kapitelnummern und Versionen im Fließtext (`# 7.1.1.6 Proxy`, `auf 1.2.1.0 aktualisieren`) erscheinen als IPv4-Befund. Abhilfe ist `scan:ignore` oder `--skip`.
- **IPv6 in URLs.** URLs mit eckigen Klammern wie `http://[::1]:8080/` erkennt der URL-Regex nicht. Die Adresse selbst taucht dann als `ip`-Befund auf.
- **`scan:ignore` nur für die eigene Zeile.** Es gibt keine Variante für die nächste Zeile oder eine ganze Datei. Ganze Dateien schließt `--skip` aus.

## Tests

```bash
uv run pytest test_scan_external_urls.py -v
```
