#!/usr/bin/env python3
"""
vulnerabilities.py - Lädt die Node.js-Schwachstellen (https://nodejs.org/en/blog/vulnerability/)
herunter und gibt sie gefiltert aus.

Quellen (pro CVE zusammengeführt):
  - Die Security-Release-Blogposts als Markdown aus dem nodejs.org-Repository
    (Liste der Posts aus dem RSS-Feed). Daraus: Titel, Severity, Beschreibung,
    betroffene Release-Linien, Veröffentlichungsdatum und die Release-Versionen.
  - Die Core-Vulnerability-Datenbank der Node.js Security WG
    (nodejs/security-wg vuln/core/index.json). Daraus: exakte Versionsbereiche
    (vulnerable/patched) und CVEs, die in keiner Blog-Überschrift stehen.
  Der Blog ist aktueller als die Datenbank, die Datenbank präziser bei Versionen.

Unterbefehle:
  download  Daten herunterladen und in die lokale Kopie einführen (überspringt den
            Download, solange die lokale Kopie jünger als --max-age-hours ist;
            --force erzwingt ihn). Die lokale Kopie wächst nur: neue CVEs kommen
            hinzu, geänderte werden aktualisiert, verschwundene bleiben erhalten.
  list      Einträge nach Veröffentlichung (neueste zuerst) ausgeben, optional gefiltert
  search    Volltextsuche (alle Begriffe müssen vorkommen), sonst wie list
  show      Alle Details zu einzelnen CVE-IDs ausgeben

Die lokale Kopie liegt standardmäßig neben diesem Skript (nodejs/vulnerabilities.json)
und ist versioniert. Sie wird immer gleich formatiert und sortiert geschrieben,
damit git-Diffs nur echte Änderungen zeigen.

Beispiele:
  python3 nodejs/vulnerabilities.py download
  python3 nodejs/vulnerabilities.py list --line 22 --min-severity high
  python3 nodejs/vulnerabilities.py list --since 2026-01-01 --format json
  python3 nodejs/vulnerabilities.py search "permission model" realpath
  python3 nodejs/vulnerabilities.py show CVE-2026-111497

Exit-Codes:
  0 - Erfolg
  1 - show: mindestens eine CVE-ID nicht vorhanden
  2 - Skriptfehler (Download fehlgeschlagen, Datei fehlt/ungültig, ...)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

SOURCE_URL = "https://nodejs.org/en/blog/vulnerability/"
FEED_URL = "https://nodejs.org/en/feed/vulnerability.xml"
POST_URL = "https://nodejs.org/en/blog/vulnerability/{slug}"
POST_SOURCE_URL = "https://raw.githubusercontent.com/nodejs/nodejs.org/main/apps/site/pages/en/blog/vulnerability/{slug}{ext}"
POST_SOURCE_EXTS = (".md", ".mdx")
NSWG_URL = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json"
DEFAULT_FILE = Path(__file__).resolve().parent / "vulnerabilities.json"
DOWNLOAD_TIMEOUT = 30
DOWNLOAD_RETRIES = 3
DOWNLOAD_WORKERS = 4
DEFAULT_MAX_AGE_HOURS = 24.0

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
_SEVERITY_WORDS = r"critical|high|medium|moderate|low"

# Slugs landen in einer URL — nur das bekannte Format zulassen
SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Steuerzeichen (inkl. ESC) aus heruntergeladenen Texten entfernen, damit
# manipulierte Inhalte keine Terminal-Escape-Sequenzen ausführen können.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


class VulnError(Exception):
    """Daten fehlen, sind ungültig oder konnten nicht geladen werden."""


def clean(value: Any) -> str:
    return _CONTROL_CHARS.sub("", str(value if value is not None else ""))


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def http_get(url: str, allow_404: bool = False) -> bytes | None:
    request = urllib.request.Request(url, headers={"User-Agent": "scan-tools-nodejs/1.0"})
    last_exc: Exception | None = None
    for attempt in range(DOWNLOAD_RETRIES):
        try:
            with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and allow_404:
                return None
            last_exc = exc
        except OSError as exc:
            last_exc = exc
        time.sleep(1 + attempt * 2)
    raise VulnError(f"Download von {url} fehlgeschlagen: {last_exc}")


def fetch_post_slugs() -> list[str]:
    raw = http_get(FEED_URL)
    try:
        root = ET.fromstring(raw or b"")
    except ET.ParseError as exc:
        raise VulnError(f"RSS-Feed {FEED_URL} ist ungültig: {exc}") from exc

    slugs = []
    for item in root.iter("item"):
        link = (item.findtext("link") or "").strip().rstrip("/")
        slug = link.rsplit("/", 1)[-1]
        if not SLUG_PATTERN.match(slug):
            print(f"WARNUNG: unbekannter Post-Link '{clean(link)}' übersprungen", file=sys.stderr)
            continue
        slugs.append(slug)
    if not slugs:
        raise VulnError(f"RSS-Feed {FEED_URL} enthält keine Posts")
    return slugs


def fetch_post(slug: str) -> str | None:
    """Markdown-Quelle eines Posts (.md oder .mdx); None, wenn keine existiert."""
    for ext in POST_SOURCE_EXTS:
        raw = http_get(POST_SOURCE_URL.format(slug=slug, ext=ext), allow_404=True)
        if raw is not None:
            return raw.decode("utf-8", errors="replace")
    return None


def fetch_nswg() -> dict[str, Any]:
    try:
        data = json.loads(http_get(NSWG_URL) or b"")
    except json.JSONDecodeError as exc:
        raise VulnError(f"{NSWG_URL} lieferte kein gültiges JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise VulnError(f"Unerwartetes Format von {NSWG_URL}")
    return data


# ---------------------------------------------------------------------------
# Blogposts parsen
# ---------------------------------------------------------------------------

def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if not m:
        return {}, text
    meta = {}
    for line in m.group(1).splitlines():
        key, sep, value = line.partition(":")
        if sep:
            meta[key.strip()] = value.strip().strip("'\"")
    return meta, text[m.end():]


def normalize_severity(raw: str | None) -> str:
    s = (raw or "").strip().upper()
    return "MEDIUM" if s == "MODERATE" else (s if s in SEVERITY_ORDER else "")


def _md_links(text: str) -> str:
    """[Text](url) → 'Text (url)', relative Links absolut auf nodejs.org."""
    def repl(m: re.Match[str]) -> str:
        label, url = m.group(1), m.group(2)
        if url.startswith("/"):
            url = "https://nodejs.org" + url
        return label if label == url else f"{label} ({url})"
    return re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", repl, text)


def parse_heading(heading: str) -> tuple[list[str], str, str]:
    """CVE-IDs, Titel und Severity aus einer Überschrift in allen bisherigen Formaten:
    '## Titel (CVE-…) - (high)', '### Titel (High) (CVE-…)', '### CVE-…: Titel - Moderate', …"""
    cves = list(dict.fromkeys(c.upper() for c in _CVE_IN_TEXT.findall(heading)))
    sev = re.search(rf"\(\s*({_SEVERITY_WORDS})\s*\)", heading, re.IGNORECASE) or re.search(
        rf"[-–]\s*({_SEVERITY_WORDS})\s*$", heading, re.IGNORECASE)

    title = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", heading)
    title = re.sub(r"\(\s*CVE-[^)]*\)", "", title, flags=re.IGNORECASE)
    title = re.sub(rf"\(\s*({_SEVERITY_WORDS})\s*\)", "", title, flags=re.IGNORECASE)
    title = re.sub(rf"[-–]\s*({_SEVERITY_WORDS})\s*$", "", title, flags=re.IGNORECASE)
    title = re.sub(r"CVE-\d{4}-\d{4,}(\s*(,|and|&)\s*)?", "", title, flags=re.IGNORECASE)
    title = re.sub(r"\s+", " ", title).strip(" :-–")
    return cves, title, normalize_severity(sev.group(1) if sev else "")


# '22.x', aber auch alte Linien wie '0.12.x' — und nie '12.x' aus '0.12.x'
_LINE_IN_TEXT = re.compile(r"(?<![\d.])((?:0\.)?\d{1,2})\.x\b")


def line_key(line: str) -> tuple[int, ...]:
    return tuple(int(x) for x in line.removesuffix(".x").split("."))


def affected_lines(text: str) -> list[str]:
    """Release-Linien aus Sätzen wie 'affects Node.js **26.x**, **24.x**' oder
    'affects … on Node.js v20, v22'. Verneinte Sätze ('does not affect') zählen nicht."""
    found: set[str] = set()
    for sentence in re.split(r"(?<=[.!?])\s+|\n", text.replace("*", "")):
        if not re.search(r"affect|impact|vulnerab", sentence, re.IGNORECASE) or re.search(r"\bnot\b|n't", sentence, re.IGNORECASE):
            continue
        found.update(f"{n}.x" for n in _LINE_IN_TEXT.findall(sentence))
        found.update(f"{int(n)}.x" for n in re.findall(r"\bv(\d{1,2})\b(?!\.)", sentence))
    return sorted(found, key=line_key, reverse=True)


def parse_post(slug: str, text: str) -> list[dict[str, Any]]:
    """Ein Eintrag pro CVE aus allen Überschriften, die CVE-IDs enthalten."""
    meta, body = parse_frontmatter(text)
    lines = body.splitlines()
    post = {
        "url": POST_URL.format(slug=slug),
        "title": meta.get("title", slug),
        "date": meta.get("date", "")[:10],
    }
    releases = sorted(set(re.findall(r"/blog/release/v(\d+\.\d+\.\d+)", body)),
                      key=lambda v: tuple(int(x) for x in v.split(".")), reverse=True)

    entries = []
    for i, line in enumerate(lines):
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if not m or not _CVE_IN_TEXT.search(m.group(2)):
            continue
        level = len(m.group(1))
        end = next((j for j in range(i + 1, len(lines))
                    if (h := re.match(r"^(#{1,6})\s", lines[j])) and len(h.group(1)) <= level), len(lines))
        section = "\n".join(lines[i + 1:end]).strip()
        section = re.sub(r"\n{3,}", "\n\n", _md_links(section))
        cves, title, severity = parse_heading(m.group(2))
        for cve in cves:
            entries.append({
                "id": cve,
                "title": title,
                "severity": severity,
                "description": section,
                "affectedLines": affected_lines(section),
                "releases": releases,
                "post": post,
            })
    return entries


# ---------------------------------------------------------------------------
# Zusammenführen
# ---------------------------------------------------------------------------

def _majors(semver_range: str) -> list[str]:
    return sorted({f"{n}.x" for n in _LINE_IN_TEXT.findall(semver_range)}, key=line_key, reverse=True)


def _first_sentence(text: str, limit: int = 160) -> str:
    first = re.split(r"(?<=[.!?])\s", text.strip(), maxsplit=1)[0].split("\n")[0].strip()
    return first if len(first) <= limit else first[: limit - 1].rsplit(" ", 1)[0] + " …"


def build_entries(posts: dict[str, str], nswg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    blog: dict[str, dict[str, Any]] = {}
    post_by_url: dict[str, dict[str, str]] = {}
    for slug, text in posts.items():
        for entry in parse_post(slug, text):
            # Mehrfach genannte CVE (z. B. Update-Post): ältesten Post behalten
            if entry["id"] not in blog or entry["post"]["date"] < blog[entry["id"]]["post"]["date"]:
                blog[entry["id"]] = entry
        meta, _ = parse_frontmatter(text)
        post_by_url[POST_URL.format(slug=slug)] = {
            "url": POST_URL.format(slug=slug), "title": meta.get("title", slug), "date": meta.get("date", "")[:10],
        }

    result: dict[str, dict[str, Any]] = {}
    nswg_by_cve: dict[str, tuple[str, dict[str, Any]]] = {}
    for key, v in nswg.items():
        if not isinstance(v, dict):
            continue
        cves = [str(c).upper() for c in v.get("cve") or [] if CVE_PATTERN.match(str(c))]
        for cve in cves or [f"NSWG-CORE-{key}"]:
            nswg_by_cve[cve] = (key, v)

    for cve in sorted(set(blog) | set(nswg_by_cve)):
        b = blog.get(cve, {})
        key, n = nswg_by_cve.get(cve, ("", {}))
        ref = str(n.get("ref") or "").rstrip("/")
        post = b.get("post") or post_by_url.get(ref) or ({"url": ref, "title": "", "date": ""} if ref else {})
        vulnerable = str(n.get("vulnerable") or "")
        lines = sorted(set(b.get("affectedLines", [])) | set(_majors(vulnerable)), key=line_key, reverse=True)
        published = post.get("date") or _parse_date(n.get("publish_date"))
        result[cve] = {
            "id": cve,
            "title": b.get("title") or str(n.get("description") or "").strip()
                     or _first_sentence(str(n.get("overview") or "")),
            "severity": b.get("severity") or normalize_severity(n.get("severity")),
            "published": published,
            "affectedLines": lines,
            "vulnerable": vulnerable,
            "patched": str(n.get("patched") or ""),
            "releases": b.get("releases", []),
            "description": b.get("description") or _md_links(str(n.get("overview") or "").strip()),
            "cvss": str(n.get("cvss") or ""),
            "cvssScore": n.get("cvss_score") or "",
            "reportedBy": str(n.get("reported_by") or ""),
            "post": post,
            "nswg": f"NSWG-CORE-{key}" if key else "",
            "sources": [s for s, present in (("blog", bool(b)), ("security-wg", bool(key))) if present],
        }
    return result


def _parse_date(raw: Any) -> str:
    if not raw:
        return ""
    s = str(raw)
    try:
        return dt.date.fromisoformat(s[:10]).isoformat()
    except ValueError:
        pass
    try:
        # publish_date in der DB ist teils ein Unix-Zeitstempel
        return dt.datetime.fromtimestamp(float(s), tz=dt.timezone.utc).date().isoformat()
    except (ValueError, OverflowError, OSError):
        return ""


def merge_vulns(local: dict[str, Any] | None, quiet: bool) -> tuple[dict[str, Any], dict[str, int]]:
    slugs = fetch_post_slugs()
    if not quiet:
        print(f"Lade {len(slugs)} Blogposts und die Security-WG-Datenbank ...", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as pool:
        texts = dict(zip(slugs, pool.map(fetch_post, slugs)))
    for slug, text in texts.items():
        if text is None:
            print(f"WARNUNG: Quelle für Post '{slug}' nicht gefunden", file=sys.stderr)
    posts = {slug: text for slug, text in texts.items() if text is not None}
    fresh = build_entries(posts, fetch_nswg())

    local_by_id = {str(v.get("id", "")).upper(): v for v in (local or {}).get("vulnerabilities", [])}
    stats = {"neu": 0, "aktualisiert": 0, "unverändert": 0, "nur lokal": 0}
    merged: dict[str, dict[str, Any]] = {}
    for key, entry in fresh.items():
        old = local_by_id.get(key)
        if old is None:
            stats["neu"] += 1
        elif old != entry:
            stats["aktualisiert"] += 1
        else:
            stats["unverändert"] += 1
        merged[key] = entry
    for key, entry in local_by_id.items():
        if key not in merged:
            stats["nur lokal"] += 1
            merged[key] = entry

    vulns = sorted(merged.values(), key=lambda v: (v.get("published", ""), v.get("id", "")), reverse=True)
    return {"source": SOURCE_URL, "count": len(vulns), "vulnerabilities": vulns}, stats


# ---------------------------------------------------------------------------
# Laden / Speichern
# ---------------------------------------------------------------------------

def validate(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise VulnError("Unerwartetes Format: Schlüssel 'vulnerabilities' fehlt")
    return data


def load_vulns(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise VulnError(f"Datei '{path}' nicht gefunden — zuerst 'download' ausführen oder --refresh verwenden")
    try:
        with path.open(encoding="utf-8") as fh:
            return validate(json.load(fh))
    except json.JSONDecodeError as exc:
        raise VulnError(f"Datei '{path}' ist kein gültiges JSON: {exc}") from exc


def dump_vulns(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def save_vulns(path: Path, data: dict[str, Any]) -> None:
    # Erst in eine temporäre Datei schreiben und dann ersetzen — ein Abbruch
    # hinterlässt so nie eine halbe Datei.
    path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp legt die Datei mit 0600 an — Rechte der bestehenden Datei übernehmen
    try:
        mode = path.stat().st_mode & 0o777
    except FileNotFoundError:
        mode = 0o644
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(dump_vulns(data))
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def file_age_hours(path: Path) -> float | None:
    try:
        return (time.time() - path.stat().st_mtime) / 3600
    except FileNotFoundError:
        return None


def ensure_vulns(path: Path, force: bool, max_age_hours: float, quiet: bool = False) -> dict[str, Any]:
    """Lädt nur neu, wenn erzwungen oder die lokale Kopie zu alt ist, und führt die Daten ein."""
    age = file_age_hours(path)
    if not force and age is not None and age < max_age_hours:
        if not quiet:
            print(f"Lokale Kopie ist {age:.1f} h alt (< {max_age_hours:g} h) — kein Download nötig.", file=sys.stderr)
        return load_vulns(path)

    # Lokale Kopie vor dem Download laden: ist sie kaputt, bricht load_vulns ab,
    # statt den angesammelten Bestand zu überschreiben.
    local = load_vulns(path) if path.exists() else None
    if not quiet:
        print(f"Lade {FEED_URL} ...", file=sys.stderr)
    merged, stats = merge_vulns(local, quiet=quiet)
    save_vulns(path, merged)
    if not quiet:
        print(", ".join(f"{n} {label}" for label, n in stats.items()), file=sys.stderr)
    return merged


# ---------------------------------------------------------------------------
# Filtern / Ausgabe
# ---------------------------------------------------------------------------

SEARCH_FIELDS = ("id", "title", "description", "vulnerable", "patched", "affectedLines", "reportedBy", "nswg")


def search_text(v: dict[str, Any]) -> str:
    """Alle durchsuchbaren Felder eines Eintrags als ein String (Listen zusammengefügt)."""
    parts = []
    for key in SEARCH_FIELDS:
        value = v.get(key)
        parts.append(" ".join(map(str, value)) if isinstance(value, list) else str(value or ""))
    parts.append(str((v.get("post") or {}).get("title", "")))
    return "\n".join(parts)


def filter_vulns(
    vulns: list[dict[str, Any]],
    line: str | None = None,
    min_severity: str | None = None,
    terms: list[re.Pattern[str]] | None = None,
    since: str | None = None,
) -> list[dict[str, Any]]:
    min_order = SEVERITY_ORDER[min_severity] if min_severity else -1
    result = []
    for v in vulns:
        if line and line not in v.get("affectedLines", []):
            continue
        if SEVERITY_ORDER.get(str(v.get("severity", "")).upper(), -1) < min_order:
            continue
        # ISO-Datumsstrings (YYYY-MM-DD) lassen sich direkt lexikografisch vergleichen
        if since and str(v.get("published", "")) < since:
            continue
        # Mehrere Suchbegriffe sind UND-verknüpft
        if terms:
            text = search_text(v)
            if not all(t.search(text) for t in terms):
                continue
        result.append(v)
    return sorted(result, key=lambda v: (str(v.get("published", "")), str(v.get("id", ""))), reverse=True)


def format_line(v: dict[str, Any]) -> str:
    lines = ",".join(v.get("affectedLines", [])) or "-"
    return (
        f"{clean(v.get('published')) or '?':<10}  {clean(v.get('id')):<16}  {clean(v.get('severity')) or '?':<8}  "
        f"{clean(lines):<14}  {clean(v.get('title'))}"
    )


def format_details(v: dict[str, Any]) -> str:
    def row(label: str, value: Any) -> str:
        return f"{label + ':':<16}{clean(value)}"

    post = v.get("post") or {}
    lines = [row(label, value) for label, value in (
        ("CVE", v.get("id")), ("Titel", v.get("title")), ("Severity", v.get("severity")),
        ("Veröffentlicht", v.get("published")), ("Release-Linien", ", ".join(v.get("affectedLines", []))),
        ("Verwundbar", v.get("vulnerable")), ("Gepatcht", v.get("patched")),
        ("Releases", ", ".join(v.get("releases", []))), ("CVSS", v.get("cvss")),
        ("Gemeldet von", v.get("reportedBy")), ("Security WG", v.get("nswg")),
        ("Post", f"{post.get('title', '')} — {post.get('url', '')}" if post.get("url") else ""),
    ) if value]
    if v.get("description"):
        lines.append("Beschreibung:")
        lines.extend(f"  {clean(line)}" for line in str(v["description"]).splitlines())
    return "\n".join(lines)


def header(data: dict[str, Any]) -> str:
    vulns = data["vulnerabilities"]
    newest = max((str(v.get("published", "")) for v in vulns), default="?")
    return f"Node.js-Schwachstellen — {len(vulns)} Einträge, neueste vom {clean(newest)}"


# ---------------------------------------------------------------------------
# Unterbefehle
# ---------------------------------------------------------------------------

def cmd_download(args: argparse.Namespace) -> int:
    data = ensure_vulns(args.file, args.force, args.max_age_hours)
    print(header(data))
    print(f"Datei: {args.file}")
    return 0


def compile_terms(terms: list[str], regex: bool) -> list[re.Pattern[str]]:
    try:
        return [re.compile(t if regex else re.escape(t), re.IGNORECASE) for t in terms]
    except re.error as exc:
        raise VulnError(f"Ungültiger regulärer Ausdruck: {exc}") from exc


def cmd_list(args: argparse.Namespace) -> int:
    """Gemeinsame Implementierung für 'list' und 'search' (list hat keine Suchbegriffe)."""
    terms = compile_terms(args.terms, args.regex)
    if args.refresh:
        data = ensure_vulns(args.file, force=False, max_age_hours=args.max_age_hours, quiet=args.format == "json")
    else:
        data = load_vulns(args.file)

    vulns = filter_vulns(
        data["vulnerabilities"],
        line=args.line,
        min_severity=args.min_severity,
        terms=terms,
        since=args.since,
    )
    total = len(vulns)
    if args.limit > 0:
        vulns = vulns[: args.limit]

    if args.format == "json":
        json.dump(vulns, sys.stdout, indent=2, ensure_ascii=False)
        print()
        return 0

    print(header(data))
    print(f"{total} Treffer, zeige {len(vulns)}\n")
    for v in vulns:
        print(format_line(v))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    data = load_vulns(args.file)
    by_id = {str(v.get("id", "")).upper(): v for v in data["vulnerabilities"]}

    found: list[dict[str, Any]] = []
    missing: list[str] = []
    for cve in args.cve:
        entry = by_id.get(cve.upper())
        if entry is None:
            missing.append(cve)
        else:
            found.append(entry)

    if args.format == "json":
        json.dump(found, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        print("\n\n".join(format_details(v) for v in found))

    for cve in missing:
        print(f"{cve}: nicht in den Node.js-Schwachstellen", file=sys.stderr)
    return 1 if missing else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def iso_date(value: str) -> str:
    try:
        return dt.date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"ungültiges Datum '{value}' (erwartet YYYY-MM-DD)") from exc


def cve_id(value: str) -> str:
    if not CVE_PATTERN.match(value) and not re.match(r"^NSWG-CORE-\d+$", value, re.IGNORECASE):
        raise argparse.ArgumentTypeError(f"ungültige ID '{value}' (erwartet CVE-JJJJ-NNNN oder NSWG-CORE-N)")
    return value.upper()


def severity(value: str) -> str:
    if value.upper() not in SEVERITY_ORDER:
        raise argparse.ArgumentTypeError(f"ungültige Severity '{value}' (erlaubt: {', '.join(SEVERITIES)})")
    return value.upper()


def release_line(value: str) -> str:
    m = re.match(r"^v?((?:0\.)?\d{1,2})(\.x)?$", value, re.IGNORECASE)
    if not m:
        raise argparse.ArgumentTypeError(f"ungültige Release-Linie '{value}' (z. B. 22, 22.x oder 0.12)")
    return f"{m.group(1)}.x"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Node.js-Schwachstellen (nodejs.org/en/blog/vulnerability) herunterladen und durchsuchen.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit-Codes: 0 = OK, 1 = CVE nicht gefunden (show), 2 = Fehler",
    )
    parser.add_argument(
        "--file", type=Path, default=DEFAULT_FILE,
        help=f"Pfad der lokalen Datei (Standard: {DEFAULT_FILE.name} neben dem Skript)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_dl = sub.add_parser("download", help="Daten herunterladen")
    p_dl.add_argument("--force", action="store_true", help="Download auch bei aktueller lokaler Kopie erzwingen")
    p_dl.add_argument(
        "--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS,
        help="Lokale Kopie gilt so lange als aktuell (Standard: %(default)s)",
    )
    p_dl.set_defaults(func=cmd_download)

    # Filter- und Ausgabeoptionen, die 'list' und 'search' gemeinsam haben
    filters = argparse.ArgumentParser(add_help=False)
    filters.add_argument("-n", "--limit", type=int, default=30, help="Maximale Anzahl (0 = alle, Standard: %(default)s)")
    filters.add_argument("--line", type=release_line, help="Nur Einträge, die diese Release-Linie betreffen (z. B. 22)")
    filters.add_argument(
        "--min-severity", type=severity, metavar="SEVERITY",
        help=f"Mindest-Severity ({', '.join(SEVERITIES)}, ohne Groß-/Kleinschreibung)",
    )
    filters.add_argument("--since", type=iso_date, help="Nur Einträge ab diesem Datum (YYYY-MM-DD)")
    filters.add_argument("--format", choices=("text", "json"), default="text", help="Ausgabeformat")
    filters.add_argument(
        "--refresh", action="store_true",
        help="Vorher herunterladen, falls die lokale Kopie fehlt oder älter als --max-age-hours ist",
    )
    filters.add_argument("--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS, help=argparse.SUPPRESS)

    p_list = sub.add_parser("list", parents=[filters], help="Einträge auflisten (neueste zuerst)")
    p_list.set_defaults(func=cmd_list, terms=[], regex=False)

    p_search = sub.add_parser(
        "search", parents=[filters],
        help="Volltextsuche (CVE, Titel, Beschreibung, Versionen, Post-Titel)",
    )
    p_search.add_argument("terms", nargs="+", metavar="BEGRIFF", help="Suchbegriffe (alle müssen vorkommen)")
    p_search.add_argument("-E", "--regex", action="store_true", help="Suchbegriffe als reguläre Ausdrücke behandeln")
    p_search.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="Details zu CVE-IDs anzeigen")
    p_show.add_argument("cve", nargs="+", type=cve_id, help="Eine oder mehrere CVE-IDs (oder NSWG-CORE-N)")
    p_show.add_argument("--format", choices=("text", "json"), default="text", help="Ausgabeformat")
    p_show.set_defaults(func=cmd_show)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except VulnError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        # z. B. "vulnerabilities.py list | head" — kein Fehler, nur vorzeitig beendet
        sys.stderr.close()
        return 0


if __name__ == "__main__":
    sys.exit(main())
