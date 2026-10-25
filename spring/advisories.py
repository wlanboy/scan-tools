#!/usr/bin/env python3
"""
advisories.py - Lädt die Spring Security Advisories (https://spring.io/security)
herunter und gibt sie gefiltert aus.

Quelle sind die Gatsby-Daten hinter spring.io: eine Übersicht aller Advisories
(Severity, Datum, Projekt, betroffene Versionen) und pro CVE eine Detailseite
(Titel, Beschreibung, CVSS, Mitigation, Referenzen, Historie).

Unterbefehle:
  download  Advisories herunterladen und in die lokale Kopie einführen (überspringt
            den Download, solange die lokale Kopie jünger als --max-age-hours ist;
            --force erzwingt ihn). Details werden nur für neue Advisories oder bei
            geänderter Übersicht (Severity, Datum, Versionen) geladen, dazu immer
            die neuesten RECENT_ADVISORIES; --full lädt alle Details neu. Die lokale Kopie wächst nur: aus der Übersicht
            entfernte Advisories bleiben erhalten.
  list      Advisories nach Veröffentlichung (neueste zuerst) ausgeben, optional gefiltert
  search    Volltextsuche (alle Begriffe müssen vorkommen), sonst wie list
  show      Alle Details zu einzelnen CVE-IDs ausgeben

Die lokale Kopie liegt standardmäßig neben diesem Skript (spring/advisories.json)
und ist versioniert. Sie wird immer gleich formatiert und sortiert geschrieben,
damit git-Diffs nur echte Änderungen zeigen. HTML aus der Quelle wird als
Klartext gespeichert.

Beispiele:
  python3 spring/advisories.py download
  python3 spring/advisories.py list --project "spring security" --min-severity high
  python3 spring/advisories.py list --since 2026-01-01 --format json
  python3 spring/advisories.py search spring-webmvc "path traversal"
  python3 spring/advisories.py show CVE-2022-22965

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
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

SOURCE_URL = "https://spring.io/security"
LISTING_URL = "https://spring.io/page-data/security/page-data.json"
DETAIL_URL = "https://spring.io/page-data/security/{slug}/page-data.json"
PAGE_URL = "https://spring.io/security/{slug}"
DEFAULT_FILE = Path(__file__).resolve().parent / "advisories.json"
DOWNLOAD_TIMEOUT = 30
DOWNLOAD_RETRIES = 3
DOWNLOAD_WORKERS = 4
DEFAULT_MAX_AGE_HOURS = 24.0
# Die Übersicht hat kein Änderungsdatum: Nachbesserungen an Beschreibung oder
# Mitigation sieht man nur auf der Detailseite — die neuesten deshalb immer laden.
RECENT_ADVISORIES = 10

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# Slugs landen in einer URL — nur das bekannte Format zulassen
SLUG_PATTERN = re.compile(r"^cve-\d{4}-\d{4,}$")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Steuerzeichen (inkl. ESC) aus heruntergeladenen Texten entfernen, damit
# manipulierte Inhalte keine Terminal-Escape-Sequenzen ausführen können.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


class AdvisoryError(Exception):
    """Daten fehlen, sind ungültig oder konnten nicht geladen werden."""


def clean(value: Any) -> str:
    return _CONTROL_CHARS.sub("", str(value if value is not None else ""))


# ---------------------------------------------------------------------------
# HTML → Klartext
# ---------------------------------------------------------------------------

_BLOCK_TAGS = frozenset({"p", "div", "pre", "ul", "ol", "table", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote"})


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.in_pre = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _BLOCK_TAGS:
            self.parts.append("\n\n")
        elif tag == "li":
            self.parts.append("\n- ")
        elif tag == "br":
            self.parts.append("\n")
        if tag == "pre":
            self.in_pre += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in _BLOCK_TAGS:
            self.parts.append("\n\n")
        if tag == "pre":
            self.in_pre = max(0, self.in_pre - 1)

    def handle_data(self, data: str) -> None:
        if self.in_pre:
            self.parts.append(data)
            return
        text = re.sub(r"\s+", " ", data)
        # Zeilenanfang außerhalb von <pre>: keine führenden Leerzeichen
        if not self.parts or self.parts[-1].endswith("\n"):
            text = text.lstrip()
        self.parts.append(text)


def html_to_text(html: str | None) -> str:
    if not html:
        return ""
    parser = _TextExtractor()
    parser.feed(html)
    parser.close()
    text = "".join(parser.parts)
    text = re.sub(r"[ \t]+\n", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def http_get_json(url: str) -> Any:
    request = urllib.request.Request(url, headers={"User-Agent": "scan-tools-spring/1.0"})
    last_exc: Exception | None = None
    for attempt in range(DOWNLOAD_RETRIES):
        try:
            with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as resp:
                return json.loads(resp.read())
        except json.JSONDecodeError as exc:
            raise AdvisoryError(f"{url} lieferte kein gültiges JSON: {exc}") from exc
        except OSError as exc:
            last_exc = exc
            time.sleep(1 + attempt * 2)
    raise AdvisoryError(f"Download von {url} fehlgeschlagen: {last_exc}")


def _json_field(raw: Any, default: Any) -> Any:
    """Einige Felder liefert spring.io als JSON-String."""
    if raw in (None, ""):
        return default
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return default
    return raw


def _as_list(raw: Any) -> list[Any]:
    """JSON-Liste als String ('["CWE-79"]'), einzelner Wert oder nichts → Liste."""
    value = _json_field(raw, raw)
    if value in (None, ""):
        return []
    return value if isinstance(value, list) else [value]


def _parse_date(raw: str | None) -> str:
    if not raw:
        return ""
    for fmt in ("%Y-%m-%d", "%B %d, %Y"):
        try:
            return dt.datetime.strptime(raw, fmt).date().isoformat()
        except ValueError:
            continue
    return raw


def fetch_listing() -> list[dict[str, Any]]:
    data = http_get_json(LISTING_URL)
    try:
        nodes = data["result"]["data"]["cves"]["nodes"]
    except (KeyError, TypeError) as exc:
        raise AdvisoryError("Unerwartetes Format der Übersicht: result.data.cves.nodes fehlt") from exc

    listing = []
    for node in nodes:
        fields = node.get("fields") or {}
        slug = str(fields.get("slug", ""))
        if not SLUG_PATTERN.match(slug):
            print(f"WARNUNG: unbekannter Slug '{clean(slug)}' übersprungen", file=sys.stderr)
            continue
        affected = _json_field(fields.get("affected"), {})
        listing.append({
            "slug": slug,
            "id": slug.upper(),
            "severity": str(fields.get("severity") or "").upper(),
            "published": _parse_date(fields.get("publishedAt")),
            "project": fields.get("project") or "",
            "projectSlug": fields.get("projectSlug") or "",
            "artifacts": affected.get("artifacts", []),
            "versions": affected.get("versions", []),
        })
    return listing


def fetch_detail(item: dict[str, Any]) -> dict[str, Any]:
    """Baut einen vollständigen Eintrag aus Übersicht + Detailseite."""
    data = http_get_json(DETAIL_URL.format(slug=item["slug"]))
    try:
        result = data["result"]["data"]
        fields = result["page"]["fields"]
    except (KeyError, TypeError) as exc:
        raise AdvisoryError(f"Unerwartetes Format der Detailseite {item['slug']}") from exc

    affected = _json_field(fields.get("affected"), {})
    return {
        "id": item["id"],
        "url": PAGE_URL.format(slug=item["slug"]),
        "title": fields.get("title") or "",
        "severity": str(fields.get("severity") or item["severity"]).upper(),
        "published": _parse_date(fields.get("publishedAtRaw")) or item["published"],
        "project": fields.get("project") or item["project"],
        "projectSlug": item["projectSlug"],
        "cvssVersion": fields.get("cvssVersion") or "",
        "cvssVector": fields.get("cvssVector") or "",
        "weakness": _as_list(fields.get("weakness")),
        "artifacts": affected.get("artifacts", item["artifacts"]),
        "versions": affected.get("versions", item["versions"]),
        "description": html_to_text(result["page"].get("html")),
        "mitigation": html_to_text((result.get("mitigation") or {}).get("html")),
        "credit": html_to_text((result.get("credit") or {}).get("html")),
        "references": _json_field(fields.get("references"), []),
        "history": _json_field(fields.get("history"), []),
    }


def listing_changed(entry: dict[str, Any], item: dict[str, Any]) -> bool:
    return any(entry.get(k) != item[k] for k in ("severity", "published", "project", "artifacts", "versions"))


def merge_advisories(
    local: dict[str, Any] | None, full: bool, quiet: bool,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Lädt Übersicht + nötige Details und führt sie in die lokale Kopie ein (Schlüssel: id)."""
    local_by_id = {str(a.get("id", "")).upper(): a for a in (local or {}).get("advisories", [])}
    listing = fetch_listing()
    newest = sorted(listing, key=lambda it: (it["published"], it["id"]), reverse=True)
    recent = {it["id"] for it in newest[:RECENT_ADVISORIES]}
    todo = [it for it in listing if full or it["id"] in recent or it["id"] not in local_by_id
            or listing_changed(local_by_id[it["id"]], it)]

    if todo and not quiet:
        print(f"Lade Details für {len(todo)} von {len(listing)} Advisories ...", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as pool:
        fetched = {entry["id"]: entry for entry in pool.map(fetch_detail, todo)}

    stats = {"neu": 0, "aktualisiert": 0, "unverändert": 0, "nur lokal": 0}
    merged: dict[str, dict[str, Any]] = {}
    for it in listing:
        old = local_by_id.get(it["id"])
        new = fetched.get(it["id"], old)
        if new is None:
            continue
        if old is None:
            stats["neu"] += 1
        elif new != old:
            stats["aktualisiert"] += 1
        else:
            stats["unverändert"] += 1
        merged[it["id"]] = new
    for key, entry in local_by_id.items():
        if key not in merged:
            stats["nur lokal"] += 1
            merged[key] = entry

    advisories = sorted(merged.values(), key=lambda a: (a.get("published", ""), a.get("id", "")), reverse=True)
    return {"source": SOURCE_URL, "count": len(advisories), "advisories": advisories}, stats


# ---------------------------------------------------------------------------
# Laden / Speichern
# ---------------------------------------------------------------------------

def validate(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get("advisories"), list):
        raise AdvisoryError("Unerwartetes Format: Schlüssel 'advisories' fehlt")
    return data


def load_advisories(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise AdvisoryError(f"Datei '{path}' nicht gefunden — zuerst 'download' ausführen oder --refresh verwenden")
    try:
        with path.open(encoding="utf-8") as fh:
            return validate(json.load(fh))
    except json.JSONDecodeError as exc:
        raise AdvisoryError(f"Datei '{path}' ist kein gültiges JSON: {exc}") from exc


def dump_advisories(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def save_advisories(path: Path, data: dict[str, Any]) -> None:
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
            fh.write(dump_advisories(data))
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def file_age_hours(path: Path) -> float | None:
    try:
        return (time.time() - path.stat().st_mtime) / 3600
    except FileNotFoundError:
        return None


def ensure_advisories(
    path: Path, force: bool, max_age_hours: float, full: bool = False, quiet: bool = False,
) -> dict[str, Any]:
    """Lädt nur neu, wenn erzwungen oder die lokale Kopie zu alt ist, und führt die Daten ein."""
    age = file_age_hours(path)
    if not force and not full and age is not None and age < max_age_hours:
        if not quiet:
            print(f"Lokale Kopie ist {age:.1f} h alt (< {max_age_hours:g} h) — kein Download nötig.", file=sys.stderr)
        return load_advisories(path)

    # Lokale Kopie vor dem Download laden: ist sie kaputt, bricht load_advisories ab,
    # statt den angesammelten Bestand zu überschreiben.
    local = load_advisories(path) if path.exists() else None
    if not quiet:
        print(f"Lade {LISTING_URL} ...", file=sys.stderr)
    merged, stats = merge_advisories(local, full=full, quiet=quiet)
    save_advisories(path, merged)
    if not quiet:
        print(", ".join(f"{n} {label}" for label, n in stats.items()), file=sys.stderr)
    return merged


# ---------------------------------------------------------------------------
# Filtern / Ausgabe
# ---------------------------------------------------------------------------

SEARCH_FIELDS = (
    "id", "title", "project", "description", "mitigation",
    "artifacts", "references", "cvssVector", "weakness",
)


def search_text(a: dict[str, Any]) -> str:
    """Alle durchsuchbaren Felder eines Eintrags als ein String (Listen zusammengefügt)."""
    parts = []
    for key in SEARCH_FIELDS:
        value = a.get(key)
        parts.append(" ".join(map(str, value)) if isinstance(value, list) else str(value or ""))
    return "\n".join(parts)


def filter_advisories(
    advisories: list[dict[str, Any]],
    project: str | None = None,
    min_severity: str | None = None,
    terms: list[re.Pattern[str]] | None = None,
    since: str | None = None,
) -> list[dict[str, Any]]:
    min_order = SEVERITY_ORDER[min_severity] if min_severity else -1
    result = []
    for a in advisories:
        if project and project.lower() not in str(a.get("project", "")).lower():
            continue
        if SEVERITY_ORDER.get(str(a.get("severity", "")).upper(), -1) < min_order:
            continue
        # ISO-Datumsstrings (YYYY-MM-DD) lassen sich direkt lexikografisch vergleichen
        if since and str(a.get("published", "")) < since:
            continue
        # Mehrere Suchbegriffe sind UND-verknüpft
        if terms:
            text = search_text(a)
            if not all(t.search(text) for t in terms):
                continue
        result.append(a)
    return sorted(result, key=lambda a: (str(a.get("published", "")), str(a.get("id", ""))), reverse=True)


def format_line(a: dict[str, Any]) -> str:
    return (
        f"{clean(a.get('published')):<10}  {clean(a.get('id')):<16}  {clean(a.get('severity')):<8}  "
        f"{clean(a.get('project'))} | {clean(a.get('title'))}"
    )


def format_versions(versions: list[dict[str, Any]]) -> list[str]:
    lines = []
    for v in versions:
        rng = f"{clean(v.get('introduced') or '?')} – {clean(v.get('last-affected') or '?')}"
        fixes = ", ".join(f"{clean(f.get('version'))} ({clean(f.get('availability'))})" for f in v.get("fixes", []))
        lines.append(f"{rng}  →  {fixes or 'kein Fix'}")
    return lines


def format_details(a: dict[str, Any]) -> str:
    def row(label: str, value: Any) -> str:
        return f"{label + ':':<16}{clean(value)}"

    lines = [row(label, a.get(key)) for label, key in (
        ("CVE", "id"), ("Titel", "title"), ("Projekt", "project"), ("Severity", "severity"),
        ("Veröffentlicht", "published"), ("CVSS", "cvssVector"), ("Link", "url"),
    ) if a.get(key)]
    for label, key in (("CWE", "weakness"), ("Artefakte", "artifacts")):
        if a.get(key):
            lines.append(row(label, ", ".join(map(str, a[key]))))
    if a.get("versions"):
        lines.append("Betroffen:")
        lines.extend(f"  {v}" for v in format_versions(a["versions"]))
    for label, key in (("Beschreibung", "description"), ("Mitigation", "mitigation"), ("Credit", "credit")):
        if a.get(key):
            lines.append(f"{label}:")
            lines.extend(f"  {clean(line)}" for line in str(a[key]).splitlines())
    if a.get("references"):
        lines.append("Referenzen:")
        lines.extend(f"  {clean(r)}" for r in a["references"])
    for h in a.get("history") or []:
        lines.append(row("Historie", f"{h.get('date', '')} {h.get('action', '')}"))
    return "\n".join(lines)


def header(data: dict[str, Any]) -> str:
    advisories = data["advisories"]
    newest = max((str(a.get("published", "")) for a in advisories), default="?")
    return f"Spring Security Advisories — {len(advisories)} Einträge, neuester vom {clean(newest)}"


# ---------------------------------------------------------------------------
# Unterbefehle
# ---------------------------------------------------------------------------

def cmd_download(args: argparse.Namespace) -> int:
    data = ensure_advisories(args.file, args.force, args.max_age_hours, full=args.full)
    print(header(data))
    print(f"Datei: {args.file}")
    return 0


def compile_terms(terms: list[str], regex: bool) -> list[re.Pattern[str]]:
    try:
        return [re.compile(t if regex else re.escape(t), re.IGNORECASE) for t in terms]
    except re.error as exc:
        raise AdvisoryError(f"Ungültiger regulärer Ausdruck: {exc}") from exc


def cmd_list(args: argparse.Namespace) -> int:
    """Gemeinsame Implementierung für 'list' und 'search' (list hat keine Suchbegriffe)."""
    terms = compile_terms(args.terms, args.regex)
    if args.refresh:
        data = ensure_advisories(args.file, force=False, max_age_hours=args.max_age_hours, quiet=args.format == "json")
    else:
        data = load_advisories(args.file)

    advisories = filter_advisories(
        data["advisories"],
        project=args.project,
        min_severity=args.min_severity,
        terms=terms,
        since=args.since,
    )
    total = len(advisories)
    if args.limit > 0:
        advisories = advisories[: args.limit]

    if args.format == "json":
        json.dump(advisories, sys.stdout, indent=2, ensure_ascii=False)
        print()
        return 0

    print(header(data))
    print(f"{total} Treffer, zeige {len(advisories)}\n")
    for a in advisories:
        print(format_line(a))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    data = load_advisories(args.file)
    by_id = {str(a.get("id", "")).upper(): a for a in data["advisories"]}

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
        print("\n\n".join(format_details(a) for a in found))

    for cve in missing:
        print(f"{cve}: nicht in den Spring Advisories", file=sys.stderr)
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
    if not CVE_PATTERN.match(value):
        raise argparse.ArgumentTypeError(f"ungültige CVE-ID '{value}' (erwartet CVE-JJJJ-NNNN)")
    return value.upper()


def severity(value: str) -> str:
    if value.upper() not in SEVERITY_ORDER:
        raise argparse.ArgumentTypeError(f"ungültige Severity '{value}' (erlaubt: {', '.join(SEVERITIES)})")
    return value.upper()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Spring Security Advisories (spring.io/security) herunterladen und durchsuchen.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit-Codes: 0 = OK, 1 = CVE nicht gefunden (show), 2 = Fehler",
    )
    parser.add_argument(
        "--file", type=Path, default=DEFAULT_FILE,
        help=f"Pfad der lokalen Datei (Standard: {DEFAULT_FILE.name} neben dem Skript)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_dl = sub.add_parser("download", help="Advisories herunterladen")
    p_dl.add_argument("--force", action="store_true", help="Download auch bei aktueller lokaler Kopie erzwingen")
    p_dl.add_argument(
        "--full", action="store_true",
        help=f"Details aller Advisories neu laden statt nur neue, geänderte und die neuesten {RECENT_ADVISORIES} "
             "(impliziert --force)",
    )
    p_dl.add_argument(
        "--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS,
        help="Lokale Kopie gilt so lange als aktuell (Standard: %(default)s)",
    )
    p_dl.set_defaults(func=cmd_download)

    # Filter- und Ausgabeoptionen, die 'list' und 'search' gemeinsam haben
    filters = argparse.ArgumentParser(add_help=False)
    filters.add_argument("-n", "--limit", type=int, default=30, help="Maximale Anzahl (0 = alle, Standard: %(default)s)")
    filters.add_argument("--project", help="Filter auf Projekt (Teilstring, ohne Groß-/Kleinschreibung)")
    filters.add_argument(
        "--min-severity", type=severity, metavar="SEVERITY",
        help=f"Mindest-Severity ({', '.join(SEVERITIES)}, ohne Groß-/Kleinschreibung)",
    )
    filters.add_argument("--since", type=iso_date, help="Nur Advisories ab diesem Datum (YYYY-MM-DD)")
    filters.add_argument("--format", choices=("text", "json"), default="text", help="Ausgabeformat")
    filters.add_argument(
        "--refresh", action="store_true",
        help="Vorher herunterladen, falls die lokale Kopie fehlt oder älter als --max-age-hours ist",
    )
    filters.add_argument("--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS, help=argparse.SUPPRESS)

    p_list = sub.add_parser("list", parents=[filters], help="Advisories auflisten (neueste zuerst)")
    p_list.set_defaults(func=cmd_list, terms=[], regex=False)

    p_search = sub.add_parser(
        "search", parents=[filters],
        help="Volltextsuche (CVE, Titel, Projekt, Beschreibung, Mitigation, Artefakte, Referenzen)",
    )
    p_search.add_argument("terms", nargs="+", metavar="BEGRIFF", help="Suchbegriffe (alle müssen vorkommen)")
    p_search.add_argument("-E", "--regex", action="store_true", help="Suchbegriffe als reguläre Ausdrücke behandeln")
    p_search.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="Details zu CVE-IDs anzeigen")
    p_show.add_argument("cve", nargs="+", type=cve_id, help="Eine oder mehrere CVE-IDs")
    p_show.add_argument("--format", choices=("text", "json"), default="text", help="Ausgabeformat")
    p_show.set_defaults(func=cmd_show)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except AdvisoryError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        # z. B. "advisories.py list | head" — kein Fehler, nur vorzeitig beendet
        sys.stderr.close()
        return 0


if __name__ == "__main__":
    sys.exit(main())
