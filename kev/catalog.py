#!/usr/bin/env python3
"""
catalog.py - Lädt den CISA "Known Exploited Vulnerabilities" (KEV) Katalog herunter
und gibt ihn gefiltert aus.

Unterbefehle:
  download  Katalog herunterladen (überspringt den Download, solange die lokale
            Kopie jünger als --max-age-hours ist; --force erzwingt ihn)
  list      Einträge nach Aufnahmedatum (neueste zuerst) ausgeben, optional gefiltert
  show      Alle Details zu einzelnen CVE-IDs ausgeben

Die lokale Kopie liegt standardmäßig neben diesem Skript
(kev/known_exploited_vulnerabilities.json) und ist per .gitignore ausgeschlossen.

Beispiele:
  python3 kev/catalog.py download
  python3 kev/catalog.py list --limit 50 --vendor microsoft --ransomware
  python3 kev/catalog.py list --since 2026-10-01 --format json
  python3 kev/catalog.py list --refresh
  python3 kev/catalog.py show CVE-2026-111497

Exit-Codes:
  0 - Erfolg
  1 - show: mindestens eine CVE-ID nicht im Katalog
  2 - Skriptfehler (Download fehlgeschlagen, Katalog fehlt/ungültig, ...)
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
from pathlib import Path
from typing import Any

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_FILE = Path(__file__).resolve().parent / "known_exploited_vulnerabilities.json"
DOWNLOAD_TIMEOUT = 60
DEFAULT_MAX_AGE_HOURS = 24.0

# Steuerzeichen (inkl. ESC) aus heruntergeladenen Texten entfernen, damit
# manipulierte Feed-Inhalte keine Terminal-Escape-Sequenzen ausführen können.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class CatalogError(Exception):
    """Katalog fehlt, ist ungültig oder konnte nicht geladen werden."""


def clean(value: Any) -> str:
    return _CONTROL_CHARS.sub("", str(value if value is not None else ""))


# ---------------------------------------------------------------------------
# Download / Laden
# ---------------------------------------------------------------------------

def validate_catalog(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise CatalogError("Unerwartetes Format: Schlüssel 'vulnerabilities' fehlt")
    return data


def file_age_hours(path: Path) -> float | None:
    try:
        return (time.time() - path.stat().st_mtime) / 3600
    except FileNotFoundError:
        return None


def download_catalog(path: Path, url: str = KEV_URL, timeout: int = DOWNLOAD_TIMEOUT) -> dict[str, Any]:
    """Lädt den Katalog, validiert ihn und schreibt ihn atomar nach ``path``."""
    request = urllib.request.Request(url, headers={"User-Agent": "scan-tools-kev/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            raw = resp.read()
    except OSError as exc:
        raise CatalogError(f"Download von {url} fehlgeschlagen: {exc}") from exc

    try:
        data = validate_catalog(json.loads(raw))
    except json.JSONDecodeError as exc:
        raise CatalogError(f"Download ist kein gültiges JSON: {exc}") from exc

    # Erst in eine temporäre Datei schreiben und dann ersetzen — ein abgebrochener
    # Download hinterlässt so nie eine halbe Katalogdatei.
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return data


def load_catalog(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise CatalogError(f"Katalog '{path}' nicht gefunden — zuerst 'download' ausführen oder --refresh verwenden")
    try:
        with path.open(encoding="utf-8") as fh:
            return validate_catalog(json.load(fh))
    except json.JSONDecodeError as exc:
        raise CatalogError(f"Katalog '{path}' ist kein gültiges JSON: {exc}") from exc


def ensure_catalog(path: Path, force: bool, max_age_hours: float, quiet: bool = False) -> dict[str, Any]:
    """Lädt den Katalog nur neu, wenn erzwungen oder die lokale Kopie zu alt ist."""
    age = file_age_hours(path)
    if not force and age is not None and age < max_age_hours:
        if not quiet:
            print(f"Lokale Kopie ist {age:.1f} h alt (< {max_age_hours:g} h) — kein Download nötig.", file=sys.stderr)
        return load_catalog(path)
    if not quiet:
        print(f"Lade {KEV_URL} ...", file=sys.stderr)
    return download_catalog(path)


# ---------------------------------------------------------------------------
# Filtern / Ausgabe
# ---------------------------------------------------------------------------

def filter_vulns(
    vulns: list[dict[str, Any]],
    vendor: str | None = None,
    product: str | None = None,
    search: str | None = None,
    since: str | None = None,
    ransomware: bool = False,
) -> list[dict[str, Any]]:
    def contains(field_value: Any, needle: str) -> bool:
        return needle.lower() in str(field_value or "").lower()

    result = []
    for v in vulns:
        if vendor and not contains(v.get("vendorProject"), vendor):
            continue
        if product and not contains(v.get("product"), product):
            continue
        if search and not any(
            contains(v.get(k), search)
            for k in ("cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription")
        ):
            continue
        # ISO-Datumsstrings (YYYY-MM-DD) lassen sich direkt lexikografisch vergleichen
        if since and str(v.get("dateAdded", "")) < since:
            continue
        if ransomware and str(v.get("knownRansomwareCampaignUse", "")).lower() != "known":
            continue
        result.append(v)
    return sorted(result, key=lambda v: str(v.get("dateAdded", "")), reverse=True)


def format_line(v: dict[str, Any]) -> str:
    ransomware = "R" if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known" else "-"
    return (
        f"{clean(v.get('dateAdded')):<10}  {clean(v.get('cveID')):<16}  {ransomware}  "
        f"{clean(v.get('vendorProject'))} | {clean(v.get('product'))} | {clean(v.get('vulnerabilityName'))}"
    )


def format_details(v: dict[str, Any]) -> str:
    fields = (
        ("CVE", "cveID"),
        ("Hersteller", "vendorProject"),
        ("Produkt", "product"),
        ("Name", "vulnerabilityName"),
        ("Aufgenommen", "dateAdded"),
        ("Frist", "dueDate"),
        ("Ransomware", "knownRansomwareCampaignUse"),
        ("CWE", "cwes"),
        ("Beschreibung", "shortDescription"),
        ("Maßnahme", "requiredAction"),
        ("Hinweise", "notes"),
    )
    lines = []
    for label, key in fields:
        value = v.get(key)
        if isinstance(value, list):
            value = ", ".join(str(x) for x in value)
        if value:
            lines.append(f"{label + ':':<14}{clean(value)}")
    return "\n".join(lines)


def catalog_header(data: dict[str, Any]) -> str:
    return (
        f"KEV-Katalog {clean(data.get('catalogVersion', '?'))} "
        f"vom {clean(data.get('dateReleased', '?'))[:10]} — "
        f"{len(data['vulnerabilities'])} Einträge"
    )


# ---------------------------------------------------------------------------
# Unterbefehle
# ---------------------------------------------------------------------------

def cmd_download(args: argparse.Namespace) -> int:
    data = ensure_catalog(args.file, args.force, args.max_age_hours)
    print(catalog_header(data))
    print(f"Datei: {args.file}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    if args.refresh:
        data = ensure_catalog(args.file, force=False, max_age_hours=args.max_age_hours, quiet=args.format == "json")
    else:
        data = load_catalog(args.file)

    vulns = filter_vulns(
        data["vulnerabilities"],
        vendor=args.vendor,
        product=args.product,
        search=args.search,
        since=args.since,
        ransomware=args.ransomware,
    )
    total = len(vulns)
    if args.limit > 0:
        vulns = vulns[: args.limit]

    if args.format == "json":
        json.dump(vulns, sys.stdout, indent=2, ensure_ascii=False)
        print()
        return 0

    print(catalog_header(data))
    print(f"{total} Treffer, zeige {len(vulns)} (R = bekannte Ransomware-Nutzung)\n")
    for v in vulns:
        print(format_line(v))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    data = load_catalog(args.file)
    by_id = {str(v.get("cveID", "")).upper(): v for v in data["vulnerabilities"]}

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
        print(f"{cve}: nicht im KEV-Katalog", file=sys.stderr)
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CISA Known Exploited Vulnerabilities (KEV) Katalog herunterladen und durchsuchen.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit-Codes: 0 = OK, 1 = CVE nicht gefunden (show), 2 = Fehler",
    )
    parser.add_argument(
        "--file", type=Path, default=DEFAULT_FILE,
        help=f"Pfad der lokalen Katalogdatei (Standard: {DEFAULT_FILE.name} neben dem Skript)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_dl = sub.add_parser("download", help="Katalog herunterladen")
    p_dl.add_argument("--force", action="store_true", help="Download auch bei aktueller lokaler Kopie erzwingen")
    p_dl.add_argument(
        "--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS,
        help="Lokale Kopie gilt so lange als aktuell (Standard: %(default)s)",
    )
    p_dl.set_defaults(func=cmd_download)

    p_list = sub.add_parser("list", help="Einträge auflisten (neueste zuerst)")
    p_list.add_argument("-n", "--limit", type=int, default=30, help="Maximale Anzahl (0 = alle, Standard: %(default)s)")
    p_list.add_argument("--vendor", help="Filter auf Hersteller (Teilstring, ohne Groß-/Kleinschreibung)")
    p_list.add_argument("--product", help="Filter auf Produkt (Teilstring, ohne Groß-/Kleinschreibung)")
    p_list.add_argument("-s", "--search", help="Freitextsuche in CVE, Hersteller, Produkt, Name und Beschreibung")
    p_list.add_argument("--since", type=iso_date, help="Nur Einträge ab diesem Aufnahmedatum (YYYY-MM-DD)")
    p_list.add_argument("--ransomware", action="store_true", help="Nur Einträge mit bekannter Ransomware-Nutzung")
    p_list.add_argument("--format", choices=("text", "json"), default="text", help="Ausgabeformat")
    p_list.add_argument(
        "--refresh", action="store_true",
        help="Katalog vorher herunterladen, falls er fehlt oder älter als --max-age-hours ist",
    )
    p_list.add_argument("--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS, help=argparse.SUPPRESS)
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="Details zu CVE-IDs anzeigen")
    p_show.add_argument("cve", nargs="+", type=cve_id, help="Eine oder mehrere CVE-IDs")
    p_show.add_argument("--format", choices=("text", "json"), default="text", help="Ausgabeformat")
    p_show.set_defaults(func=cmd_show)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CatalogError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        # z. B. "catalog.py list | head" — kein Fehler, nur vorzeitig beendet
        sys.stderr.close()
        return 0


if __name__ == "__main__":
    sys.exit(main())
