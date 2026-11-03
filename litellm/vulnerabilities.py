#!/usr/bin/env python3
"""
vulnerabilities.py - Lädt alle Schwachstellen des PyPI-Pakets litellm (BerriAI/litellm)
aus der OSV-Datenbank (https://osv.dev) herunter und gibt sie gefiltert aus.

OSV führt für litellm drei Arten von Einträgen:
  - GHSA-*  GitHub Security Advisories (Titel, Beschreibung, Severity, CVSS,
            betroffene Bereiche je Backport-Linie, CWE)
  - PYSEC-* PyPA-Advisory-Datenbank, meist dieselbe Lücke wie ein GHSA-Eintrag
  - MAL-*   Schadcode in veröffentlichten PyPI-Releases (OpenSSF Malicious Packages)
PYSEC-Einträge, deren GHSA-Gegenstück vorhanden ist, werden mit diesem
zusammengeführt (Aliase und Referenzen), sodass jede Lücke nur einmal vorkommt.

Unterbefehle:
  download  Daten herunterladen und in die lokale Kopie einführen (überspringt den
            Download, solange die lokale Kopie jünger als --max-age-hours ist;
            --force erzwingt ihn). Die lokale Kopie wächst nur: aus OSV
            entfernte Einträge bleiben erhalten.
  list      Einträge nach Veröffentlichung (neueste zuerst) ausgeben, optional gefiltert
  search    Volltextsuche (alle Begriffe müssen vorkommen), sonst wie list
  show      Alle Details zu einzelnen IDs ausgeben (CVE, GHSA, PYSEC oder MAL)
  check     Einträge ausgeben, die eine installierte litellm-Version betreffen

Die lokale Kopie liegt standardmäßig neben diesem Skript (litellm/vulnerabilities.json)
und ist versioniert. Sie wird immer gleich formatiert und sortiert geschrieben,
damit git-Diffs nur echte Änderungen zeigen.

Beispiele:
  python3 litellm/vulnerabilities.py download
  python3 litellm/vulnerabilities.py list --min-severity high
  python3 litellm/vulnerabilities.py search ssrf proxy
  python3 litellm/vulnerabilities.py show CVE-2026-84377
  python3 litellm/vulnerabilities.py check 1.82.7

Exit-Codes:
  0 - Erfolg (check: Version nicht betroffen)
  1 - show: mindestens eine ID nicht vorhanden; check: Version betroffen
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
from pathlib import Path
from typing import Any

PACKAGE = "litellm"
QUERY_URL = "https://api.osv.dev/v1/query"
OSV_URL = "https://osv.dev/vulnerability/{id}"
PYPI_URL = "https://pypi.org/pypi/litellm/json"
DEFAULT_FILE = Path(__file__).resolve().parent / "vulnerabilities.json"
DOWNLOAD_TIMEOUT = 60
DOWNLOAD_RETRIES = 3
DEFAULT_MAX_AGE_HOURS = 24.0

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
# GitHub nennt MEDIUM "MODERATE"
SEVERITY_ALIASES = {"MODERATE": "MEDIUM"}

ID_PATTERN = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[0-9a-z]{4}){3}|PYSEC-\d{4}-\d+|MAL-\d{4}-\d+)$", re.IGNORECASE)
# Rangfolge, wenn mehrere OSV-Einträge dieselbe Lücke beschreiben
PRIMARY_RANK = {"GHSA": 0, "MAL": 1, "PYSEC": 2}

# Steuerzeichen (inkl. ESC) aus heruntergeladenen Texten entfernen, damit
# manipulierte Inhalte keine Terminal-Escape-Sequenzen ausführen können.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


class VulnError(Exception):
    """Daten fehlen, sind ungültig oder konnten nicht geladen werden."""


def clean(value: Any) -> str:
    return _CONTROL_CHARS.sub("", str(value if value is not None else ""))


# ---------------------------------------------------------------------------
# Versionen (vereinfachtes PEP 440: Release, a/b/rc, post, dev)
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(
    r"^v?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?"
    r"(?:[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+.*)?$",
    re.IGNORECASE,
)
_PRE_RANK = {"a": 1, "alpha": 1, "b": 2, "beta": 2, "c": 3, "rc": 3, "pre": 3, "preview": 3}


def version_key(v: str) -> tuple[Any, ...] | None:
    """Sortierschlüssel: dev < a < b < rc < final < post; None = nicht auswertbar."""
    match = _VERSION_RE.match(str(v).strip())
    if not match:
        return None
    release, pre, pre_n, post, post_n, dev, dev_n = match.groups()
    nums = [int(p) for p in release.split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    # Phase: 0 = nur dev, 1-3 = Vorabversion, 4 = final; danach post und dev der Phase
    phase = _PRE_RANK[pre.lower()] if pre else (0 if dev and not post else 4)
    return (tuple(nums), phase, int(pre_n or 0) if pre else 0,
            int(post_n or 0) + 1 if post else 0, 0 if dev else 1, int(dev_n or 0))


def affects(entry: dict[str, Any], version: str) -> bool | None:
    """Betrifft der Eintrag die Version? None, wenn die Version nicht auswertbar ist."""
    key = version_key(version)
    if key is None:
        return None
    if version in (entry.get("versions") or []):
        return True
    for r in entry.get("ranges") or []:
        lo = version_key(r.get("introduced") or "0")
        if lo is None or key < lo:
            continue
        if r.get("fixed"):
            hi = version_key(r["fixed"])
            if hi is not None and key < hi:
                return True
        elif r.get("lastAffected"):
            hi = version_key(r["lastAffected"])
            if hi is not None and key <= hi:
                return True
        else:
            return True
    return False


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def http_request(url: str, payload: dict[str, Any] | None = None) -> Any:
    """GET/POST mit Retries, Antwort als JSON."""
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"User-Agent": "scan-tools-litellm/1.0", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers)
    last_exc: Exception | None = None
    for attempt in range(DOWNLOAD_RETRIES):
        try:
            with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as resp:
                return json.loads(resp.read())
        except json.JSONDecodeError as exc:
            raise VulnError(f"Antwort von {url} ist kein gültiges JSON: {exc}") from exc
        except OSError as exc:
            last_exc = exc
        time.sleep(1 + attempt * 2)
    raise VulnError(f"Download von {url} fehlgeschlagen: {last_exc}")


def fetch_osv() -> list[dict[str, Any]]:
    """Alle OSV-Einträge für PyPI/litellm (die Query-API blättert per page_token)."""
    vulns: list[dict[str, Any]] = []
    payload: dict[str, Any] = {"package": {"name": PACKAGE, "ecosystem": "PyPI"}}
    while True:
        body = http_request(QUERY_URL, payload)
        if not isinstance(body, dict):
            raise VulnError(f"Unerwartete Antwort von {QUERY_URL}")
        vulns.extend(v for v in body.get("vulns") or [] if isinstance(v, dict) and v.get("id"))
        token = body.get("next_page_token")
        if not token:
            break
        payload["page_token"] = token
    if not vulns:
        raise VulnError(f"Keine Einträge für {PACKAGE} von {QUERY_URL} erhalten")
    return vulns


def fetch_latest() -> str:
    """Neueste stabile Version auf PyPI (nur zur Anzeige); leer, wenn nicht ermittelbar."""
    try:
        body = http_request(PYPI_URL)
    except VulnError:
        return ""
    return str((body.get("info") or {}).get("version") or "") if isinstance(body, dict) else ""


def id_prefix(vid: str) -> str:
    return vid.split("-", 1)[0].upper()


def group_vulns(vulns: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Einträge, die sich per ID/Alias verweisen, zu einer Gruppe zusammenfassen."""
    by_id = {v["id"]: v for v in vulns}
    seen: set[str] = set()
    groups = []
    for v in vulns:
        if v["id"] in seen:
            continue
        group, todo = [], [v["id"]]
        while todo:
            vid = todo.pop()
            if vid in seen or vid not in by_id:
                continue
            seen.add(vid)
            group.append(by_id[vid])
            todo.extend(by_id[vid].get("aliases") or [])
            # Rückverweise: ein anderer Eintrag nennt diesen als Alias
            todo.extend(o["id"] for o in vulns if vid in (o.get("aliases") or []))
        groups.append(sorted(group, key=lambda g: (PRIMARY_RANK.get(id_prefix(g["id"]), 9), g["id"])))
    return groups


def osv_ranges(affected: list[dict[str, Any]]) -> list[dict[str, str]]:
    """OSV-Events (introduced/fixed/last_affected) → Bereiche je Backport-Linie."""
    ranges: list[dict[str, str]] = []
    for a in affected:
        if str((a.get("package") or {}).get("name") or "").lower() != PACKAGE:
            continue
        for r in a.get("ranges") or []:
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            current: dict[str, str] | None = None
            for event in r.get("events") or []:
                if "introduced" in event:
                    current = {"introduced": str(event["introduced"])}
                    ranges.append(current)
                elif current is not None and "fixed" in event:
                    current["fixed"] = str(event["fixed"])
                    current = None
                elif current is not None and "last_affected" in event:
                    current["lastAffected"] = str(event["last_affected"])
                    current = None
    return sorted(ranges, key=lambda r: version_key(r["introduced"]) or ((0,),))


def explicit_versions(affected: list[dict[str, Any]]) -> list[str]:
    """Nur für Einträge ohne Bereiche (MAL-*): die konkret betroffenen Releases."""
    versions = {str(v) for a in affected if str((a.get("package") or {}).get("name") or "").lower() == PACKAGE
                for v in a.get("versions") or []}
    return sorted(versions, key=lambda v: version_key(v) or ((0,),))


def osv_severity(v: dict[str, Any]) -> tuple[str, str]:
    """Severity (GitHub-Einstufung) und bester CVSS-Vektor (v4 vor v3)."""
    sev = str((v.get("database_specific") or {}).get("severity") or "").upper()
    sev = SEVERITY_ALIASES.get(sev, sev)
    vectors = {str(s.get("type")): str(s.get("score") or "") for s in v.get("severity") or []}
    vector = vectors.get("CVSS_V4") or vectors.get("CVSS_V3") or ""
    return (sev if sev in SEVERITY_ORDER else ""), vector


def strip_osv_footer(text: str) -> str:
    """MAL-Einträge hängen die Rohberichte aller Quellen an — nur den Kopf behalten."""
    return re.split(r"\n-{3,}\n_-= Per source details", text, maxsplit=1)[0].strip()


def build_entry(group: list[dict[str, Any]]) -> dict[str, Any]:
    primary = group[0]
    ids = {g["id"] for g in group} | {a for g in group for a in g.get("aliases") or []}
    cves = sorted(i for i in ids if i.upper().startswith("CVE-"))
    severity, vector = osv_severity(primary)
    for g in group[1:]:
        if severity and vector:
            break
        s, vec = osv_severity(g)
        severity, vector = severity or s, vector or vec
    db = primary.get("database_specific") or {}
    cwes = list(dict.fromkeys(
        [str(c) for c in db.get("cwe_ids") or []]
        + [str(c.get("cweId")) for a in primary.get("affected") or []
           for c in (a.get("database_specific") or {}).get("cwes") or [] if c.get("cweId")]))
    references: list[str] = []
    for g in group:
        for ref in g.get("references") or []:
            url = str(ref.get("url") or "")
            if url.startswith(("http://", "https://")) and url not in references:
                references.append(url)
    ranges = osv_ranges(primary.get("affected") or [])
    # CWE-506 (Embedded Malicious Code): GitHub führt die kompromittierten Releases auch als GHSA
    kind = "malicious" if id_prefix(primary["id"]) == "MAL" or "CWE-506" in cwes else "vulnerability"
    ghsa = next((i for i in sorted(ids) if i.upper().startswith("GHSA-")), "")
    url = (f"https://github.com/advisories/{ghsa}" if ghsa and kind != "malicious"
           else OSV_URL.format(id=primary["id"]))
    return {
        "id": cves[0] if cves else primary["id"],
        "kind": kind,
        "url": url,
        "title": str(primary.get("summary") or ""),
        "published": str(primary.get("published") or "")[:10],
        "modified": str(max(str(g.get("modified") or "") for g in group))[:10],
        "severity": "CRITICAL" if kind == "malicious" and not severity else severity,
        "cvssVector": vector,
        "weakness": cwes,
        "cves": cves,
        "aliases": sorted(i for i in ids if not i.upper().startswith("CVE-") and i != (cves[0] if cves else primary["id"])),
        "ranges": ranges,
        # Nur bei MAL-Einträgen: die konkreten Releases (bei anderen wäre das jede Version seit 0.1.0)
        "versions": explicit_versions(primary.get("affected") or []) if not ranges else [],
        "fixes": sorted({r["fixed"] for r in ranges if r.get("fixed")}, key=lambda f: version_key(f) or ((0,),)),
        "unfixed": any(not r.get("fixed") for r in ranges),
        "description": strip_osv_footer(str(primary.get("details") or "")),
        "references": references,
    }


def merge_vulns(local: dict[str, Any] | None, quiet: bool) -> tuple[dict[str, Any], dict[str, int]]:
    local_by_id = {str(e.get("id", "")).upper(): e for e in (local or {}).get("vulnerabilities", [])}
    vulns = fetch_osv()
    groups = group_vulns(vulns)
    if not quiet:
        print(f"{len(vulns)} OSV-Einträge, {len(groups)} nach Zusammenführung", file=sys.stderr)

    stats = {"neu": 0, "aktualisiert": 0, "unverändert": 0, "nur lokal": 0}
    merged: dict[str, dict[str, Any]] = {}
    for group in groups:
        entry = build_entry(group)
        key = entry["id"].upper()
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

    entries = sorted(merged.values(), key=lambda e: (e.get("published", ""), e.get("id", "")), reverse=True)
    latest = fetch_latest() or str((local or {}).get("latestVersion") or "")
    return {"source": "https://osv.dev/list?ecosystem=PyPI&q=litellm", "package": PACKAGE,
            "latestVersion": latest, "count": len(entries), "vulnerabilities": entries}, stats


# ---------------------------------------------------------------------------
# Laden / Speichern
# ---------------------------------------------------------------------------

def load_vulns(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise VulnError(f"Datei '{path}' nicht gefunden — zuerst 'download' ausführen oder --refresh verwenden")
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise VulnError(f"Datei '{path}' ist kein gültiges JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise VulnError("Unerwartetes Format: Schlüssel 'vulnerabilities' fehlt")
    return data


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
            fh.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
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
        print(f"Lade {QUERY_URL} ({PACKAGE}) ...", file=sys.stderr)
    merged, stats = merge_vulns(local, quiet=quiet)
    save_vulns(path, merged)
    if not quiet:
        print(", ".join(f"{n} {label}" for label, n in stats.items()), file=sys.stderr)
    return merged


# ---------------------------------------------------------------------------
# Filtern / Ausgabe
# ---------------------------------------------------------------------------

SEARCH_FIELDS = ("id", "title", "description", "aliases", "cves", "weakness", "references", "cvssVector")


def search_text(e: dict[str, Any]) -> str:
    """Alle durchsuchbaren Felder eines Eintrags als ein String (Listen zusammengefügt)."""
    parts = []
    for key in SEARCH_FIELDS:
        value = e.get(key)
        parts.append(" ".join(map(str, value)) if isinstance(value, list) else str(value or ""))
    return "\n".join(parts)


def filter_vulns(
    entries: list[dict[str, Any]],
    min_severity: str | None = None,
    terms: list[re.Pattern[str]] | None = None,
    since: str | None = None,
    version: str | None = None,
) -> list[dict[str, Any]]:
    min_order = SEVERITY_ORDER[min_severity] if min_severity else -1
    result = []
    for e in entries:
        if SEVERITY_ORDER.get(str(e.get("severity", "")).upper(), -1) < min_order:
            continue
        # ISO-Datumsstrings (YYYY-MM-DD) lassen sich direkt lexikografisch vergleichen
        if since and str(e.get("published", "")) < since:
            continue
        if version and not affects(e, version):
            continue
        # Mehrere Suchbegriffe sind UND-verknüpft
        if terms:
            text = search_text(e)
            if not all(t.search(text) for t in terms):
                continue
        result.append(e)
    return sorted(result, key=lambda e: (str(e.get("published", "")), str(e.get("id", ""))), reverse=True)


def format_range(r: dict[str, str]) -> str:
    lo = r.get("introduced") or "0"
    lo = "alle" if lo == "0" else f">= {lo}"
    if r.get("fixed"):
        return f"{lo} < {r['fixed']}"
    if r.get("lastAffected"):
        return f"{lo} <= {r['lastAffected']}"
    return f"{lo} (kein Ende)"


def fix_text(e: dict[str, Any]) -> str:
    if e.get("kind") == "malicious":
        return "Release meiden"
    fixes = ", ".join(e.get("fixes") or [])
    if fixes:
        return fixes + (" (+ ohne Fix)" if e.get("unfixed") else "")
    last = [r["lastAffected"] for r in e.get("ranges") or [] if r.get("lastAffected")]
    return f"keiner (betroffen bis {last[-1]})" if last else "kein Fix angegeben"


def format_line(e: dict[str, Any]) -> str:
    return (
        f"{clean(e.get('published')):<10}  {clean(e.get('id')):<20}  {clean(e.get('severity')):<8}  "
        f"{clean(fix_text(e))[:28]:<28}  {clean(e.get('title'))}"
    )


def list_header() -> str:
    return f"{'Datum':<10}  {'ID':<20}  {'Severity':<8}  {'Fix':<28}  Titel"


def format_details(e: dict[str, Any]) -> str:
    def row(label: str, value: Any) -> str:
        return f"{label + ':':<16}{clean(value)}"

    lines = [row(label, value) for label, value in (
        ("ID", e.get("id")), ("Titel", e.get("title")), ("Art", e.get("kind")),
        ("Severity", e.get("severity")), ("CVSS", e.get("cvssVector")),
        ("Veröffentlicht", e.get("published")), ("Geändert", e.get("modified")),
        ("Link", e.get("url")), ("Aliase", ", ".join(e.get("aliases") or [])),
        ("CWE", ", ".join(e.get("weakness") or [])),
        ("Releases", ", ".join(e.get("versions") or [])),
    ) if value]
    for r in e.get("ranges") or []:
        lines.append(row("  Bereich", format_range(r)))
    if e.get("description"):
        lines.append("Beschreibung:")
        lines.extend(f"  {clean(line)}" for line in str(e["description"]).splitlines())
    if e.get("references"):
        lines.append("Referenzen:")
        lines.extend(f"  {clean(r)}" for r in e["references"])
    return "\n".join(lines)


def header(data: dict[str, Any]) -> str:
    entries = data["vulnerabilities"]
    newest = max((str(e.get("published", "")) for e in entries), default="?")
    latest = f", neueste PyPI-Version {clean(data['latestVersion'])}" if data.get("latestVersion") else ""
    return f"LiteLLM-Schwachstellen — {len(entries)} Einträge, neuester vom {clean(newest)}{latest}"


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
    """Gemeinsame Implementierung für 'list', 'search' und 'check'."""
    terms = compile_terms(args.terms, args.regex)
    if args.refresh:
        data = ensure_vulns(args.file, force=False, max_age_hours=args.max_age_hours, quiet=args.format == "json")
    else:
        data = load_vulns(args.file)
    if args.version and version_key(args.version) is None:
        raise VulnError(f"Version '{args.version}' nicht auswertbar")

    entries = filter_vulns(data["vulnerabilities"], min_severity=args.min_severity, terms=terms,
                           since=args.since, version=args.version)
    total = len(entries)
    if args.limit > 0:
        entries = entries[: args.limit]

    if args.format == "json":
        json.dump(entries, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        print(header(data))
        label = f"betreffen {PACKAGE} {clean(args.version)}" if args.version else "Treffer"
        print(f"{total} {label}, zeige {len(entries)}\n")
        if entries:
            print(list_header())
        for e in entries:
            print(format_line(e))
    return 1 if args.version and total else 0


def cmd_show(args: argparse.Namespace) -> int:
    data = load_vulns(args.file)
    by_id: dict[str, dict[str, Any]] = {}
    for e in data["vulnerabilities"]:
        for key in [e.get("id", ""), *(e.get("aliases") or []), *(e.get("cves") or [])]:
            by_id.setdefault(str(key).upper(), e)

    found: list[dict[str, Any]] = []
    missing: list[str] = []
    for vid in args.id:
        entry = by_id.get(vid.upper())
        if entry is None:
            missing.append(vid)
        elif entry not in found:
            found.append(entry)

    if args.format == "json":
        json.dump(found, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        print("\n\n".join(format_details(e) for e in found))

    for vid in missing:
        print(f"{vid}: nicht in den LiteLLM-Schwachstellen", file=sys.stderr)
    return 1 if missing else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def iso_date(value: str) -> str:
    try:
        return dt.date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"ungültiges Datum '{value}' (erwartet YYYY-MM-DD)") from exc


def vuln_id(value: str) -> str:
    if not ID_PATTERN.match(value):
        raise argparse.ArgumentTypeError(f"ungültige ID '{value}' (erwartet CVE-, GHSA-, PYSEC- oder MAL-ID)")
    return value


def severity(value: str) -> str:
    upper = SEVERITY_ALIASES.get(value.upper(), value.upper())
    if upper not in SEVERITY_ORDER:
        raise argparse.ArgumentTypeError(f"ungültige Severity '{value}' (erlaubt: {', '.join(SEVERITIES)})")
    return upper


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="LiteLLM-Schwachstellen (OSV: GHSA, PYSEC, MAL) herunterladen und durchsuchen.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit-Codes: 0 = OK, 1 = ID nicht gefunden (show) bzw. Version betroffen (check), 2 = Fehler",
    )
    parser.add_argument(
        "--file", type=Path, default=DEFAULT_FILE,
        help=f"Pfad der lokalen Datei (Standard: {DEFAULT_FILE.name} neben dem Skript)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_dl = sub.add_parser("download", help="Daten aus OSV herunterladen")
    p_dl.add_argument("--force", action="store_true", help="Download auch bei aktueller lokaler Kopie erzwingen")
    p_dl.add_argument(
        "--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS,
        help="Lokale Kopie gilt so lange als aktuell (Standard: %(default)s)",
    )
    p_dl.set_defaults(func=cmd_download)

    # Filter- und Ausgabeoptionen, die 'list', 'search' und 'check' gemeinsam haben
    filters = argparse.ArgumentParser(add_help=False)
    filters.add_argument("-n", "--limit", type=int, default=30, help="Maximale Anzahl (0 = alle, Standard: %(default)s)")
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
    p_list.set_defaults(func=cmd_list, terms=[], regex=False, version=None)

    p_search = sub.add_parser("search", parents=[filters], help="Volltextsuche (ID, Titel, Beschreibung, Aliase, Referenzen)")
    p_search.add_argument("terms", nargs="+", metavar="BEGRIFF", help="Suchbegriffe (alle müssen vorkommen)")
    p_search.add_argument("-E", "--regex", action="store_true", help="Suchbegriffe als reguläre Ausdrücke behandeln")
    p_search.set_defaults(func=cmd_list, version=None)

    p_check = sub.add_parser("check", parents=[filters], help="Einträge, die eine litellm-Version betreffen")
    p_check.add_argument("version", help="Installierte Version, z. B. 1.82.7 (pip show litellm)")
    p_check.set_defaults(func=cmd_list, terms=[], regex=False, limit=0)

    p_show = sub.add_parser("show", help="Details zu IDs anzeigen")
    p_show.add_argument("id", nargs="+", type=vuln_id, help="Eine oder mehrere CVE-/GHSA-/PYSEC-/MAL-IDs")
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
