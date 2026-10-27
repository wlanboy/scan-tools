#!/usr/bin/env python3
"""
cves.py - Lädt die CVE-Liste von Apache Kafka (https://kafka.apache.org/community/cve-list/)
herunter und gibt sie gefiltert aus.

Quelle ist die offizielle CVE-Liste des Kafka-Projekts (Titel, Beschreibung,
betroffene und gefixte Versionen, Impact, Advice). Pro CVE kommen aus dem
CVE-Record (cveawg.mitre.org) Veröffentlichungsdatum, CVSS/Severity, CWE und
Referenzen dazu. Aus den Versionsangaben wird je Release-Linie (2.x, 3.x, 4.x)
abgeleitet, ob sie betroffen ist und welche Versionen der Linie den Fix enthalten.

Unterbefehle:
  download  CVE-Liste und CVE-Records herunterladen und in die lokale Kopie einführen
            (überspringt den Download, solange die lokale Kopie jünger als
            --max-age-hours ist; --force erzwingt ihn). Die lokale Kopie wächst nur:
            aus der Liste entfernte CVEs bleiben erhalten.
  list      CVEs nach Veröffentlichung (neueste zuerst) ausgeben, optional gefiltert
  search    Volltextsuche (alle Begriffe müssen vorkommen), sonst wie list
  show      Alle Details zu einzelnen CVE-IDs ausgeben

Die lokale Kopie liegt standardmäßig neben diesem Skript (kafka/cves.json)
und ist versioniert. Sie wird immer gleich formatiert und sortiert geschrieben,
damit git-Diffs nur echte Änderungen zeigen.

Beispiele:
  python3 kafka/cves.py download
  python3 kafka/cves.py list --line 3 --min-severity high
  python3 kafka/cves.py list --line 2 --unfixed
  python3 kafka/cves.py search connect "ConfigProvider"
  python3 kafka/cves.py show CVE-2024-31141

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
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

SOURCE_URL = "https://kafka.apache.org/community/cve-list/"
SELF_LINK_RE = re.compile(r"^https?://kafka\.apache\.org/(community/)?cve-list/?(#.*)?$")
RECORD_URL = "https://cveawg.mitre.org/api/cve/{id}"
CVE_ORG_URL = "https://www.cve.org/CVERecord?id={id}"
# Nur für ältere CVEs ohne Score im CVE-Record; ohne API-Key max. 5 Anfragen / 30 s
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}"
NVD_DELAY = 6.5
DEFAULT_FILE = Path(__file__).resolve().parent / "cves.json"
DOWNLOAD_TIMEOUT = 30
DOWNLOAD_RETRIES = 3
DOWNLOAD_WORKERS = 4
DEFAULT_MAX_AGE_HOURS = 24.0

# Release-Linien, für die Betroffenheit und Fixes ausgewertet werden
LINES = (2, 3, 4)

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
# Apache-CNA-Records geben oft nur eine textuelle Einstufung an
TEXTUAL_SEVERITY = {"low": "LOW", "moderate": "MEDIUM", "medium": "MEDIUM", "important": "HIGH",
                    "high": "HIGH", "critical": "CRITICAL"}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
VERSION_RE = re.compile(r"\d+(?:\.\d+)+")

# Feldnamen der CVE-Liste (Tabellenzeile oder "Feld: Wert") → Schlüssel
FIELD_KEYS = {
    "versions affected": "affected",
    "affected versions": "affected",
    "affected": "affected",
    "fixed versions": "fixed",
    "fixed version": "fixed",
    "fixed in": "fixed",
    "impact": "impact",
    "advice": "advice",
    "mitigation": "advice",
}
FIELD_RE = re.compile(rf"^({'|'.join(sorted(map(re.escape, FIELD_KEYS), key=len, reverse=True))})\s*:\s*(.*)$",
                      re.IGNORECASE | re.DOTALL)

# Steuerzeichen (inkl. ESC) aus heruntergeladenen Texten entfernen, damit
# manipulierte Inhalte keine Terminal-Escape-Sequenzen ausführen können.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


class CveError(Exception):
    """Daten fehlen, sind ungültig oder konnten nicht geladen werden."""


def clean(value: Any) -> str:
    return _CONTROL_CHARS.sub("", str(value if value is not None else ""))


# ---------------------------------------------------------------------------
# CVE-Liste (HTML) parsen
# ---------------------------------------------------------------------------

_HEADINGS = frozenset({"h1", "h2", "h3", "h4", "h5", "h6"})
_TEXT_BLOCKS = frozenset({"p", "li", "pre", "blockquote", "dd", "dt"})


class _CveListParser(HTMLParser):
    """Zerlegt die Seite in CVE-Abschnitte: Überschrift mit CVE-ID, danach Absätze und Tabellen.

    Die Seite war früher handgeschriebenes HTML (h3 + Tabelle) und ist heute aus
    Markdown generiert — der Parser hängt deshalb nur an Überschriften, Absätzen
    und Tabellenzeilen, nicht an Klassen oder IDs.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.entries: list[dict[str, Any]] = []
        self.current: dict[str, Any] | None = None
        self.heading: tuple[str, int, str, list[str]] | None = None  # tag, level, id, text
        self.block: list[str] | None = None
        self.block_depth = 0
        self.cell: list[str] | None = None
        self.row: list[str] | None = None
        self.links: list[str] = []
        self.heading_links: list[str] = []
        self.in_pre = 0
        self.skip = 0

    # --- Hilfen -------------------------------------------------------------

    def _close_entry(self) -> None:
        if self.current is not None:
            self.entries.append(self.current)
        self.current = None

    def _text(self, data: str) -> None:
        for target in (self.heading[3] if self.heading else None, self.cell, self.block):
            if target is not None:
                target.append(data)
                return

    # --- Ereignisse ---------------------------------------------------------

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style", "nav", "footer"):
            self.skip += 1
            return
        if self.skip:
            return
        attr = dict(attrs)
        if tag == "pre":
            self.in_pre += 1
        if tag in _HEADINGS:
            self.heading = (tag, int(tag[1]), attr.get("id") or "", [])
            self.heading_links = []
        elif tag in ("td", "th"):
            self.cell = []
        elif tag == "tr":
            self.row = []
        elif tag in _TEXT_BLOCKS:
            # Verschachtelte Blöcke (p in li) bleiben ein Block
            if self.block is None:
                self.block = []
            self.block_depth += 1
        elif tag == "br":
            self._text("\n")
        elif tag == "a":
            href = attr.get("href") or ""
            if not href.startswith(("http://", "https://")):
                return
            # Links in der Überschrift gehören zum neuen Abschnitt, nicht zum vorigen
            if self.heading is not None:
                self.heading_links.append(href)
            elif self.current is not None:
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "nav", "footer"):
            self.skip = max(0, self.skip - 1)
            return
        if self.skip:
            return
        if tag == "pre":
            self.in_pre = max(0, self.in_pre - 1)
        if tag in _HEADINGS and self.heading:
            _, level, hid, parts = self.heading
            self.heading = None
            text = normalize_ws("".join(parts))
            match = CVE_RE.search(text)
            if match:
                self._close_entry()
                cve = match.group(0).upper()
                title = normalize_ws(CVE_RE.sub("", text, count=1)).strip(" :–-")
                self.current = {"id": cve, "anchor": hid or cve, "level": level, "title": title,
                                "paragraphs": [], "fields": {}, "links": self.heading_links}
                self.links = self.current["links"]
            elif self.current is not None and level <= self.current["level"]:
                # Neuer Abschnitt ohne CVE auf gleicher Ebene: CVE-Abschnitt ist zu Ende
                self._close_entry()
        elif tag in ("td", "th") and self.cell is not None:
            if self.row is not None:
                self.row.append(normalize_ws("".join(self.cell)))
            self.cell = None
        elif tag == "tr" and self.row is not None:
            self._add_row(self.row)
            self.row = None
        elif tag in _TEXT_BLOCKS and self.block is not None:
            self.block_depth -= 1
            if self.block_depth <= 0:
                self._add_paragraph(normalize_ws("".join(self.block), keep_newlines=True))
                self.block, self.block_depth = None, 0

    def handle_data(self, data: str) -> None:
        if not self.skip:
            # Zeilenumbrüche im Quelltext sind keine Absätze — nur <br> und <pre> zählen
            self._text(data if self.in_pre else data.replace("\n", " "))

    def close(self) -> None:
        super().close()
        self._close_entry()

    # --- Inhalte ------------------------------------------------------------

    def _add_row(self, cells: list[str]) -> None:
        if self.current is None or len(cells) < 2:
            return
        key = FIELD_KEYS.get(cells[0].lower().rstrip(":").strip())
        if key:
            self.current["fields"][key] = " ".join(c for c in cells[1:] if c)

    def _add_paragraph(self, text: str) -> None:
        if self.current is None or not text or self.cell is not None:
            return
        match = FIELD_RE.match(text)
        if match:
            self.current["fields"][FIELD_KEYS[match.group(1).lower()]] = match.group(2).strip()
        else:
            self.current["paragraphs"].append(text)


def normalize_ws(text: str, keep_newlines: bool = False) -> str:
    if keep_newlines:
        lines = (re.sub(r"[ \t\r\f\v]+", " ", line).strip() for line in text.split("\n"))
        return "\n".join(line for line in lines if line)
    return re.sub(r"\s+", " ", text).strip()


def parse_cve_list(html_text: str) -> list[dict[str, Any]]:
    parser = _CveListParser()
    parser.feed(html_text)
    parser.close()
    # Gleiche CVE mehrfach (z. B. Inhaltsverzeichnis + Abschnitt): den mit mehr Inhalt nehmen
    by_id: dict[str, dict[str, Any]] = {}
    for e in parser.entries:
        size = len(e["paragraphs"]) + len(e["fields"])
        prev = by_id.get(e["id"])
        if prev is None or size > len(prev["paragraphs"]) + len(prev["fields"]):
            by_id[e["id"]] = e
    return [e for e in by_id.values() if e["paragraphs"] or e["fields"]]


# ---------------------------------------------------------------------------
# Versionsbereiche → Release-Linien
# ---------------------------------------------------------------------------

def version_key(v: str) -> tuple[int, ...]:
    """Auf 4 Stellen aufgefüllt, damit 0.10.2.0 und 3.7.0 vergleichbar sind."""
    parts = [int(p) for p in v.split(".")[:4]]
    return tuple(parts + [0] * (4 - len(parts)))


INF = (10**9,) * 4
# "and" nur vor Ziffern als Trenner, sonst würde "and later" zerschnitten
SEGMENT_SPLIT = re.compile(r"[,;]|\band\b(?=\s*\d)")
# Log4j-Einträge: "NA" = Kafka nicht betroffen, "All (AK) versions" = alle betroffen
NOT_AFFECTED_RE = re.compile(r"^\s*(n/?a|none|not affected)\s*\.?\s*$", re.IGNORECASE)
ALL_VERSIONS_RE = re.compile(r"\ball\b.*\bversions?\b", re.IGNORECASE)


def parse_ranges(text: str) -> list[dict[str, Any]]:
    """'2.0.0 - 3.3.2, 3.4.0' / 'up to 3.7.0' / '3.4.0 and later' → Bereiche mit Grenzen.

    Ein Bereich ist {"introduced", "last-affected"} oder {"introduced", "before"}
    (obere Grenze exklusiv); fehlt eine Grenze, ist sie offen.
    """
    if not VERSION_RE.search(text) and ALL_VERSIONS_RE.search(text):
        return [{"introduced": "", "last-affected": ""}]
    ranges: list[dict[str, Any]] = []
    for segment in SEGMENT_SPLIT.split(text):
        versions = VERSION_RE.findall(segment)
        if not versions:
            continue
        lower = segment.lower()
        if len(versions) >= 2:
            ranges.append({"introduced": versions[0], "last-affected": versions[1]})
        elif re.search(r"\b(before|prior to|below|less than)\b|<(?!=)", lower):
            ranges.append({"introduced": "", "before": versions[0]})
        elif re.search(r"\b(up to|through|until)\b|<=|≤", lower):
            ranges.append({"introduced": "", "last-affected": versions[0]})
        elif re.search(r"\b(later|after|onwards|newer|above|since)\b|>=|\+", lower):
            ranges.append({"introduced": versions[0], "last-affected": ""})
        else:
            ranges.append({"introduced": versions[0], "last-affected": versions[0]})
    return ranges


def parse_fixes(text: str) -> list[str]:
    """Nur einzelne Versionen zählen als Fix — ein Bereich unter "Fixed versions"
    (z. B. reine Doku-Korrektur bei CVE-2026-41115) ist keine Fix-Version."""
    fixes = set()
    for segment in SEGMENT_SPLIT.split(text):
        versions = VERSION_RE.findall(segment)
        if len(versions) == 1:
            fixes.add(versions[0])
    return sorted(fixes, key=version_key)


def ranges_from_record(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Fallback: betroffene Versionen aus dem CVE-Record (CVE JSON 5), nur Kafka-Produkte."""
    ranges = []
    for product in (record.get("containers", {}).get("cna", {}).get("affected") or []):
        # Log4j-CVEs stehen in der Kafka-Liste, ihr Record beschreibt aber Log4j-Versionen
        if "kafka" not in str(product.get("product") or "").lower():
            continue
        for v in product.get("versions") or []:
            if v.get("status") != "affected" or not VERSION_RE.fullmatch(str(v.get("version", ""))):
                continue
            # Grenzen wie "unspecified" oder "*" zählen als offen
            le, lt = (str(v.get(k) or "") for k in ("lessThanOrEqual", "lessThan"))
            if VERSION_RE.fullmatch(le):
                ranges.append({"introduced": v["version"], "last-affected": le})
            elif VERSION_RE.fullmatch(lt):
                ranges.append({"introduced": v["version"], "before": lt})
            elif le or lt:
                ranges.append({"introduced": v["version"], "last-affected": ""})
            else:
                ranges.append({"introduced": v["version"], "last-affected": v["version"]})
    return ranges


def range_overlaps(r: dict[str, Any], major: int) -> bool:
    start, nxt = (major, 0, 0, 0), (major + 1, 0, 0, 0)
    lo = version_key(r["introduced"]) if VERSION_RE.fullmatch(r.get("introduced") or "") else (0, 0, 0, 0)
    if lo >= nxt:
        return False
    if r.get("before"):
        return version_key(r["before"]) > start
    hi = r.get("last-affected") or ""
    return (version_key(hi) if VERSION_RE.fullmatch(hi) else INF) >= start


def format_range(r: dict[str, Any]) -> str:
    lo = r.get("introduced") or "?"
    if r.get("before"):
        return f"{lo} – <{r['before']}"
    hi = r.get("last-affected")
    if hi == lo:
        return lo
    return f"{lo} – {hi or 'neueste'}"


def line_status(ranges: list[dict[str, Any]], fixes: list[str]) -> dict[str, Any]:
    """Je Linie: betroffene Bereiche und Fix-Versionen dieser Linie (leer = kein Fix in der Linie)."""
    lines: dict[str, Any] = {}
    for major in LINES:
        hit = [format_range(r) for r in ranges if range_overlaps(r, major)]
        if hit:
            lines[f"{major}.x"] = {
                "affected": hit,
                "fixes": sorted({f for f in fixes if version_key(f)[0] == major}, key=version_key),
            }
    return lines


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def http_get(url: str, accept: str, extra_headers: dict[str, str] | None = None) -> bytes | None:
    """GET mit Retries; 404 → None (CVE-Record noch nicht veröffentlicht)."""
    headers = {"User-Agent": "scan-tools-kafka/1.0", "Accept": accept, **(extra_headers or {})}
    request = urllib.request.Request(url, headers=headers)
    last_exc: Exception | None = None
    for attempt in range(DOWNLOAD_RETRIES):
        try:
            with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            last_exc = exc
        except OSError as exc:
            last_exc = exc
        time.sleep(1 + attempt * 2)
    raise CveError(f"Download von {url} fehlgeschlagen: {last_exc}")


def fetch_listing() -> list[dict[str, Any]]:
    body = http_get(SOURCE_URL, "text/html")
    if body is None:
        raise CveError(f"{SOURCE_URL} nicht gefunden (404)")
    listing = parse_cve_list(body.decode("utf-8", errors="replace"))
    if not listing:
        raise CveError(f"Keine CVEs auf {SOURCE_URL} gefunden — hat sich das Seitenformat geändert?")
    return listing


def fetch_record(cve: str) -> dict[str, Any]:
    body = http_get(RECORD_URL.format(id=cve), "application/json")
    if body is None:
        return {}
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise CveError(f"CVE-Record {cve} ist kein gültiges JSON: {exc}") from exc
    return data if isinstance(data, dict) else {}


def record_metrics(record: dict[str, Any]) -> dict[str, Any]:
    """Bester verfügbarer Score: CVSS des CNA (Apache), dann ADP (CISA), dann textuelle Einstufung."""
    containers = record.get("containers") or {}
    sources = [("Apache", containers.get("cna") or {})]
    sources += [(str((adp.get("providerMetadata") or {}).get("shortName") or "ADP"), adp)
                for adp in containers.get("adp") or []]
    for source, container in sources:
        for metric in container.get("metrics") or []:
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                cvss = metric.get(key)
                if cvss and cvss.get("baseSeverity"):
                    return {"severity": str(cvss["baseSeverity"]).upper(), "cvssScore": cvss.get("baseScore"),
                            "cvssVector": cvss.get("vectorString") or "", "scoreSource": source}
    for metric in (containers.get("cna") or {}).get("metrics") or []:
        text = str(((metric.get("other") or {}).get("content") or {}).get("text") or "").lower()
        if text in TEXTUAL_SEVERITY:
            return {"severity": TEXTUAL_SEVERITY[text], "cvssScore": None, "cvssVector": "",
                    "scoreSource": f"Apache ({text})"}
    return {"severity": "", "cvssScore": None, "cvssVector": "", "scoreSource": ""}


def nvd_metrics(cve: str) -> dict[str, Any] | None:
    """CVSS aus der NVD (v3.1, v3.0, v2), falls der CVE-Record keinen Score hat."""
    key = os.environ.get("NVD_API_KEY")
    body = http_get(NVD_URL.format(id=cve), "application/json", {"apiKey": key} if key else None)
    try:
        vulns = json.loads(body or b"{}").get("vulnerabilities") or []
    except json.JSONDecodeError:
        return None
    metrics = (vulns[0].get("cve") or {}).get("metrics") or {} if vulns else {}
    for name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(name) or []:
            data = m.get("cvssData") or {}
            sev = data.get("baseSeverity") or m.get("baseSeverity")
            if sev:
                version = name.removeprefix("cvssMetricV").replace("31", "3.1").replace("30", "3.0")
                return {"severity": str(sev).upper(), "cvssScore": data.get("baseScore"),
                        "cvssVector": data.get("vectorString") or "", "scoreSource": f"NVD (CVSS {version})"}
    return None


def record_cwes(record: dict[str, Any]) -> list[str]:
    cwes = []
    for pt in (record.get("containers", {}).get("cna", {}).get("problemTypes") or []):
        for d in pt.get("descriptions") or []:
            cwe = d.get("cweId") or ""
            if cwe and cwe not in cwes:
                cwes.append(cwe)
    return cwes


def record_references(record: dict[str, Any]) -> list[str]:
    refs = [str(r.get("url") or "") for r in (record.get("containers", {}).get("cna", {}).get("references") or [])]
    return [r for r in refs if r.startswith(("http://", "https://"))]


def build_entry(item: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    fields = item["fields"]
    meta = record.get("cveMetadata") or {}
    cna = (record.get("containers") or {}).get("cna") or {}
    affected_text = fields.get("affected", "")
    fixed_text = fields.get("fixed", "")
    not_affected = bool(NOT_AFFECTED_RE.match(affected_text))
    ranges = [] if not_affected else parse_ranges(affected_text) or ranges_from_record(record)
    fixes = parse_fixes(fixed_text)
    # Rückverweise auf die CVE-Liste selbst und auf cve.org bringen nichts
    references = [r for r in dict.fromkeys(item["links"] + record_references(record))
                  if not SELF_LINK_RE.match(r) and r != CVE_ORG_URL.format(id=item["id"])]
    return {
        "id": item["id"],
        "url": f"{SOURCE_URL}#{item['anchor']}",
        "title": item["title"] or cna.get("title") or "",
        "published": str(meta.get("datePublished") or "")[:10],
        "updated": str(meta.get("dateUpdated") or "")[:10],
        **record_metrics(record),
        "weakness": record_cwes(record),
        "affectedText": affected_text,
        "fixedText": fixed_text,
        "ranges": ranges,
        "fixes": fixes,
        # Ohne auswertbare Versionsangabe ist offen, welche Linien betroffen sind
        "affectedUnknown": not ranges and not not_affected,
        "lines": line_status(ranges, fixes),
        "description": "\n\n".join(item["paragraphs"]),
        "impact": fields.get("impact", ""),
        "advice": fields.get("advice", ""),
        "references": references,
    }


def merge_cves(local: dict[str, Any] | None, quiet: bool) -> tuple[dict[str, Any], dict[str, int]]:
    """Lädt Liste + alle CVE-Records (wenige Dutzend) und führt sie in die lokale Kopie ein."""
    local_by_id = {str(c.get("id", "")).upper(): c for c in (local or {}).get("cves", [])}
    listing = fetch_listing()
    if not quiet:
        print(f"{len(listing)} CVEs in der Liste, lade CVE-Records ...", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as pool:
        records = list(pool.map(lambda it: fetch_record(it["id"]), listing))

    metric_keys = ("severity", "cvssScore", "cvssVector", "scoreSource")
    stats = {"neu": 0, "aktualisiert": 0, "unverändert": 0, "nur lokal": 0}
    merged: dict[str, dict[str, Any]] = {}
    nvd_todo: list[dict[str, Any]] = []
    for item, record in zip(listing, records):
        old = local_by_id.get(item["id"])
        new = build_entry(item, record)
        if not record and old:
            # cve.org vorübergehend ohne Record: bisherige Metadaten behalten
            for key in ("published", "updated", *metric_keys, "weakness"):
                new[key] = old.get(key, new[key])
        if not new["severity"]:
            # NVD-Score einmal holen und danach aus der lokalen Kopie übernehmen
            if old and str(old.get("scoreSource", "")).startswith("NVD"):
                new.update({k: old[k] for k in metric_keys})
            else:
                nvd_todo.append(new)
        merged[item["id"]] = new

    if nvd_todo and not quiet:
        print(f"Lade CVSS aus der NVD für {len(nvd_todo)} CVEs ohne Score im CVE-Record ...", file=sys.stderr)
    for i, entry in enumerate(nvd_todo):
        if i and not os.environ.get("NVD_API_KEY"):
            time.sleep(NVD_DELAY)
        metrics = nvd_metrics(entry["id"])
        if metrics:
            entry.update(metrics)

    for item in listing:
        old, new = local_by_id.get(item["id"]), merged[item["id"]]
        if old is None:
            stats["neu"] += 1
        elif new != old:
            stats["aktualisiert"] += 1
        else:
            stats["unverändert"] += 1
    for key, entry in local_by_id.items():
        if key not in merged:
            stats["nur lokal"] += 1
            merged[key] = entry

    cves = sorted(merged.values(), key=lambda c: (c.get("published", ""), c.get("id", "")), reverse=True)
    return {"source": SOURCE_URL, "lines": [f"{m}.x" for m in LINES], "count": len(cves), "cves": cves}, stats


# ---------------------------------------------------------------------------
# Laden / Speichern
# ---------------------------------------------------------------------------

def validate(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get("cves"), list):
        raise CveError("Unerwartetes Format: Schlüssel 'cves' fehlt")
    return data


def load_cves(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise CveError(f"Datei '{path}' nicht gefunden — zuerst 'download' ausführen oder --refresh verwenden")
    try:
        with path.open(encoding="utf-8") as fh:
            return validate(json.load(fh))
    except json.JSONDecodeError as exc:
        raise CveError(f"Datei '{path}' ist kein gültiges JSON: {exc}") from exc


def save_cves(path: Path, data: dict[str, Any]) -> None:
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


def ensure_cves(path: Path, force: bool, max_age_hours: float, quiet: bool = False) -> dict[str, Any]:
    """Lädt nur neu, wenn erzwungen oder die lokale Kopie zu alt ist, und führt die Daten ein."""
    age = file_age_hours(path)
    if not force and age is not None and age < max_age_hours:
        if not quiet:
            print(f"Lokale Kopie ist {age:.1f} h alt (< {max_age_hours:g} h) — kein Download nötig.", file=sys.stderr)
        return load_cves(path)

    # Lokale Kopie vor dem Download laden: ist sie kaputt, bricht load_cves ab,
    # statt den angesammelten Bestand zu überschreiben.
    local = load_cves(path) if path.exists() else None
    if not quiet:
        print(f"Lade {SOURCE_URL} ...", file=sys.stderr)
    merged, stats = merge_cves(local, quiet=quiet)
    save_cves(path, merged)
    if not quiet:
        print(", ".join(f"{n} {label}" for label, n in stats.items()), file=sys.stderr)
    return merged


# ---------------------------------------------------------------------------
# Filtern / Ausgabe
# ---------------------------------------------------------------------------

SEARCH_FIELDS = (
    "id", "title", "description", "impact", "advice", "affectedText",
    "fixedText", "references", "cvssVector", "weakness",
)


def search_text(c: dict[str, Any]) -> str:
    """Alle durchsuchbaren Felder eines Eintrags als ein String (Listen zusammengefügt)."""
    parts = []
    for key in SEARCH_FIELDS:
        value = c.get(key)
        parts.append(" ".join(map(str, value)) if isinstance(value, list) else str(value or ""))
    return "\n".join(parts)


def filter_cves(
    cves: list[dict[str, Any]],
    line: str | None = None,
    unfixed: bool = False,
    min_severity: str | None = None,
    terms: list[re.Pattern[str]] | None = None,
    since: str | None = None,
) -> list[dict[str, Any]]:
    min_order = SEVERITY_ORDER[min_severity] if min_severity else -1
    result = []
    for c in cves:
        lines = c.get("lines") or {}
        if line and line not in lines:
            continue
        if unfixed:
            # Ohne --line: irgendeine betroffene Linie ohne Fix
            relevant = [lines[line]] if line else list(lines.values())
            if not any(not s.get("fixes") for s in relevant):
                continue
        if SEVERITY_ORDER.get(str(c.get("severity", "")).upper(), -1) < min_order:
            continue
        # ISO-Datumsstrings (YYYY-MM-DD) lassen sich direkt lexikografisch vergleichen
        if since and str(c.get("published", "")) < since:
            continue
        # Mehrere Suchbegriffe sind UND-verknüpft
        if terms:
            text = search_text(c)
            if not all(t.search(text) for t in terms):
                continue
        result.append(c)
    return sorted(result, key=lambda c: (str(c.get("published", "")), str(c.get("id", ""))), reverse=True)


def line_cell(c: dict[str, Any], line: str) -> str:
    status = (c.get("lines") or {}).get(line)
    if status is None:
        return "?" if c.get("affectedUnknown") else "–"
    return ", ".join(status["fixes"]) or "kein Fix"


def format_line(c: dict[str, Any]) -> str:
    cells = "  ".join(f"{clean(line_cell(c, f'{m}.x')):<14}" for m in LINES)
    return (
        f"{clean(c.get('published')):<10}  {clean(c.get('id')):<16}  {clean(c.get('severity')):<8}  "
        f"{cells}  {clean(c.get('title'))}"
    )


def list_header() -> str:
    cells = "  ".join(f"{f'Fix {m}.x':<14}" for m in LINES)
    return f"{'Datum':<10}  {'CVE':<16}  {'Severity':<8}  {cells}  Titel"


def format_details(c: dict[str, Any]) -> str:
    def row(label: str, value: Any) -> str:
        return f"{label + ':':<16}{clean(value)}"

    score = " ".join(str(v) for v in (c.get("cvssScore"), c.get("cvssVector")) if v)
    lines = [row(label, value) for label, value in (
        ("CVE", c.get("id")), ("Titel", c.get("title")), ("Severity", c.get("severity")),
        ("CVSS", f"{score} ({c.get('scoreSource')})" if score else ""),
        ("Veröffentlicht", c.get("published")), ("Link", c.get("url")),
        ("CWE", ", ".join(c.get("weakness") or [])),
        ("Betroffen", c.get("affectedText")), ("Gefixt in", c.get("fixedText")),
    ) if value]
    for line, status in (c.get("lines") or {}).items():
        fixes = ", ".join(status["fixes"]) or "kein Fix in dieser Linie"
        lines.append(row(f"  {line}", f"{', '.join(status['affected'])}  →  {fixes}"))
    for label, key in (("Beschreibung", "description"), ("Impact", "impact"), ("Advice", "advice")):
        if c.get(key):
            lines.append(f"{label}:")
            lines.extend(f"  {clean(line)}" for line in str(c[key]).splitlines())
    if c.get("references"):
        lines.append("Referenzen:")
        lines.extend(f"  {clean(r)}" for r in c["references"])
    return "\n".join(lines)


def header(data: dict[str, Any]) -> str:
    cves = data["cves"]
    newest = max((str(c.get("published", "")) for c in cves), default="?")
    return f"Apache Kafka CVEs — {len(cves)} Einträge, neuester vom {clean(newest)}"


# ---------------------------------------------------------------------------
# Unterbefehle
# ---------------------------------------------------------------------------

def cmd_download(args: argparse.Namespace) -> int:
    data = ensure_cves(args.file, args.force, args.max_age_hours)
    print(header(data))
    print(f"Datei: {args.file}")
    return 0


def compile_terms(terms: list[str], regex: bool) -> list[re.Pattern[str]]:
    try:
        return [re.compile(t if regex else re.escape(t), re.IGNORECASE) for t in terms]
    except re.error as exc:
        raise CveError(f"Ungültiger regulärer Ausdruck: {exc}") from exc


def cmd_list(args: argparse.Namespace) -> int:
    """Gemeinsame Implementierung für 'list' und 'search' (list hat keine Suchbegriffe)."""
    terms = compile_terms(args.terms, args.regex)
    if args.refresh:
        data = ensure_cves(args.file, force=False, max_age_hours=args.max_age_hours, quiet=args.format == "json")
    else:
        data = load_cves(args.file)

    cves = filter_cves(
        data["cves"],
        line=f"{args.line}.x" if args.line else None,
        unfixed=args.unfixed,
        min_severity=args.min_severity,
        terms=terms,
        since=args.since,
    )
    total = len(cves)
    if args.limit > 0:
        cves = cves[: args.limit]

    if args.format == "json":
        json.dump(cves, sys.stdout, indent=2, ensure_ascii=False)
        print()
        return 0

    print(header(data))
    print(f"{total} Treffer, zeige {len(cves)}\n")
    print(list_header())
    for c in cves:
        print(format_line(c))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    data = load_cves(args.file)
    by_id = {str(c.get("id", "")).upper(): c for c in data["cves"]}

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
        print("\n\n".join(format_details(c) for c in found))

    for cve in missing:
        print(f"{cve}: nicht in der Kafka-CVE-Liste", file=sys.stderr)
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
        description="Apache-Kafka-CVEs (kafka.apache.org/community/cve-list) herunterladen und durchsuchen.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit-Codes: 0 = OK, 1 = CVE nicht gefunden (show), 2 = Fehler",
    )
    parser.add_argument(
        "--file", type=Path, default=DEFAULT_FILE,
        help=f"Pfad der lokalen Datei (Standard: {DEFAULT_FILE.name} neben dem Skript)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_dl = sub.add_parser("download", help="CVE-Liste und CVE-Records herunterladen")
    p_dl.add_argument("--force", action="store_true", help="Download auch bei aktueller lokaler Kopie erzwingen")
    p_dl.add_argument(
        "--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS,
        help="Lokale Kopie gilt so lange als aktuell (Standard: %(default)s)",
    )
    p_dl.set_defaults(func=cmd_download)

    # Filter- und Ausgabeoptionen, die 'list' und 'search' gemeinsam haben
    filters = argparse.ArgumentParser(add_help=False)
    filters.add_argument("-n", "--limit", type=int, default=30, help="Maximale Anzahl (0 = alle, Standard: %(default)s)")
    filters.add_argument("--line", type=int, choices=LINES, help="Nur CVEs, die diese Release-Linie betreffen")
    filters.add_argument(
        "--unfixed", action="store_true",
        help="Nur CVEs ohne Fix in der Linie (mit --line) bzw. in irgendeiner betroffenen Linie",
    )
    filters.add_argument(
        "--min-severity", type=severity, metavar="SEVERITY",
        help=f"Mindest-Severity ({', '.join(SEVERITIES)}, ohne Groß-/Kleinschreibung)",
    )
    filters.add_argument("--since", type=iso_date, help="Nur CVEs ab diesem Datum (YYYY-MM-DD)")
    filters.add_argument("--format", choices=("text", "json"), default="text", help="Ausgabeformat")
    filters.add_argument(
        "--refresh", action="store_true",
        help="Vorher herunterladen, falls die lokale Kopie fehlt oder älter als --max-age-hours ist",
    )
    filters.add_argument("--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS, help=argparse.SUPPRESS)

    p_list = sub.add_parser("list", parents=[filters], help="CVEs auflisten (neueste zuerst)")
    p_list.set_defaults(func=cmd_list, terms=[], regex=False)

    p_search = sub.add_parser(
        "search", parents=[filters],
        help="Volltextsuche (CVE, Titel, Beschreibung, Impact, Advice, Versionen, Referenzen)",
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
    except CveError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        # z. B. "cves.py list | head" — kein Fehler, nur vorzeitig beendet
        sys.stderr.close()
        return 0


if __name__ == "__main__":
    sys.exit(main())
