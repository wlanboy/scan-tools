#!/usr/bin/env python3
"""
Istio Release CVE Scanner
Durchsucht die Istio Release Notes (Patch-Announcements + Change Notes der
Minor-Releases) nach CVE-Nummern. Verlinkte Security Bulletins
(ISTIO-SECURITY-YYYY-NNN) werden ebenfalls ausgewertet, da manche Patch-Releases
die CVEs nur dort auflisten.

Berücksichtigt nur 1.2x und 1.3x Releases (keine alpha/beta/rc), vom neuesten
Release zurück bis --min-version (Standard 1.26).

Quellen:
  https://istio.io/latest/news/releases/
  https://istio.io/latest/news/security/

Exit codes:
  0 - Scan erfolgreich
  2 - Fehler (Netzwerk, Parsing)
"""

from __future__ import annotations

import argparse
import html
import io
import json
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


BASE_URL = "https://istio.io/latest/news/releases/"
USER_AGENT = "scan-tools/istio-release-cves (+https://github.com/wlanboy/scan-tools)"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
CVSS_RE = re.compile(r"CVSS score\s*([\d.]+)(?:\s*,\s*([A-Za-z]+))?", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
ARTICLE_RE = re.compile(r"<article\b.*?</article>", re.DOTALL | re.IGNORECASE)
MINOR_LINK_RE = re.compile(r"/news/releases/(1\.(?:2|3)\d)\.x/")
BULLETIN_RE = re.compile(r"https://istio\.io/latest/news/security/istio-security-\d{4}-\d+/")
PRERELEASE_RE = re.compile(r"(alpha|beta|rc)", re.IGNORECASE)


# ==============================================================================
# Datenmodell
# ==============================================================================

@dataclass
class CveHit:
    cve: str
    cvss: str = ""
    severity: str = ""
    description: str = ""
    source: str = ""          # URL der Seite, auf der die CVE gefunden wurde
    via_bulletin: str = ""    # Bulletin-ID, falls über ein Security Bulletin gefunden


@dataclass
class Release:
    version: str
    url: str
    cves: list[CveHit] = field(default_factory=list)


# ==============================================================================
# HTTP
# ==============================================================================

_cache: dict[str, str] = {}


def fetch(url: str, retries: int = 3, timeout: int = 30) -> str:
    if url in _cache:
        return _cache[url]
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                _cache[url] = body
                return body
        except urllib.error.HTTPError as e:
            if e.code == 404:
                _cache[url] = ""
                return ""
            last_err = e
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
        time.sleep(1 + attempt)
    raise RuntimeError(f"Abruf fehlgeschlagen: {url} ({last_err})")


# ==============================================================================
# Parsing
# ==============================================================================

def version_key(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split("."))


def article(page: str) -> str:
    """Nur den eigentlichen Inhalt auswerten (keine Navigation, kein Release-Banner)."""
    m = ARTICLE_RE.search(page)
    return m.group(0) if m else page


def to_text(fragment: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(TAG_RE.sub(" ", fragment))).strip()


def context_for(content: str, pos: int) -> str:
    """Text des umschließenden <li> (oder <p>/<tr>) einer Fundstelle."""
    for open_tag, close_tag in (("<li", "</li>"), ("<p", "</p>"), ("<tr", "</tr>")):
        start = content.rfind(open_tag, 0, pos)
        end = content.find(close_tag, pos)
        # Kein anderes schließendes Tag gleichen Typs dazwischen -> echtes Elternelement
        if start != -1 and end != -1 and content.find(close_tag, start, pos) == -1:
            return to_text(content[start:end])
    return to_text(content[max(0, pos - 200):pos + 200])


def extract_cves(page: str, source: str, via_bulletin: str = "") -> list[CveHit]:
    content = article(page)
    hits: dict[str, CveHit] = {}
    for m in CVE_RE.finditer(content):
        cve = m.group(0)
        ctx = context_for(content, m.start())
        cvss = CVSS_RE.search(ctx)
        hit = CveHit(
            cve=cve,
            cvss=cvss.group(1) if cvss else "",
            severity=(cvss.group(2) or "").capitalize() if cvss else "",
            description=ctx,
            source=source,
            via_bulletin=via_bulletin,
        )
        prev = hits.get(cve)
        # Fundstelle mit CVSS-Angabe bzw. mehr Kontext bevorzugen
        if prev is None or (hit.cvss and not prev.cvss) or (
            bool(hit.cvss) == bool(prev.cvss) and len(hit.description) > len(prev.description)
        ):
            hits[cve] = hit
    return list(hits.values())


def bulletin_links(page: str) -> list[str]:
    return sorted(set(BULLETIN_RE.findall(article(page))))


def bulletin_id(url: str) -> str:
    return url.rstrip("/").rsplit("/", 1)[-1].upper()


def list_minors(min_version: str) -> list[str]:
    index = fetch(BASE_URL)
    minors = {m for m in MINOR_LINK_RE.findall(index) if version_key(m) >= version_key(min_version)}
    if not minors:
        raise RuntimeError("Keine passenden Minor-Releases auf der Release-Übersicht gefunden")
    return sorted(minors, key=version_key, reverse=True)


def list_releases(minor: str) -> list[Release]:
    page = fetch(f"{BASE_URL}{minor}.x/")
    link_re = re.compile(
        rf"https://istio\.io/latest/news/releases/{re.escape(minor)}\.x/announcing-([^/\s\"'>]+)/"
    )
    releases: dict[str, Release] = {}
    for m in link_re.finditer(page):
        name = m.group(1)
        if PRERELEASE_RE.search(name):
            continue
        if not re.fullmatch(rf"{re.escape(minor)}(\.\d+)?", name):
            continue
        version = name if name.count(".") == 2 else f"{name}.0"
        releases[version] = Release(version=version, url=m.group(0))
    return sorted(releases.values(), key=lambda r: version_key(r.version), reverse=True)


def scan_release(rel: Release, follow_bulletins: bool) -> Release:
    pages = [rel.url]
    if rel.version.endswith(".0"):
        # Minor-Release: CVEs stehen in den Change Notes
        pages.append(f"{rel.url}change-notes/")

    found: dict[str, CveHit] = {}
    bulletins: set[str] = set()
    for url in pages:
        page = fetch(url)
        if not page:
            continue
        for hit in extract_cves(page, url):
            found.setdefault(hit.cve, hit)
        if follow_bulletins:
            bulletins.update(bulletin_links(page))

    for burl in sorted(bulletins):
        page = fetch(burl)
        if not page:
            continue
        for hit in extract_cves(page, burl, via_bulletin=bulletin_id(burl)):
            prev = found.get(hit.cve)
            if prev is None:
                found[hit.cve] = hit
            elif not prev.cvss and hit.cvss:
                prev.cvss, prev.severity = hit.cvss, hit.severity

    rel.cves = sorted(found.values(), key=lambda h: h.cve)
    return rel


# ==============================================================================
# Ausgabe
# ==============================================================================

def print_text(releases: list[Release], verbose: bool) -> None:
    for rel in releases:
        if not rel.cves:
            print(f"Istio {rel.version:<8} -")
            continue
        print(f"Istio {rel.version:<8} {len(rel.cves)} CVE(s)  {rel.url}")
        for h in rel.cves:
            score = f"{h.cvss} {h.severity}".strip() or "n/a"
            via = f"  [via {h.via_bulletin}]" if h.via_bulletin else ""
            print(f"    {h.cve:<16} CVSS {score:<14}{via}")
            if verbose:
                desc = h.description if len(h.description) <= 200 else h.description[:197] + "..."
                print(f"        {desc}")

    summary: dict[str, list[str]] = {}
    for rel in releases:
        for h in rel.cves:
            summary.setdefault(h.cve, []).append(rel.version)

    print()
    print(f"Zusammenfassung: {len(summary)} eindeutige CVE(s) in {len(releases)} Releases")
    for cve in sorted(summary, key=lambda c: (int(c.split("-")[1]), int(c.split("-")[2])), reverse=True):
        versions = sorted(summary[cve], key=version_key)
        print(f"    {cve:<16} {', '.join(versions)}")


def print_json(releases: list[Release]) -> None:
    print(json.dumps([asdict(r) for r in releases], indent=2, ensure_ascii=False))


# ==============================================================================
# Main
# ==============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sucht CVE-Nummern in den Istio Release Notes (1.2x/1.3x, ohne alpha/beta/rc)."
    )
    parser.add_argument("--min-version", default="1.26",
                        help="Ältestes Minor-Release, das gescannt wird (Standard: 1.26)")
    parser.add_argument("--no-bulletins", action="store_true",
                        help="Verlinkte ISTIO-SECURITY Bulletins nicht auswerten")
    parser.add_argument("--json", action="store_true", help="Ausgabe als JSON")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Beschreibung je CVE ausgeben")
    parser.add_argument("--workers", type=int, default=8,
                        help="Parallele HTTP-Abrufe (Standard: 8)")
    args = parser.parse_args()

    if not re.fullmatch(r"1\.\d+", args.min_version):
        print(f"Ungültige --min-version: {args.min_version} (erwartet z.B. 1.26)", file=sys.stderr)
        return 2

    try:
        minors = list_minors(args.min_version)
        print(f"Minor-Releases: {', '.join(minors)}", file=sys.stderr)
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            per_minor = list(pool.map(list_releases, minors))
            releases = [r for rels in per_minor for r in rels]
            print(f"Scanne {len(releases)} Release-Seiten ...", file=sys.stderr)
            releases = list(pool.map(lambda r: scan_release(r, not args.no_bulletins), releases))
    except RuntimeError as e:
        print(f"Fehler: {e}", file=sys.stderr)
        return 2

    if args.json:
        print_json(releases)
    else:
        print_text(releases, args.verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
