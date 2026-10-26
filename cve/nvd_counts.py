#!/usr/bin/env python3
"""
nvd_counts.py - Zählt die veröffentlichten CVEs pro Tag und Severity über die
NVD CVE API 2.0 und schreibt sie nach cve/cve-counts.json (für cve/index.html).

Gespeichert werden nur Tageszahlen, keine einzelnen CVEs:
  "days": {"2026-10-25": [critical, high, medium, low, none], ...}

Tage ohne CVEs fehlen in der Datei. Abgelehnte CVEs (Rejected) werden nicht gezählt.
Severity: CVSS v3.1, sonst v4.0, v3.0, v2 - jeweils die Primary-Bewertung (NVD)
bevorzugt, sonst die erste vorhandene (meist vom CNA). "none" = ohne Bewertung.

Inkrementell: Geladen wird ab dem letzten Tag in der Datei. Nur dieser Tag wird
erneut abgefragt, weil dort noch CVEs dazukommen können; ältere Tage bleiben wie
sie sind (auch wenn die NVD Bewertungen später nachträgt - dafür --since).

Quelle: Kurze Zeiträume (unter WINDOW_DAYS Tagen) kommen über die CVE API. Längere
(erster Lauf, --since) aus den JSON-Jahres-Feeds der NVD (statische Dateien, ca.
230 MB gzip, kein Rate-Limit), danach wird der letzte Tag per API aufgefrischt.
Die API ist bei großen Seiten langsam und läuft oft in Timeouts; ohne API-Key
erlaubt sie nur 5 Requests pro 30 Sekunden. Die Feeds sind nach CVE-Jahr sortiert,
nicht nach Veröffentlichung, deshalb werden immer alle Jahrgänge geladen (alte IDs
werden teils Jahre später veröffentlicht). Mit NVD_API_KEY
(https://nvd.nist.gov/developers/request-an-api-key) ist die API schneller.

Beispiele:
  uv run cve/nvd_counts.py
  uv run cve/nvd_counts.py --since 2026-01-01      # ab Datum neu laden
  NVD_API_KEY=... uv run cve/nvd_counts.py

Exit-Codes:
  0 - Erfolg
  2 - Fehler (Download fehlgeschlagen, Datei ungültig, ...)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import gzip
import http.client
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Iterator

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
FEED_FIRST_YEAR = 2002     # der 2002er Feed enthält auch CVE-1999 bis CVE-2001
FEED_WORKERS = 8           # parallele Downloads, eine Verbindung ist recht langsam
FEED_CHUNK = 4 << 20       # Zeichen pro Lesevorgang beim Parsen eines Feeds
DEFAULT_FILE = Path(__file__).resolve().parent / "cve-counts.json"
DEFAULT_START = dt.date(2020, 1, 1)
WINDOW_DAYS = 100          # API erlaubt höchstens 120 Tage pro Abfrage
PAGE_SIZE = 2000           # Maximum der API
TIMEOUT = 60
RETRIES = 6

KEYS = ["critical", "high", "medium", "low", "none"]
METRIC_ORDER = ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"]


class NvdError(Exception):
    """Download fehlgeschlagen oder Datei ungültig."""


# ---------------------------------------------------------------------------
# NVD-Abfrage
# ---------------------------------------------------------------------------

def fetch_page(start: dt.date, end: dt.date, index: int, api_key: str | None) -> dict[str, Any]:
    params = urllib.parse.urlencode({
        "pubStartDate": f"{start.isoformat()}T00:00:00.000",
        "pubEndDate": f"{end.isoformat()}T23:59:59.999",
        "resultsPerPage": PAGE_SIZE,
        "startIndex": index,
    })
    headers = {"Accept-Encoding": "gzip", "User-Agent": "scan-tools/nvd_counts"}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(f"{API_URL}?{params}&noRejected", headers=headers)

    for attempt in range(1, RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
            data = json.loads(body)
            if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                raise NvdError("Unerwartetes Antwortformat")
            return data
        # OSError deckt URLError/HTTPError und socket.timeout (Python 3.9) ab, ValueError kaputtes JSON/gzip
        except (OSError, http.client.HTTPException, ValueError, NvdError) as exc:
            # 403/429 = Rate-Limit, 5xx = NVD überlastet: mit wachsender Pause wiederholen
            if attempt == RETRIES:
                raise NvdError(f"{start}..{end} startIndex={index}: {exc}") from exc
            wait = 15 * attempt
            print(f"    Fehler ({exc}), neuer Versuch in {wait}s", file=sys.stderr, flush=True)
            time.sleep(wait)
    raise AssertionError("unreachable")


def severity(cve: dict[str, Any]) -> str:
    metrics = cve.get("metrics") or {}
    for key in METRIC_ORDER:
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        # v2 hat baseSeverity auf Metrik-Ebene, v3/v4 in cvssData
        sev = (entry.get("cvssData") or {}).get("baseSeverity") or entry.get("baseSeverity") or ""
        sev = sev.lower()
        return sev if sev in KEYS else "none"
    return "none"


def tally(days: dict[str, list[int]], vulns: Iterable[Any], start: dt.date, end: dt.date) -> None:
    first, last = start.isoformat(), end.isoformat()
    for item in vulns:
        cve = item.get("cve") or {}
        day = str(cve.get("published", ""))[:10]
        # die API filtert Rejected selbst (noRejected), die Feeds nicht
        if not day or not first <= day <= last or cve.get("vulnStatus") == "Rejected":
            continue
        row = days.setdefault(day, [0] * len(KEYS))
        row[KEYS.index(severity(cve))] += 1


def count_window(start: dt.date, end: dt.date, api_key: str | None, delay: float) -> dict[str, list[int]]:
    days: dict[str, list[int]] = {}
    index, total = 0, None
    while total is None or index < total:
        data = fetch_page(start, end, index, api_key)
        total = int(data.get("totalResults", 0))
        vulns = data["vulnerabilities"]
        tally(days, vulns, start, end)
        index += len(vulns)
        if not vulns:
            break
        time.sleep(delay)
    return days


def download(url: str, dest: Path) -> Path:
    req = urllib.request.Request(url, headers={"User-Agent": "scan-tools/nvd_counts"})
    for attempt in range(1, RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp, dest.open("wb") as fh:
                shutil.copyfileobj(resp, fh, 1 << 20)
                expected = resp.headers.get("Content-Length")
            if expected is not None and dest.stat().st_size != int(expected):
                raise NvdError(f"unvollständig ({dest.stat().st_size} von {expected} Bytes)")
            return dest
        except (OSError, http.client.HTTPException, NvdError) as exc:
            if attempt == RETRIES:
                raise NvdError(f"{url}: {exc}") from exc
            wait = 15 * attempt
            print(f"    Fehler bei {dest.name} ({exc}), neuer Versuch in {wait}s", file=sys.stderr, flush=True)
            time.sleep(wait)
    raise AssertionError("unreachable")


def iter_feed(path: Path) -> Iterator[Any]:
    """Einträge aus "vulnerabilities" einzeln dekodieren - json.load auf den
    ganzen Feed braucht mehrere GB RAM."""
    decoder = json.JSONDecoder()
    sep = re.compile(r"[\s,]*")
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        buf = fh.read(FEED_CHUNK)
        key = buf.find('"vulnerabilities"')
        pos = buf.find("[", key) + 1 if key >= 0 else 0
        if pos == 0:
            raise NvdError(f"{path.name}: unerwartetes Format")
        while True:
            pos = sep.match(buf, pos).end()
            if buf.startswith("]", pos):
                return
            try:
                item, pos = decoder.raw_decode(buf, pos)
            except json.JSONDecodeError:
                # Eintrag geht über das Pufferende hinaus: nachladen
                more = fh.read(FEED_CHUNK)
                if not more:
                    raise
                buf, pos = buf[pos:] + more, 0
                continue
            yield item


def count_feeds(start: dt.date, end: dt.date) -> dict[str, list[int]]:
    days: dict[str, list[int]] = {}
    years = range(FEED_FIRST_YEAR, end.year + 1)
    with tempfile.TemporaryDirectory(prefix="nvd-feeds-") as tmp:
        pool = concurrent.futures.ThreadPoolExecutor(FEED_WORKERS)
        try:
            futures = {pool.submit(download, FEED_URL.format(year=y), Path(tmp) / f"{y}.json.gz"): y
                       for y in years}
            for done, fut in enumerate(concurrent.futures.as_completed(futures), 1):
                path = fut.result()
                try:
                    tally(days, iter_feed(path), start, end)
                except (OSError, EOFError, ValueError) as exc:
                    raise NvdError(f"{path.name}: {exc}") from exc
                path.unlink()
                print(f"  Feed {futures[fut]} ({done}/{len(years)})", flush=True)
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
    return days


# ---------------------------------------------------------------------------
# Datei
# ---------------------------------------------------------------------------

def load(path: Path) -> dict[str, list[int]]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NvdError(f"{path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("days"), dict) or data.get("keys") != KEYS:
        raise NvdError(f"{path}: unerwartetes Format")
    return data["days"]


def save(path: Path, days: dict[str, list[int]]) -> None:
    # Ein Tag pro Zeile, sortiert: git-Diffs zeigen nur geänderte Tage
    lines = [f'    "{day}": {json.dumps(days[day])}' for day in sorted(days)]
    updated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = (
        "{\n"
        f'  "source": "NVD CVE API 2.0",\n'
        f'  "updated": "{updated}",\n'
        f'  "keys": {json.dumps(KEYS)},\n'
        '  "days": {\n' + ",\n".join(lines) + "\n  }\n}\n"
    )
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".cve-counts-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)  # mkstemp legt 0600 an
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", type=Path, default=DEFAULT_FILE, help=f"Ausgabedatei (Standard: {DEFAULT_FILE.name})")
    ap.add_argument("--since", type=dt.date.fromisoformat,
                    help="ab diesem Datum neu laden (Standard: letzter Tag in der Datei, sonst 2020-01-01)")
    args = ap.parse_args()

    api_key = os.environ.get("NVD_API_KEY") or None
    delay = 0.7 if api_key else 6.5

    try:
        days = load(args.file)
        today = dt.datetime.now(dt.timezone.utc).date()
        if args.since:
            start = args.since
        elif days:
            start = dt.date.fromisoformat(max(days))
        else:
            start = DEFAULT_START

        if (today - start).days >= WINDOW_DAYS:
            print(f"Lade CVEs von {start} bis {today} aus den NVD-Jahres-Feeds", flush=True)
            counts = count_feeds(start, today)
            for day in [d for d in days if d >= start.isoformat()]:
                del days[day]
            days.update(counts)
            save(args.file, days)
            print(f"  {start} .. {today}: {sum(sum(r) for r in counts.values())} CVEs", flush=True)
            # Feeds werden einmal am Tag erzeugt: letzten Tag per API auffrischen
            start = dt.date.fromisoformat(max(days)) if days else today

        print(f"Lade CVEs von {start} bis {today} über die API{' (mit API-Key)' if api_key else ''}", flush=True)
        while start <= today:
            end = min(start + dt.timedelta(days=WINDOW_DAYS - 1), today)
            counts = count_window(start, end, api_key, delay)
            # Fenster komplett ersetzen, auch Tage, die jetzt 0 CVEs haben
            for day in [d for d in days if start.isoformat() <= d <= end.isoformat()]:
                del days[day]
            days.update(counts)
            save(args.file, days)
            print(f"  {start} .. {end}: {sum(sum(r) for r in counts.values())} CVEs", flush=True)
            start = end + dt.timedelta(days=1)
    except NvdError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nAbgebrochen - bisherige Fenster sind gespeichert.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
