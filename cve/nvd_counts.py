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
Die Datei wird nach jedem Zeitfenster geschrieben; ein abgebrochener Lauf macht
beim nächsten Aufruf dort weiter.

Ohne API-Key erlaubt die NVD 5 Requests pro 30 Sekunden, der erste Lauf ab 2020
dauert deshalb etwa 15-20 Minuten. Mit Key (Umgebungsvariable NVD_API_KEY,
https://nvd.nist.gov/developers/request-an-api-key) geht es etwa zehnmal schneller.

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
import datetime as dt
import gzip
import http.client
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
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


def count_window(start: dt.date, end: dt.date, api_key: str | None, delay: float) -> dict[str, list[int]]:
    days: dict[str, list[int]] = {}
    index, total = 0, None
    while total is None or index < total:
        data = fetch_page(start, end, index, api_key)
        total = int(data.get("totalResults", 0))
        vulns = data["vulnerabilities"]
        for item in vulns:
            cve = item.get("cve") or {}
            day = str(cve.get("published", ""))[:10]
            if not day:
                continue
            row = days.setdefault(day, [0] * len(KEYS))
            row[KEYS.index(severity(cve))] += 1
        index += len(vulns)
        if not vulns:
            break
        time.sleep(delay)
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

        print(f"Lade CVEs von {start} bis {today}{' (mit API-Key)' if api_key else ''}", flush=True)
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
