#!/usr/bin/env bash
# update.sh - Aktualisiert cve/cve-counts.json für das CVE-Diagramm (cve/index.html)
#
# Usage:
#   cve/update.sh                    # inkrementell (ab dem letzten Tag in der Datei)
#   cve/update.sh --since 2020-01-01 # ab Datum komplett neu
#
# Schneller mit NVD-API-Key: NVD_API_KEY=... cve/update.sh
#
# Anzeige im Browser (fetch() funktioniert nicht über file://):
#   python3 -m http.server -d cve 8000   ->   http://localhost:8000/

set -euo pipefail

cd "$(dirname "$0")/.."

uv run cve/nvd_counts.py "$@"

echo "cve/cve-counts.json aktualisiert"
