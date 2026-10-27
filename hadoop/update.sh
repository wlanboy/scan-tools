#!/usr/bin/env bash
# update.sh - Aktualisiert hadoop/cves.json für die CVE-Übersicht (hadoop/index.html)
#
# Usage:
#   hadoop/update.sh
#
# Ältere CVEs ohne Score im CVE-Record holen den CVSS aus der NVD; mit API-Key schneller:
#   NVD_API_KEY=... hadoop/update.sh
#
# Anzeige im Browser (fetch() funktioniert nicht über file://):
#   python3 -m http.server -d hadoop 8000   ->   http://localhost:8000/

set -euo pipefail

cd "$(dirname "$0")/.."

# --force: Die Altersprüfung nutzt die mtime der Datei, die nach checkout/pull frisch ist
uv run hadoop/cves.py download --force

echo "hadoop/cves.json aktualisiert"
