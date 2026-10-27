#!/usr/bin/env bash
# update.sh - Aktualisiert kafka/cves.json für die CVE-Übersicht (kafka/index.html)
#
# Usage:
#   kafka/update.sh
#
# Ältere CVEs ohne Score im CVE-Record holen den CVSS aus der NVD; mit API-Key schneller:
#   NVD_API_KEY=... kafka/update.sh
#
# Anzeige im Browser (fetch() funktioniert nicht über file://):
#   python3 -m http.server -d kafka 8000   ->   http://localhost:8000/

set -euo pipefail

cd "$(dirname "$0")/.."

# --force: Die Altersprüfung nutzt die mtime der Datei, die nach checkout/pull frisch ist
uv run kafka/cves.py download --force

echo "kafka/cves.json aktualisiert"
