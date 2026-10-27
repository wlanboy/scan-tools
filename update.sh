#!/usr/bin/env bash
# update.sh - Aktualisiert alle Daten-Dateien lokal (wie .github/workflows/update.yml, aber ohne Commit/Push)
#
# Usage:
#   ./update.sh
#
# Aktualisiert:
#   spring/advisories.json
#   kev/known_exploited_vulnerabilities.json
#   nodejs/vulnerabilities.json
#   istio/istio-cves.json
#   kafka/cves.json
#   hadoop/cves.json
#   cve/cve-counts.json

set -euo pipefail

cd "$(dirname "$0")"

files=(spring/advisories.json kev/known_exploited_vulnerabilities.json nodejs/vulnerabilities.json istio/istio-cves.json kafka/cves.json hadoop/cves.json cve/cve-counts.json)

# --force: Die Altersprüfung nutzt die mtime der Datei, die nach checkout/pull frisch ist
echo "==> Spring Advisories"
uv run spring/advisories.py download --force

echo "==> KEV-Katalog"
uv run kev/catalog.py download --force

echo "==> Node.js-Schwachstellen"
uv run nodejs/vulnerabilities.py download --force

echo "==> Istio CVEs"
istio/update.sh

echo "==> Kafka CVEs"
kafka/update.sh

echo "==> Hadoop CVEs"
hadoop/update.sh

echo "==> CVEs pro Tag (NVD)"
cve/update.sh

echo
if git diff --quiet -- "${files[@]}"; then
    echo "Keine Änderungen."
else
    git diff --stat -- "${files[@]}"
fi
