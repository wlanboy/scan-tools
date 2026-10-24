#!/usr/bin/env bash
# update.sh - Aktualisiert istio/istio-cves.json für die CVE-Übersicht (istio/index.html)
#
# Usage:
#   istio/update.sh
#
# Anzeige im Browser (fetch() funktioniert nicht über file://):
#   python3 -m http.server -d istio 8000   ->   http://localhost:8000/

set -euo pipefail

cd "$(dirname "$0")/.."

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

uv run istio/istio_release_cves.py --json > "$tmp"
mv "$tmp" istio/istio-cves.json

echo "istio/istio-cves.json aktualisiert"
