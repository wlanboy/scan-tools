#!/usr/bin/env bash
# update.sh - Aktualisiert litellm/vulnerabilities.json für die Übersicht (litellm/index.html)
#
# Usage:
#   litellm/update.sh
#
# Anzeige im Browser (fetch() funktioniert nicht über file://):
#   python3 -m http.server -d litellm 8000   ->   http://localhost:8000/

set -euo pipefail

cd "$(dirname "$0")/.."

# --force: Die Altersprüfung nutzt die mtime der Datei, die nach checkout/pull frisch ist
uv run litellm/vulnerabilities.py download --force

echo "litellm/vulnerabilities.json aktualisiert"
