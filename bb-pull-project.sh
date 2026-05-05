#!/usr/bin/env bash
# bb-pull-project.sh
# Clone or git-pull all repositories from a single Bitbucket project/workspace.
#
# Usage (Bitbucket Server / Data Center):
#   BB_URL=https://bitbucket.example.com \
#   BB_USER=myuser \
#   BB_TOKEN=mytoken \
#   BB_PROJECT=MYPROJECT \
#   TARGET_DIR=/opt/repos \
#   ./bb-pull-project.sh
#
# Usage (Bitbucket Cloud):
#   BB_CLOUD=1 \
#   BB_USER=myuser \
#   BB_TOKEN=myapppassword \
#   BB_PROJECT=myworkspace \
#   TARGET_DIR=/opt/repos \
#   ./bb-pull-project.sh
#
# Required env vars:
#   BB_USER      Bitbucket username (or service account)
#   BB_TOKEN     Personal access token or app password
#   BB_PROJECT   Project key (Server) or workspace slug (Cloud)
#
# Optional env vars:
#   BB_URL       Base URL for Bitbucket Server (default: https://bitbucket.example.com)
#   BB_CLOUD     Set to 1 to use Bitbucket Cloud API
#   TARGET_DIR   Directory where repos are cloned (default: ./repos)
#   PARALLEL     Number of parallel git operations (default: 4)

set -euo pipefail

BB_URL="${BB_URL:-https://bitbucket.example.com}"
BB_CLOUD="${BB_CLOUD:-0}"
BB_USER="${BB_USER:?BB_USER is required}"
BB_TOKEN="${BB_TOKEN:?BB_TOKEN is required}"
BB_PROJECT="${BB_PROJECT:?BB_PROJECT is required}"
TARGET_DIR="${TARGET_DIR:-./repos}"
PARALLEL="${PARALLEL:-4}"

mkdir -p "$TARGET_DIR"

# ── Helpers ──────────────────────────────────────────────────────────────────

log()  { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
err()  { printf '[%s] ERROR: %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }

bb_curl() {
    curl -fsSL -u "${BB_USER}:${BB_TOKEN}" "$@"
}

# ── Collect repo clone URLs ───────────────────────────────────────────────────

declare -a CLONE_URLS=()

if [[ "$BB_CLOUD" == "1" ]]; then
    # Bitbucket Cloud: paginate through /2.0/repositories/<workspace>
    NEXT="https://api.bitbucket.org/2.0/repositories/${BB_PROJECT}?pagelen=100"
    while [[ -n "$NEXT" ]]; do
        RESPONSE=$(bb_curl "$NEXT")
        # Extract SSH clone URLs (fall back to HTTPS if ssh entry missing)
        while IFS= read -r url; do
            [[ -n "$url" ]] && CLONE_URLS+=("$url")
        done < <(printf '%s' "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('values', []):
    links = r.get('links', {}).get('clone', [])
    ssh = next((l['href'] for l in links if l['name'] == 'ssh'), None)
    https = next((l['href'] for l in links if l['name'] == 'https'), None)
    print(ssh or https or '')
")
        NEXT=$(printf '%s' "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('next', ''))
" 2>/dev/null || true)
    done
else
    # Bitbucket Server/Data Center: paginate through /rest/api/1.0/projects/<key>/repos
    START=0
    LIMIT=100
    while :; do
        RESPONSE=$(bb_curl "${BB_URL}/rest/api/1.0/projects/${BB_PROJECT}/repos?start=${START}&limit=${LIMIT}")
        while IFS= read -r url; do
            [[ -n "$url" ]] && CLONE_URLS+=("$url")
        done < <(printf '%s' "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('values', []):
    links = r.get('links', {}).get('clone', [])
    ssh = next((l['href'] for l in links if l['name'] == 'ssh'), None)
    https = next((l['href'] for l in links if l['name'] == 'http'), None)
    print(ssh or https or '')
")
        IS_LAST=$(printf '%s' "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print('true' if data.get('isLastPage', True) else 'false')
" 2>/dev/null || echo 'true')
        [[ "$IS_LAST" == "true" ]] && break
        NEXT_START=$(printf '%s' "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('nextPageStart', 0))
" 2>/dev/null || echo 0)
        START="$NEXT_START"
    done
fi

TOTAL="${#CLONE_URLS[@]}"
if [[ "$TOTAL" -eq 0 ]]; then
    err "No repositories found for project '${BB_PROJECT}'. Check credentials and project key."
    exit 1
fi
log "Found ${TOTAL} repositories in project '${BB_PROJECT}'"

# ── Clone or pull each repo ───────────────────────────────────────────────────

clone_or_pull() {
    local url="$1"
    # Derive folder name from the last path segment, strip .git suffix
    local name
    name=$(basename "$url" .git)
    local dest="${TARGET_DIR}/${name}"

    if [[ -d "${dest}/.git" ]]; then
        log "  pull  ${name}"
        git -C "$dest" pull --ff-only --quiet 2>&1 | sed "s/^/         /"
    else
        log "  clone ${name}"
        git clone --quiet "$url" "$dest" 2>&1 | sed "s/^/         /"
    fi
}

export -f clone_or_pull log
export TARGET_DIR

# xargs-based parallelism; fall back to sequential if xargs -P unavailable
if printf '%s\n' "${CLONE_URLS[@]}" | \
       xargs -P "${PARALLEL}" -I{} bash -c 'clone_or_pull "$@"' _ {}; then
    log "Done. All ${TOTAL} repositories are up to date in '${TARGET_DIR}'."
else
    err "One or more git operations failed."
    exit 1
fi
