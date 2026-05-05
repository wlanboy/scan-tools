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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BB_PARSE="${SCRIPT_DIR}/bb_parse.py"

# ── Helpers ──────────────────────────────────────────────────────────────────

log()  { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
err()  { printf '[%s] ERROR: %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
step() { printf '[%s] ── %s\n' "$(date '+%H:%M:%S')" "$*"; }

bb_curl() {
    curl -fsSL -u "${BB_USER}:${BB_TOKEN}" "$@"
}

bb_parse() {
    python3 "$BB_PARSE" "$@"
}

# ── Preflight ─────────────────────────────────────────────────────────────────

step "Preflight checks"
log "  Python helper : ${BB_PARSE}"
if [[ ! -f "$BB_PARSE" ]]; then
    err "bb_parse.py not found at '${BB_PARSE}'"
    exit 1
fi
log "  Target dir    : ${TARGET_DIR}"
log "  Project       : ${BB_PROJECT}"
log "  Mode          : $( [[ "$BB_CLOUD" == "1" ]] && echo 'Bitbucket Cloud' || echo "Bitbucket Server (${BB_URL})" )"
log "  Parallelism   : ${PARALLEL}"
mkdir -p "$TARGET_DIR"
log "  Target dir created / confirmed"

# ── Collect repo clone URLs ───────────────────────────────────────────────────

step "Collecting repository list from Bitbucket API"
declare -a CLONE_URLS=()

if [[ "$BB_CLOUD" == "1" ]]; then
    PAGE=1
    NEXT="https://api.bitbucket.org/2.0/repositories/${BB_PROJECT}?pagelen=100"
    while [[ -n "$NEXT" ]]; do
        log "  Fetching Cloud page ${PAGE}: ${NEXT}"
        RESPONSE=$(bb_curl "$NEXT")

        while IFS= read -r url; do
            [[ -n "$url" ]] && CLONE_URLS+=("$url")
        done < <(printf '%s' "$RESPONSE" | bb_parse cloud-urls)

        log "  Page ${PAGE}: $(printf '%s' "$RESPONSE" | bb_parse cloud-urls | grep -c . || echo 0) repos collected (total so far: ${#CLONE_URLS[@]})"

        NEXT=$(printf '%s' "$RESPONSE" | bb_parse cloud-next 2>/dev/null || true)
        PAGE=$(( PAGE + 1 ))
    done
else
    START=0
    LIMIT=100
    PAGE=1
    while :; do
        log "  Fetching Server page ${PAGE} (start=${START}, limit=${LIMIT})"
        RESPONSE=$(bb_curl "${BB_URL}/rest/api/1.0/projects/${BB_PROJECT}/repos?start=${START}&limit=${LIMIT}")

        while IFS= read -r url; do
            [[ -n "$url" ]] && CLONE_URLS+=("$url")
        done < <(printf '%s' "$RESPONSE" | bb_parse server-urls)

        log "  Page ${PAGE}: $(printf '%s' "$RESPONSE" | bb_parse server-urls | grep -c . || echo 0) repos collected (total so far: ${#CLONE_URLS[@]})"

        IS_LAST=$(printf '%s' "$RESPONSE" | bb_parse server-islast 2>/dev/null || echo 'true')
        [[ "$IS_LAST" == "true" ]] && break

        START=$(printf '%s' "$RESPONSE" | bb_parse server-nextstart 2>/dev/null || echo 0)
        PAGE=$(( PAGE + 1 ))
    done
fi

TOTAL="${#CLONE_URLS[@]}"
if [[ "$TOTAL" -eq 0 ]]; then
    err "No repositories found for project '${BB_PROJECT}'. Check credentials and project key."
    exit 1
fi
log "Found ${TOTAL} repositories in project '${BB_PROJECT}'"

# ── Clone or pull each repo ───────────────────────────────────────────────────

step "Starting clone / pull (parallelism: ${PARALLEL})"

clone_or_pull() {
    local url="$1"
    local name
    name=$(basename "$url" .git)
    local dest="${TARGET_DIR}/${name}"

    if [[ -d "${dest}/.git" ]]; then
        printf '[%s]   pull  %s\n' "$(date '+%H:%M:%S')" "$name"
        git -C "$dest" pull --ff-only --quiet 2>&1 | sed "s/^/         /"
        printf '[%s]   pull  %s  done\n' "$(date '+%H:%M:%S')" "$name"
    else
        printf '[%s]   clone %s\n' "$(date '+%H:%M:%S')" "$name"
        git clone --quiet "$url" "$dest" 2>&1 | sed "s/^/         /"
        printf '[%s]   clone %s  done\n' "$(date '+%H:%M:%S')" "$name"
    fi
}

export -f clone_or_pull
export TARGET_DIR

if printf '%s\n' "${CLONE_URLS[@]}" | \
       xargs -P "${PARALLEL}" -I{} bash -c 'clone_or_pull "$@"' _ {}; then
    step "Finished"
    log "All ${TOTAL} repositories are up to date in '${TARGET_DIR}'."
else
    err "One or more git operations failed."
    exit 1
fi
