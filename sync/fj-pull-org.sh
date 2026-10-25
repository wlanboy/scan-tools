#!/usr/bin/env bash
# fj-pull-org.sh
# Clone or git-pull all repositories of a single Forgejo organization or user.
#
# Usage (organization):
#   FJ_URL=https://forgejo.example.com \
#   FJ_USER=myuser \
#   FJ_TOKEN=mytoken \
#   FJ_OWNER=myorg \
#   TARGET_DIR=/opt/repos \
#   ./fj-pull-org.sh
#
# Usage (user, e.g. on Codeberg):
#   FJ_URL=https://codeberg.org \
#   FJ_USER=myuser \
#   FJ_TOKEN=mytoken \
#   FJ_OWNER=myuser \
#   FJ_OWNER_TYPE=user \
#   TARGET_DIR=/opt/repos \
#   ./fj-pull-org.sh
#
# Required env vars:
#   FJ_USER        Forgejo username (or service account), used for git clone/pull
#   FJ_TOKEN       Access token (scopes: read:organization, read:repository)
#   FJ_OWNER       Organization name or username whose repositories are pulled
#
# Optional env vars:
#   FJ_URL         Base URL of the Forgejo instance (default: https://forgejo.example.com)
#   FJ_OWNER_TYPE  "org" or "user" (default: org)
#   TARGET_DIR     Directory where repos are cloned (default: ./repos)
#   PARALLEL       Number of parallel git operations (default: 4)

set -euo pipefail

FJ_URL="${FJ_URL:-https://forgejo.example.com}"
FJ_URL="${FJ_URL%/}"
FJ_USER="${FJ_USER:?FJ_USER is required}"
FJ_TOKEN="${FJ_TOKEN:?FJ_TOKEN is required}"
FJ_OWNER="${FJ_OWNER:?FJ_OWNER is required}"
FJ_OWNER_TYPE="${FJ_OWNER_TYPE:-org}"
TARGET_DIR="${TARGET_DIR:-./repos}"
PARALLEL="${PARALLEL:-4}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FJ_PARSE="${SCRIPT_DIR}/fj_parse.py"

# ── Helpers ──────────────────────────────────────────────────────────────────

log()  { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
err()  { printf '[%s] ERROR: %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
step() { printf '[%s] ── %s\n' "$(date '+%H:%M:%S')" "$*"; }

fj_curl() {
    # Token via header read from stdin, so it stays out of the process list
    printf 'Authorization: token %s\n' "$FJ_TOKEN" | curl -fsSL -H @- "$@"
}

fj_parse() {
    python3 "$FJ_PARSE" "$@"
}

# ── Preflight ─────────────────────────────────────────────────────────────────

step "Preflight checks"
log "  Python helper : ${FJ_PARSE}"
if [[ ! -f "$FJ_PARSE" ]]; then
    err "fj_parse.py not found at '${FJ_PARSE}'"
    exit 1
fi
case "$FJ_OWNER_TYPE" in
    org)  API_BASE="${FJ_URL}/api/v1/orgs/${FJ_OWNER}/repos" ;;
    user) API_BASE="${FJ_URL}/api/v1/users/${FJ_OWNER}/repos" ;;
    *)    err "FJ_OWNER_TYPE must be 'org' or 'user', got '${FJ_OWNER_TYPE}'"; exit 1 ;;
esac
log "  Target dir    : ${TARGET_DIR}"
log "  Owner         : ${FJ_OWNER} (${FJ_OWNER_TYPE})"
log "  Instance      : ${FJ_URL}"
log "  Parallelism   : ${PARALLEL}"
mkdir -p "$TARGET_DIR"
log "  Target dir created / confirmed"

# ── Collect repo clone URLs ───────────────────────────────────────────────────
# Forgejo caps the page size at [api] MAX_RESPONSE_ITEMS (default 50), so a
# short page is no reliable end marker. Stop at the first empty page instead.

step "Collecting repository list from Forgejo API"
declare -a CLONE_URLS=()

LIMIT=50
PAGE=1
while :; do
    API_URL="${API_BASE}?page=${PAGE}&limit=${LIMIT}"
    log "  Fetching page ${PAGE}: ${API_URL}"
    RESPONSE=$(fj_curl "$API_URL") || { err "API request failed (curl exit $?): ${API_URL}"; exit 1; }

    COUNT=$(printf '%s' "$RESPONSE" | fj_parse count) || { err "Could not parse API response: ${API_URL}"; exit 1; }
    [[ "$COUNT" -eq 0 ]] && break

    while IFS= read -r url; do
        [[ -n "$url" ]] && CLONE_URLS+=("$url")
    done < <(printf '%s' "$RESPONSE" | fj_parse urls)

    log "  Page ${PAGE}: ${COUNT} repos collected (total so far: ${#CLONE_URLS[@]})"
    PAGE=$(( PAGE + 1 ))
done

TOTAL="${#CLONE_URLS[@]}"
if [[ "$TOTAL" -eq 0 ]]; then
    err "No repositories found for ${FJ_OWNER_TYPE} '${FJ_OWNER}'. Check credentials and owner name."
    exit 1
fi
log "Found ${TOTAL} repositories for ${FJ_OWNER_TYPE} '${FJ_OWNER}'"

# ── Git authentication ────────────────────────────────────────────────────────
# Hand the credentials to git via environment-only config (git >= 2.31), so the
# token stays out of the process list and .git/config. Never prompt: a prompt
# inside the parallel xargs workers would hang the run.

GIT_HOST="${FJ_URL}/"
export GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0="http.${GIT_HOST}.extraHeader"
export GIT_CONFIG_VALUE_0="Authorization: Basic $(printf '%s:%s' "$FJ_USER" "$FJ_TOKEN" | base64 | tr -d '\n')"
log "Git auth: user '${FJ_USER}' for ${GIT_HOST}"

# ── Clone or pull each repo ───────────────────────────────────────────────────

step "Starting clone / pull (parallelism: ${PARALLEL})"

clone_or_pull() {
    local url="$1"
    local name
    name=$(basename "$url" .git)
    local dest="${TARGET_DIR}/${name}"
    local rc head

    if [[ -d "${dest}/.git" ]] && ! git -C "$dest" rev-parse -q --verify HEAD >/dev/null; then
        # Clone of an empty repository: no branch to pull yet, check one out
        # as soon as the remote has content.
        printf '[%s]   fetch %s  (empty clone)\n' "$(date '+%H:%M:%S')" "$name"
        git -C "$dest" fetch --quiet origin 2>&1 | sed "s/^/         /"
        rc="${PIPESTATUS[0]}"
        if [[ "$rc" -ne 0 ]]; then
            printf '[%s]   fetch %s  FAILED (git exit %s)\n' "$(date '+%H:%M:%S')" "$name" "$rc" >&2
            return 1
        fi
        if ! git -C "$dest" remote set-head origin --auto >/dev/null 2>&1; then
            printf '[%s]   fetch %s  done (still empty)\n' "$(date '+%H:%M:%S')" "$name"
            return 0
        fi
        head=$(git -C "$dest" symbolic-ref --short refs/remotes/origin/HEAD)
        git -C "$dest" checkout --quiet -B "${head#origin/}" --track "$head" 2>&1 | sed "s/^/         /"
        rc="${PIPESTATUS[0]}"
        if [[ "$rc" -ne 0 ]]; then
            printf '[%s]   fetch %s  FAILED (git exit %s)\n' "$(date '+%H:%M:%S')" "$name" "$rc" >&2
            return 1
        fi
        printf '[%s]   fetch %s  done (checked out %s)\n' "$(date '+%H:%M:%S')" "$name" "$head"
    elif [[ -d "${dest}/.git" ]]; then
        printf '[%s]   pull  %s\n' "$(date '+%H:%M:%S')" "$name"
        git -C "$dest" pull --ff-only --quiet 2>&1 | sed "s/^/         /"
        rc="${PIPESTATUS[0]}"
        if [[ "$rc" -ne 0 ]]; then
            printf '[%s]   pull  %s  FAILED (git exit %s)\n' "$(date '+%H:%M:%S')" "$name" "$rc" >&2
            return 1
        fi
        printf '[%s]   pull  %s  done\n' "$(date '+%H:%M:%S')" "$name"
    else
        printf '[%s]   clone %s\n' "$(date '+%H:%M:%S')" "$name"
        git clone --quiet "$url" "$dest" 2>&1 | sed "s/^/         /"
        rc="${PIPESTATUS[0]}"
        if [[ "$rc" -ne 0 ]]; then
            printf '[%s]   clone %s  FAILED (git exit %s)\n' "$(date '+%H:%M:%S')" "$name" "$rc" >&2
            return 1
        fi
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
