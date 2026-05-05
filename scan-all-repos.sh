#!/usr/bin/env bash
# scan-all-repos.sh - Run a scanner script against every git repo in a directory
#
# Usage:
#   ./scan-all-repos.sh <scanner.py> <repos-root-dir> [output.txt] [-- extra scanner args...]
#
# Examples:
#   ./scan-all-repos.sh scan-secrets.py ~/projects results.txt
#   ./scan-all-repos.sh scan-npm.py ~/projects results.txt -- --min-severity HIGH
#   ./scan-all-repos.sh scan-secrets.py ~/projects          # output: scan-results-YYYYMMDD.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

usage() {
    echo "Usage: $0 <scanner.py> <repos-root-dir> [output.txt] [-- extra scanner args...]"
    echo ""
    echo "  scanner.py       One of: scan-secrets.py, scan-npm.py, scan-proxy.py, scan-external-urls.py"
    echo "  repos-root-dir   Directory containing git repositories (searched one level deep)"
    echo "  output.txt       Output file (default: scan-results-YYYYMMDD-HHMMSS.txt)"
    echo "  -- ...           Any additional arguments are forwarded to the scanner"
    exit 1
}

[[ $# -lt 2 ]] && usage

SCANNER="$1"
REPOS_ROOT="$2"
shift 2

# Resolve scanner to absolute path (accept bare name or full path)
if [[ ! -f "$SCANNER" ]]; then
    SCANNER="$SCRIPT_DIR/$SCANNER"
fi
if [[ ! -f "$SCANNER" ]]; then
    echo "ERROR: Scanner not found: $1" >&2
    exit 2
fi

# Optional output file (next arg if it doesn't start with -)
OUTPUT_FILE=""
if [[ $# -gt 0 && "$1" != "--" && "$1" != -* ]]; then
    OUTPUT_FILE="$1"
    shift
fi
[[ -z "$OUTPUT_FILE" ]] && OUTPUT_FILE="scan-results-$(date +%Y%m%d-%H%M%S).txt"

# Strip leading -- separator for extra scanner args
if [[ $# -gt 0 && "$1" == "--" ]]; then
    shift
fi
EXTRA_ARGS=("$@")

# Verify repos root exists
if [[ ! -d "$REPOS_ROOT" ]]; then
    echo "ERROR: Directory not found: $REPOS_ROOT" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Discover git repositories (one level deep)
# ---------------------------------------------------------------------------

mapfile -t REPOS < <(
    find "$REPOS_ROOT" -mindepth 1 -maxdepth 2 -name ".git" -type d \
        | sed 's|/.git$||' \
        | sort
)

if [[ ${#REPOS[@]} -eq 0 ]]; then
    echo "No git repositories found under: $REPOS_ROOT"
    exit 0
fi

echo "Found ${#REPOS[@]} repositories. Scanner: $(basename "$SCANNER")"
echo "Output: $OUTPUT_FILE"
echo ""

# ---------------------------------------------------------------------------
# Run scanner against each repo and collect output
# ---------------------------------------------------------------------------

PYTHON="${PYTHON:-python3}"
FINDINGS=0
ERRORS=0
START_TIME=$(date +%s)

{
    echo "========================================================================"
    echo "  Scan report"
    echo "  Scanner : $(basename "$SCANNER")"
    echo "  Root    : $REPOS_ROOT"
    echo "  Date    : $(date)"
    echo "  Repos   : ${#REPOS[@]}"
    [[ ${#EXTRA_ARGS[@]} -gt 0 ]] && echo "  Args    : ${EXTRA_ARGS[*]}"
    echo "========================================================================"
    echo ""
} > "$OUTPUT_FILE"

for REPO in "${REPOS[@]}"; do
    REPO_NAME="$(basename "$REPO")"
    printf "Scanning %-50s ... " "$REPO_NAME"

    {
        echo "------------------------------------------------------------------------"
        echo "Repository: $REPO_NAME"
        echo "Path      : $REPO"
        echo "------------------------------------------------------------------------"
    } >> "$OUTPUT_FILE"

    # Run scanner; capture stdout+stderr; --no-fail so script doesn't abort on findings
    SCAN_OUTPUT=$("$PYTHON" "$SCANNER" "$REPO" --no-fail "${EXTRA_ARGS[@]}" 2>&1) || true
    EXIT_CODE=$?

    echo "$SCAN_OUTPUT" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

    if [[ $EXIT_CODE -eq 0 ]]; then
        echo "ok"
    elif [[ $EXIT_CODE -eq 1 ]]; then
        echo "FINDINGS"
        FINDINGS=$((FINDINGS + 1))
    else
        echo "ERROR (exit $EXIT_CODE)"
        ERRORS=$((ERRORS + 1))
    fi
done

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

{
    echo "========================================================================"
    echo "  Summary"
    echo "  Repos scanned : ${#REPOS[@]}"
    echo "  With findings : $FINDINGS"
    echo "  Errors        : $ERRORS"
    echo "  Duration      : ${ELAPSED}s"
    echo "========================================================================"
} >> "$OUTPUT_FILE"

echo ""
echo "Done in ${ELAPSED}s — repos: ${#REPOS[@]}, with findings: $FINDINGS, errors: $ERRORS"
echo "Results written to: $OUTPUT_FILE"
