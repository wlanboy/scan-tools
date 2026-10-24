#!/usr/bin/env bash
# scan-all-repos.sh - Run a scanner script against every git repo in a directory
#
# Usage:
#   ./scan-all-repos.sh <scanner.py> <repos-root-dir> [output.txt] [--whitelist FILE] [-- extra scanner args...]
#
# Examples:
#   ./scan-all-repos.sh scan-secrets.py ~/projects results.txt
#   ./scan-all-repos.sh scan-secrets.py ~/projects results.txt --whitelist secrets-whitelist.json
#   ./scan-all-repos.sh scan-external-urls.py ~/projects --whitelist whitelist.json -- --skip-tests
#   ./scan-all-repos.sh scan-npm.py ~/projects results.txt -- --min-severity HIGH
#   ./scan-all-repos.sh scan-external-urls.py ~/projects results.txt -- --format sarif   # one file per repo in results-sarif/
#   ./scan-all-repos.sh scan-secrets.py ~/projects          # output: scan-results-YYYYMMDD-HHMMSS.txt
#
# Exit codes: 0 = no findings, 1 = at least one repo with findings, 2 = at least one scanner error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

usage() {
    echo "Usage: $0 <scanner.py> <repos-root-dir> [output.txt] [--whitelist FILE] [-- extra scanner args...]"
    echo ""
    echo "  scanner.py       One of: scan-secrets.py, scan-npm.py, scan-external-urls.py"
    echo "  repos-root-dir   Directory containing git repositories (searched one level deep)"
    echo "  output.txt       Output file (default: scan-results-YYYYMMDD-HHMMSS.txt)"
    echo "  --whitelist FILE JSON whitelist forwarded to every scanner invocation"
    echo "                   (scan-secrets.py and scan-external-urls.py only)"
    echo "  -- ...           Any additional arguments are forwarded to the scanner."
    echo "                   With --format json|sarif each repo gets its own result file"
    echo "                   in <output>-<format>/, the output file keeps the summary."
    echo ""
    echo "Exit codes: 0 = no findings, 1 = findings, 2 = scanner error"
    exit 2
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

SCANNER_NAME="$(basename "$SCANNER")"
SUPPORTS_WHITELIST=0
case "$SCANNER_NAME" in
    scan-proxy.py)
        # Inspects the local host (env, /etc, docker, systemd), not a repository
        echo "ERROR: $SCANNER_NAME scans the local host, not a repository — run it directly" >&2
        exit 2
        ;;
    scan-secrets.py|scan-external-urls.py)
        SUPPORTS_WHITELIST=1
        ;;
esac

# Parse optional arguments before the -- separator
OUTPUT_FILE=""
WHITELIST_FILE=""

while [[ $# -gt 0 && "$1" != "--" ]]; do
    case "$1" in
        --whitelist)
            [[ $# -lt 2 ]] && { echo "ERROR: --whitelist requires a FILE argument" >&2; exit 2; }
            WHITELIST_FILE="$2"
            shift 2
            ;;
        -*)
            break  # Unknown flag — stop, treat remainder as EXTRA_ARGS
            ;;
        *)
            # First bare positional is the output file
            if [[ -z "$OUTPUT_FILE" ]]; then
                OUTPUT_FILE="$1"
                shift
            else
                break
            fi
            ;;
    esac
done
[[ -z "$OUTPUT_FILE" ]] && OUTPUT_FILE="scan-results-$(date +%Y%m%d-%H%M%S).txt"

# Validate and resolve whitelist path to absolute so it works from any repo dir
if [[ -n "$WHITELIST_FILE" ]]; then
    if [[ $SUPPORTS_WHITELIST -eq 0 ]]; then
        echo "ERROR: $SCANNER_NAME does not support --whitelist" >&2
        exit 2
    fi
    if [[ ! -f "$WHITELIST_FILE" ]]; then
        echo "ERROR: Whitelist file not found: $WHITELIST_FILE" >&2
        exit 2
    fi
    WHITELIST_FILE="$(realpath "$WHITELIST_FILE")"
fi

# Strip leading -- separator for extra scanner args
[[ $# -gt 0 && "$1" == "--" ]] && shift
EXTRA_ARGS=("$@")

# Machine-readable formats cannot be concatenated into one report, so each repo
# writes its own file into RESULT_DIR and the report only keeps the summary.
FORMAT="text"
for ((i = 0; i < ${#EXTRA_ARGS[@]}; i++)); do
    case "${EXTRA_ARGS[i]}" in
        --format)   FORMAT="${EXTRA_ARGS[i+1]:-text}" ;;
        --format=*) FORMAT="${EXTRA_ARGS[i]#--format=}" ;;
    esac
done
RESULT_DIR=""
if [[ "$FORMAT" != "text" ]]; then
    RESULT_DIR="${OUTPUT_FILE%.txt}-$FORMAT"
    mkdir -p "$RESULT_DIR"
fi

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

echo "Found ${#REPOS[@]} repositories. Scanner: $SCANNER_NAME"
echo "Output: $OUTPUT_FILE"
[[ -n "$RESULT_DIR" ]] && echo "Results: $RESULT_DIR/"
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
    echo "  Scanner : $SCANNER_NAME"
    echo "  Root    : $REPOS_ROOT"
    echo "  Date    : $(date)"
    echo "  Repos   : ${#REPOS[@]}"
    [[ -n "$WHITELIST_FILE" ]]      && echo "  Whitelist: $WHITELIST_FILE"
    [[ ${#EXTRA_ARGS[@]} -gt 0 ]]   && echo "  Args    : ${EXTRA_ARGS[*]}"
    [[ -n "$RESULT_DIR" ]]          && echo "  Results : $RESULT_DIR/"
    echo "========================================================================"
    echo ""
} > "$OUTPUT_FILE"

for REPO in "${REPOS[@]}"; do
    REPO_NAME="$(basename "$REPO")"
    printf "Scanning %-50s ... " "$REPO_NAME"

    REPO_RESULT=""
    [[ -n "$RESULT_DIR" ]] && REPO_RESULT="$RESULT_DIR/$REPO_NAME.$FORMAT"

    {
        echo "------------------------------------------------------------------------"
        echo "Repository: $REPO_NAME"
        echo "Path      : $REPO"
        [[ -n "$REPO_RESULT" ]] && echo "Result    : $REPO_RESULT"
        echo "------------------------------------------------------------------------"
    } >> "$OUTPUT_FILE"

    # Build whitelist args (empty array if no whitelist was specified)
    WHITELIST_ARGS=()
    [[ -n "$WHITELIST_FILE" ]] && WHITELIST_ARGS=("--whitelist" "$WHITELIST_FILE")

    # Run scanner; || EXIT_CODE=$? prevents set -e from aborting
    EXIT_CODE=0
    if [[ -n "$REPO_RESULT" ]]; then
        # stdout is the machine-readable result, stderr goes to the report
        "$PYTHON" "$SCANNER" "$REPO" "${WHITELIST_ARGS[@]}" "${EXTRA_ARGS[@]}" \
            > "$REPO_RESULT" 2>> "$OUTPUT_FILE" || EXIT_CODE=$?
    else
        SCAN_OUTPUT=$("$PYTHON" "$SCANNER" "$REPO" "${WHITELIST_ARGS[@]}" "${EXTRA_ARGS[@]}" 2>&1) || EXIT_CODE=$?
        echo "$SCAN_OUTPUT" >> "$OUTPUT_FILE"
    fi
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
[[ -n "$RESULT_DIR" ]] && echo "Per-repo results in: $RESULT_DIR/"

[[ $ERRORS -gt 0 ]] && exit 2
[[ $FINDINGS -gt 0 ]] && exit 1
exit 0
