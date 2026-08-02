#!/usr/bin/env python
"""
scan-secrets.py - Scans a git repository for credentials and secrets:
  Basic Auth (URL and header), Bearer tokens, OAuth tokens/secrets,
  API keys, private keys, JWT tokens and generic passwords.

Exit codes:
  0 - No findings (or --no-fail set)
  1 - Findings detected
  2 - Script error (invalid arguments, not a git repo, etc.)

"""

import argparse
import json
import os
import re
import subprocess
import sys

# ---------------------------------------------------------------------------
# Placeholder / false-positive guard
# ---------------------------------------------------------------------------

# Whole-value templates: the *entire* value is masking/interpolation syntax.
_PLACEHOLDER_WHOLE_RE = re.compile(
    r'^(?:'
    r'\*+|x{3,}|0{4,}|\.{3,}|\?+|_{4,}'           # masking chars
    r'|<[^>]+>'                                      # <TOKEN>, <your-key>
    r'|\$\{[^}]+\}'                                 # ${TOKEN}
    r'|\$[A-Za-z_][A-Za-z0-9_]{2,}'                  # $API_KEY, $api_key (env var ref)
    r'|\{\{[^}]+\}\}'                               # {{token}} (template)
    r'|%\([^)]+\)'                                   # %(key)s (Python format)
    r')$',
    re.IGNORECASE,
)

# Placeholder wording that can appear anywhere in the value, e.g.
# "your-api-key-here" or "REPLACE_WITH_YOUR_TOKEN".
_PLACEHOLDER_WORD_RE = re.compile(
    r'your[-_ ]|to.?do|change.?me|example|placeholder|fake|dummy'
    r'|\btest\b|\bsample\b|\binsert\b|n/?a\b|\bundefined\b|\bnull\b|\bnone\b'
    r'|\bempty\b|\bmissing\b|replace|edit.?this'
    r'|\bpassword\b|\bpasswd\b|\bsecret\b|\btoken\b|\bapikey\b|\bapi.?key\b',  # bare field names
    re.IGNORECASE,
)


def is_placeholder(value):
    """Return True if value looks like a template/placeholder, not a real secret."""
    if not value or len(value.strip()) < 4:
        return True
    v = value.strip()
    if _PLACEHOLDER_WHOLE_RE.match(v) or _PLACEHOLDER_WORD_RE.search(v):
        return True
    # All same character repeated (e.g. "aaaaaaaaaa", "11111111")
    return len(set(v)) == 1


# ---------------------------------------------------------------------------
# Credential patterns
# Each entry: (category, human_label, compiled_regex)
# Group 1 (if present) captures the secret value used for placeholder checks.
# ---------------------------------------------------------------------------

PATTERNS = [
    (
        'private_key',
        'Private Key',
        re.compile(
            r'-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+|ENCRYPTED\s+)?'
            r'PRIVATE\s+KEY(?:\s+BLOCK)?-----',
        ),
    ),
    (
        'jwt_token',
        'JWT Token',
        re.compile(
            r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{20,}'
        ),
    ),
    (
        'basic_auth_url',
        'Basic Auth in URL',
        re.compile(
            r'https?://([^@\s\'"<>()\[\]{}\\,;/]+)'
            r':([^@\s\'"<>()\[\]{}\\,;/]{3,})'
            r'@[a-zA-Z0-9.\-]+(:\d+)?'
        ),
    ),
    (
        'basic_auth_header',
        'Basic Auth Header',
        re.compile(
            r'(?:Authorization|authorization)\s*[=:]\s*["\']?\s*'
            r'Basic\s+([A-Za-z0-9+/]{8,}={0,2})',
            re.IGNORECASE,
        ),
    ),
    (
        'bearer_token',
        'Bearer Token',
        re.compile(
            r'(?:Authorization|authorization)\s*[=:]\s*["\']?\s*'
            r'Bearer\s+([A-Za-z0-9\-._~+/]{20,})',
            re.IGNORECASE,
        ),
    ),
    (
        'oauth_token',
        'OAuth Token',
        re.compile(
            r'(?:oauth_token|access_token|oauth_access_token|'
            r'refresh_token|id_token)\s*[=:]\s*["\']?([^\s"\'#\[\]{},]{10,})["\']?',
            re.IGNORECASE,
        ),
    ),
    (
        'oauth_secret',
        'OAuth Secret',
        re.compile(
            r'(?:client_secret|clientSecret|oauth_secret|consumer_secret|'
            r'app_secret|api_secret|token_secret)\s*[=:]\s*["\']?([^\s"\'#\[\]{},]{8,})["\']?',
            re.IGNORECASE,
        ),
    ),
    (
        'password',
        'Password',
        re.compile(
            r'(?<![a-zA-Z_])(?:password|passwd|pwd)'
            r'\s*[=:]\s*["\']?([^\s"\'#\[\]{},]{4,})["\']?',
            re.IGNORECASE,
        ),
    ),
    (
        'generic_secret',
        'Generic Secret / Token',
        re.compile(
            r'(?<![a-zA-Z_])(?:secret|secret_key|credential|auth_key|'
            r'auth_token|session_key|signing_key|encryption_key|hmac_key)'
            r'\s*[=:]\s*["\']?([^\s"\'#\[\]{},]{8,})["\']?',
            re.IGNORECASE,
        ),
    ),
    (
        'api_key',
        'API Key',
        re.compile(
            r'(?<![a-zA-Z_])(?:api[_.\-]?key|apikey)'
            r'\s*[=:]\s*["\']?([A-Za-z0-9\-._]{16,})["\']?',
            re.IGNORECASE,
        ),
    ),
    (
        'artifactory_token',
        'Artifactory / JFrog Token',
        re.compile(
            # .npmrc / .yarnrc auth token: //registry.example.com/:_authToken=VALUE
            r'(?::_authToken'
            # named variables in env / CI config
            r'|artifactory[_.\-]?(?:api[_.\-]?key|token|password|api[_.\-]?token)'
            r'|ARTIFACTORY[_.\-]?(?:API[_.\-]?KEY|TOKEN|PASSWORD|API[_.\-]?TOKEN)'
            r'|JFROG[_.\-]?(?:TOKEN|API[_.\-]?KEY|PASSWORD)'
            r'|jfrog[_.\-]?(?:token|api[_.\-]?key|password))'
            r'\s*[=:]\s*["\']?([A-Za-z0-9\-._]{20,})["\']?',
            re.IGNORECASE,
        ),
    ),
    (
        'bitbucket_token',
        'Bitbucket / Atlassian Token',
        re.compile(
            # Bitbucket Cloud personal access tokens (ATBB), newer tokens (ATCTT),
            # and Atlassian API tokens (ATATT) all use well-known prefixes, or
            # named variables in env / CI config files
            r'\b(?:ATBB[A-Za-z0-9]{28,}'
            r'|ATCTT[A-Za-z0-9_\-]{50,}'
            r'|ATATT[A-Za-z0-9_\-]{50,})\b'
            r'|(?:bitbucket[_.\-]?(?:token|app[_.\-]?password|api[_.\-]?key'
            r'|access[_.\-]?token|pat)'
            r'|BITBUCKET[_.\-]?(?:TOKEN|APP[_.\-]?PASSWORD|API[_.\-]?KEY'
            r'|ACCESS[_.\-]?TOKEN|PAT))'
            r'\s*[=:]\s*["\']?([A-Za-z0-9\-._]{16,})["\']?',
            re.IGNORECASE,
        ),
    ),
    (
        'github_token',
        'GitHub Token',
        re.compile(
            # gh[pousr]_ = PAT, OAuth, server-to-server, user-to-server, refresh
            r'\b(gh[pousr]_[A-Za-z0-9]{36,})\b',
        ),
    ),
    (
        'aws_access_key',
        'AWS Access Key ID',
        re.compile(
            # AKIA = long-term, ASIA = STS/temporary, ABIA = service account
            r'\b((?:AKIA|ASIA|ABIA)[0-9A-Z]{16})\b',
        ),
    ),
    (
        'aws_secret_key',
        'AWS Secret Access Key',
        re.compile(
            # AWS secret keys have no signature, so only flag them next to a
            # recognizable variable name (base64-alphabet, 40 chars)
            r'(?:aws[_.\-]?secret[_.\-]?access[_.\-]?key|aws[_.\-]?secret[_.\-]?key'
            r'|AWS[_.\-]?SECRET[_.\-]?ACCESS[_.\-]?KEY|AWS[_.\-]?SECRET[_.\-]?KEY)'
            r'\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
            re.IGNORECASE,
        ),
    ),
    (
        'slack_token',
        'Slack Token',
        re.compile(
            r'\b(xox[baprs]-[0-9]{8,13}-[0-9]{8,13}(?:-[0-9]{8,13})?-[A-Za-z0-9]{24,})\b',
        ),
    ),
]

CATEGORY_ORDER = [p[0] for p in PATTERNS]


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

BINARY_CHECK_BYTES = 8192

ALWAYS_SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
    '.webp', '.tiff', '.pdf', '.zip', '.tar', '.gz', '.bz2',
    '.xz', '.7z', '.rar', '.jar', '.war', '.ear', '.class',
    '.pyc', '.pyo', '.so', '.o', '.a', '.dll', '.exe', '.bin',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.avi', '.mov', '.mkv',
    '.lock',
}


def is_binary(path):
    try:
        with open(path, 'rb') as fh:
            return b'\x00' in fh.read(BINARY_CHECK_BYTES)
    except OSError:
        return True


def is_test_file(path):
    lower = path.lower()
    basename = os.path.basename(lower)
    return (
        '/test/' in lower or '/tests/' in lower or '\\test\\' in lower or '\\tests\\' in lower or basename.startswith('test_') or basename.endswith(('_test.py', '_test.go', '.test.ts', '.test.js', '.test.jsx', '.spec.ts', '.spec.js', '.spec.jsx', 'test.java', '_spec.rb'))
    )


def get_extension(path):
    _, ext = os.path.splitext(path)
    return ext.lower()


def matches_any(value, patterns):
    value_lower = value.lower()
    for pat in patterns:
        try:
            if re.search(pat, value_lower, re.IGNORECASE):
                return True
        except re.error:
            if pat.lower() in value_lower:
                return True
    return False


# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------

def get_tracked_files(repo_path):
    cmd = ['git', '-C', repo_path, 'ls-files',
           '--cached', '--others', '--exclude-standard']
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        if isinstance(output, bytes):
            output = output.decode('utf-8', errors='replace')
        return [
            os.path.join(repo_path, f)
            for f in output.splitlines()
            if f.strip()
        ]
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f'git ls-files failed: {exc}')


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan_line(line_text, allow_patterns, categories):
    """Yield (category, label, matched_text) for each finding on this line."""
    for category, label, pattern in PATTERNS:
        if categories is not None and category not in categories:
            continue
        for m in pattern.finditer(line_text):
            matched = m.group(0)
            # basic_auth_url: the password (group 2) is the secret, not the
            # username (group 1) — a placeholder username shouldn't hide a
            # real password.
            if category == 'basic_auth_url' and (m.lastindex or 0) >= 2:
                secret = m.group(2)
            elif m.lastindex and m.lastindex >= 1:
                secret = m.group(1)
            else:
                secret = matched
            if is_placeholder(secret):
                continue
            if matches_any(matched, allow_patterns):
                continue
            yield (category, label, matched)


def scan_file(path, repo_path, allow_patterns, skip_patterns, categories, skip_tests,
              whitelist=None):
    findings = []

    if get_extension(path) in ALWAYS_SKIP_EXTENSIONS:
        return findings

    if skip_tests and is_test_file(path):
        return findings

    rel_path = os.path.relpath(path, repo_path)
    if matches_any(rel_path, skip_patterns):
        return findings

    if is_binary(path):
        return findings

    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
    except OSError:
        return findings

    for line_no, raw_line in enumerate(lines, start=1):
        line_text = raw_line.rstrip('\n\r')
        for category, label, matched in scan_line(line_text, allow_patterns, categories):
            finding = {
                'category': category,
                'label': label,
                'value': matched,
                'file': rel_path,
                'line': line_no,
                'context': line_text.strip()[:120],
            }
            if whitelist and is_whitelisted(finding, whitelist):
                continue
            findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_text_report(findings):
    if not findings:
        print('No secrets found.')
        return

    by_category = {}
    for f in findings:
        by_category.setdefault(f['category'], []).append(f)

    sep = '=' * 70
    print(f'\n{sep}')
    print(f'  Secrets scan -- {len(findings)} finding(s)')
    print(f'{sep}\n')

    printed = set()
    for cat in CATEGORY_ORDER:
        items = by_category.get(cat, [])
        if not items:
            continue
        printed.add(cat)
        print('  {} ({})'.format(items[0]['label'], len(items)))
        print('  {}'.format('-' * 40))
        for f in items:
            print('  {}:{}'.format(f['file'], f['line']))
            print('    Value  : {}'.format(f['value'][:80]))
            print('    Context: {}'.format(f['context']))
            print()

    # Catch any categories not listed in CATEGORY_ORDER
    for cat, items in by_category.items():
        if cat not in printed and items:
            print('  {} ({})'.format(items[0]['label'], len(items)))
            print('  {}'.format('-' * 40))
            for f in items:
                print('  {}:{}'.format(f['file'], f['line']))
                print('    Value  : {}'.format(f['value'][:80]))
                print('    Context: {}'.format(f['context']))
                print()

    files = {f['file'] for f in findings}
    print(f'{sep}')
    print(f'  Total: {len(findings)} finding(s) in {len(files)} file(s)')
    print(f'{sep}\n')


def print_json_report(findings):
    print(json.dumps(findings, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    valid_categories = [cat for cat, _, _ in PATTERNS]
    parser = argparse.ArgumentParser(
        description='Scan a git repository for credentials, tokens, and secrets.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Scan current directory
  python scan-secrets.py

  # Scan specific repo, skip test files
  python scan-secrets.py /path/to/repo --skip-tests

  # Only scan for OAuth secrets and API keys
  python scan-secrets.py --categories oauth_secret api_key

  # JSON output for CI pipelines
  python scan-secrets.py --format json

  # Suppress a known safe pattern
  python scan-secrets.py --allow "example\\.com" "localhost"

  # Use a JSON whitelist
  python scan-secrets.py --whitelist secrets-whitelist.json

JSON whitelist format (array or object with "entries" key):
  [
    {{ "value": "known-ci-token",        "comment": "CI service account, rotated monthly" }},
    {{ "file": "config/example.yml",     "comment": "Example config, no real credentials" }},
    {{ "category": "jwt_token",
       "file_pattern": "fixtures/",      "comment": "Test JWTs in fixture files" }},
    {{ "value_pattern": "localhost|127\\\\.0\\\\.0\\\\.1" }}
  ]
  All specified fields must match (AND logic). "comment" is documentation only.

Categories: {cats}
""".format(cats=', '.join(valid_categories)),
    )
    parser.add_argument(
        'repo', nargs='?', default='.',
        help='Path to the git repository root (default: current directory)',
    )
    parser.add_argument(
        '--categories', nargs='+',
        choices=valid_categories,
        default=None,
        metavar='CATEGORY',
        help='Limit scan to specific categories (default: all)',
    )
    parser.add_argument(
        '--allow', nargs='*', default=[],
        metavar='PATTERN',
        help='Regex patterns to suppress findings (e.g. "localhost")',
    )
    parser.add_argument(
        '--allow-file', metavar='FILE',
        help='File with one allow-pattern per line (# comments supported)',
    )
    parser.add_argument(
        '--whitelist', metavar='FILE',
        help='JSON file with structured whitelist entries (see docs)',
    )
    parser.add_argument(
        '--skip', nargs='*', default=[],
        metavar='PATTERN',
        help='Path patterns to skip (e.g. "docs/" "fixtures/")',
    )
    parser.add_argument(
        '--skip-tests', action='store_true',
        help='Skip common test file and directory patterns',
    )
    parser.add_argument(
        '--format', choices=['text', 'json'], default='text',
        dest='output_format',
        help='Output format: text (default) or json',
    )
    parser.add_argument(
        '--no-fail', action='store_true',
        help='Always exit 0, even when findings are present',
    )
    return parser


def load_allow_file(path):
    patterns = []
    with open(path, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith('#'):
                patterns.append(line)
    return patterns


def load_whitelist(path):
    """Load a JSON whitelist file. Returns a list of entry dicts.

    Supported format (array or object with 'entries' key):
      [
        { "value": "known-safe-token", "comment": "CI service account" },
        { "file": "config/example.yml", "comment": "Example config" },
        { "category": "jwt_token", "file_pattern": "fixtures/", "comment": "Test JWTs" },
        { "value_pattern": "localhost|127\\\\.0\\\\.0\\\\.1" }
      ]

    A finding is suppressed when ALL specified fields in an entry match it.
    Valid match fields: category, file, file_pattern, value, value_pattern.
    The 'comment' field is ignored (documentation only).
    """
    try:
        with open(path, encoding='utf-8') as fh:
            data = json.load(fh)
    except ValueError as exc:
        raise ValueError(f'Invalid JSON in whitelist "{path}": {exc}')
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and 'entries' in data:
        return data['entries']
    raise ValueError(
        'Whitelist must be a JSON array or an object with an "entries" key'
    )


_WHITELIST_MATCH_FIELDS = {'category', 'file', 'file_pattern', 'value', 'value_pattern'}


def _entry_matches(finding, entry):
    """Return True if ALL specified match fields in entry match the finding."""
    if not _WHITELIST_MATCH_FIELDS.intersection(entry):
        return False  # entry has no match fields — skip it
    if 'category' in entry and entry['category'] != finding['category']:
        return False
    if 'file' in entry and entry['file'] not in finding['file']:
        return False
    if 'file_pattern' in entry:
        try:
            if not re.search(entry['file_pattern'], finding['file'], re.IGNORECASE):
                return False
        except re.error:
            return False
    if 'value' in entry and entry['value'] not in finding['value']:
        return False
    if 'value_pattern' in entry:
        try:
            if not re.search(entry['value_pattern'], finding['value'], re.IGNORECASE):
                return False
        except re.error:
            return False
    return True


def is_whitelisted(finding, whitelist):
    """Return True if finding matches any entry in the whitelist."""
    return any(_entry_matches(finding, entry) for entry in whitelist)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    repo_path = os.path.abspath(args.repo)
    if not os.path.isdir(os.path.join(repo_path, '.git')):
        print(f'ERROR: "{repo_path}" is not a git repository root.',
              file=sys.stderr)
        return 2

    allow_patterns = list(args.allow)
    if args.allow_file:
        try:
            allow_patterns.extend(load_allow_file(args.allow_file))
        except OSError as exc:
            print(f'ERROR: Cannot read allow-file: {exc}',
                  file=sys.stderr)
            return 2

    whitelist = []
    if args.whitelist:
        try:
            whitelist = load_whitelist(args.whitelist)
        except (OSError, ValueError) as exc:
            print(f'ERROR: Cannot load whitelist: {exc}',
                  file=sys.stderr)
            return 2

    categories = set(args.categories) if args.categories else None
    skip_patterns = args.skip or []

    try:
        files = get_tracked_files(repo_path)
    except RuntimeError as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2

    if args.output_format == 'text':
        print(f'Scanning {len(files)} tracked file(s) in "{repo_path}" ...')

    all_findings = []
    for path in files:
        all_findings.extend(scan_file(
            path, repo_path, allow_patterns, skip_patterns,
            categories, args.skip_tests, whitelist,
        ))

    if args.output_format == 'json':
        print_json_report(all_findings)
    else:
        print_text_report(all_findings)

    if all_findings and not args.no_fail:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
