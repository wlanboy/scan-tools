#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
scan-secrets.py - Scans a git repository for credentials and secrets:
  Basic Auth (URL and header), Bearer tokens, OAuth tokens/secrets,
  API keys, private keys, JWT tokens and generic passwords.

Exit codes:
  0 - No findings (or --no-fail set)
  1 - Findings detected
  2 - Script error (invalid arguments, not a git repo, etc.)

Compatible with Python 2.7 and 3.x.
"""
from __future__ import print_function, unicode_literals

import argparse
import io
import json
import os
import re
import subprocess
import sys


# ---------------------------------------------------------------------------
# Placeholder / false-positive guard
# ---------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(
    r'^(?:'
    r'\*+|x{3,}|0{4,}|\.{3,}|\?+|_{4,}'           # masking chars
    r'|your[-_ ]'                                    # "your-secret-here"
    r'|<[^>]+>'                                      # <TOKEN>, <your-key>
    r'|\$\{[^}]+\}'                                 # ${TOKEN}
    r'|\$[A-Z_][A-Z0-9_]{2,}'                      # $API_KEY (env var ref)
    r'|\{\{[^}]+\}\}'                               # {{token}} (template)
    r'|%\([^)]+\)'                                   # %(key)s (Python format)
    r'|todo|change.?me|example|placeholder|fake|dummy'
    r'|test|sample|insert|n/?a|undefined|null|none'
    r'|empty|missing|replace.?this|edit.?this'
    r'|password|passwd|secret|token|apikey|api.?key'  # bare field names
    r')$',
    re.IGNORECASE,
)


def is_placeholder(value):
    """Return True if value looks like a template/placeholder, not a real secret."""
    if not value or len(value.strip()) < 4:
        return True
    v = value.strip()
    if _PLACEHOLDER_RE.match(v):
        return True
    # All same character repeated (e.g. "aaaaaaaaaa", "11111111")
    if len(set(v)) == 1:
        return True
    return False


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
            r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        ),
    ),
    (
        'basic_auth_url',
        'Basic Auth in URL',
        re.compile(
            r'https?://([^@\s\'"<>()\[\]{}\\,;/]+)'
            r':([^@\s\'"<>()\[\]{}\\,;/]{3,})'
            r'@[a-zA-Z0-9.\-]+'
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
            r'(?:^|[^a-zA-Z])(?:password|passwd|pwd)'
            r'\s*[=:]\s*["\']([^"\']{4,})["\']',
            re.IGNORECASE,
        ),
    ),
    (
        'generic_secret',
        'Generic Secret / Token',
        re.compile(
            r'(?:^|[^a-zA-Z])(?:secret|credential|auth_key|'
            r'auth_token|session_key|private_key|signing_key)'
            r'\s*[=:]\s*["\']([^"\']{8,})["\']',
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
            # and Atlassian API tokens (ATATT) all use well-known prefixes
            r'\b(ATBB[A-Za-z0-9]{28,}'
            r'|ATCTT[A-Za-z0-9_\-]{50,}'
            r'|ATATT[A-Za-z0-9_\-]{50,})\b',
        ),
    ),
    (
        'bitbucket_token',
        'Bitbucket / Atlassian Token',
        re.compile(
            # named variables in env / CI config files
            r'(?:bitbucket[_.\-]?(?:token|app[_.\-]?password|api[_.\-]?key'
            r'|access[_.\-]?token|pat)'
            r'|BITBUCKET[_.\-]?(?:TOKEN|APP[_.\-]?PASSWORD|API[_.\-]?KEY'
            r'|ACCESS[_.\-]?TOKEN|PAT))'
            r'\s*[=:]\s*["\']?([A-Za-z0-9\-._]{16,})["\']?',
            re.IGNORECASE,
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
    except (IOError, OSError):
        return True


def is_test_file(path):
    lower = path.lower()
    basename = os.path.basename(lower)
    return (
        '/test/' in lower
        or '/tests/' in lower
        or '\\test\\' in lower
        or '\\tests\\' in lower
        or basename.startswith('test_')
        or basename.endswith('_test.py')
        or basename.endswith('_test.go')
        or basename.endswith('.test.ts')
        or basename.endswith('.test.js')
        or basename.endswith('.test.jsx')
        or basename.endswith('.spec.ts')
        or basename.endswith('.spec.js')
        or basename.endswith('.spec.jsx')
        or basename.endswith('test.java')
        or basename.endswith('_spec.rb')
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
        raise RuntimeError('git ls-files failed: {0}'.format(exc))


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
            # Group 1 is the extracted secret value when the pattern captures it
            if m.lastindex and m.lastindex >= 1:
                secret = m.group(1)
            else:
                secret = matched
            if is_placeholder(secret):
                continue
            # basic_auth_url: also check the password group (group 2)
            if category == 'basic_auth_url' and (m.lastindex or 0) >= 2:
                if is_placeholder(m.group(2)):
                    continue
            if matches_any(matched, allow_patterns):
                continue
            yield (category, label, matched)


def scan_file(path, repo_path, allow_patterns, skip_patterns, categories, skip_tests):
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
        with io.open(path, encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
    except (IOError, OSError):
        return findings

    for line_no, raw_line in enumerate(lines, start=1):
        line_text = raw_line.rstrip('\n\r')
        for category, label, matched in scan_line(line_text, allow_patterns, categories):
            findings.append({
                'category': category,
                'label': label,
                'value': matched,
                'file': rel_path,
                'line': line_no,
                'context': line_text.strip()[:120],
            })

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
    print('\n{0}'.format(sep))
    print('  Secrets scan -- {0} finding(s)'.format(len(findings)))
    print('{0}\n'.format(sep))

    printed = set()
    for cat in CATEGORY_ORDER:
        items = by_category.get(cat, [])
        if not items:
            continue
        printed.add(cat)
        print('  {0} ({1})'.format(items[0]['label'], len(items)))
        print('  {0}'.format('-' * 40))
        for f in items:
            print('  {0}:{1}'.format(f['file'], f['line']))
            print('    Value  : {0}'.format(f['value'][:80]))
            print('    Context: {0}'.format(f['context']))
            print()

    # Catch any categories not listed in CATEGORY_ORDER
    for cat, items in by_category.items():
        if cat not in printed and items:
            print('  {0} ({1})'.format(items[0]['label'], len(items)))
            print('  {0}'.format('-' * 40))
            for f in items:
                print('  {0}:{1}'.format(f['file'], f['line']))
                print('    Value  : {0}'.format(f['value'][:80]))
                print('    Context: {0}'.format(f['context']))
                print()

    files = set(f['file'] for f in findings)
    print('{0}'.format(sep))
    print('  Total: {0} finding(s) in {1} file(s)'.format(
        len(findings), len(files)))
    print('{0}\n'.format(sep))


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
    with io.open(path, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith('#'):
                patterns.append(line)
    return patterns


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    repo_path = os.path.abspath(args.repo)
    if not os.path.isdir(os.path.join(repo_path, '.git')):
        print('ERROR: "{0}" is not a git repository root.'.format(repo_path),
              file=sys.stderr)
        return 2

    allow_patterns = list(args.allow)
    if args.allow_file:
        try:
            allow_patterns.extend(load_allow_file(args.allow_file))
        except (IOError, OSError) as exc:
            print('ERROR: Cannot read allow-file: {0}'.format(exc),
                  file=sys.stderr)
            return 2

    categories = set(args.categories) if args.categories else None
    skip_patterns = args.skip or []

    try:
        files = get_tracked_files(repo_path)
    except RuntimeError as exc:
        print('ERROR: {0}'.format(exc), file=sys.stderr)
        return 2

    if args.output_format == 'text':
        print('Scanning {0} tracked file(s) in "{1}" ...'.format(
            len(files), repo_path))

    all_findings = []
    for path in files:
        all_findings.extend(scan_file(
            path, repo_path, allow_patterns, skip_patterns,
            categories, args.skip_tests,
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
