#!/usr/bin/env python3
"""
scan_external_urls.py - Scans a git repository for external URLs, emails,
hostnames, and IP addresses that could leak data or cause unintended outbound
connections in tests or code.

Exit codes:
  0 - No findings (or --no-fail set)
  1 - Findings detected
  2 - Script error (invalid arguments, not a git repo, etc.)
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------


class Category(str, Enum):
    URL = "url"
    EMAIL = "email"
    HOSTNAME = "hostname"
    IP = "ip"


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

URL_PATTERN = re.compile(
    r'https?://[^\s\'"<>()\[\]{}\\,;]+'
    r'(?:[^\s\'"<>()\[\]{}\\,;.!?])',
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)

# Matches hostnames like "api.example.com", "mail.internal.corp"
# Requires at least one dot and a known-ish TLD length (2-6 chars).
# Each segment must be at least 2 chars to exclude single-letter variables (p.name, p.parent).
HOSTNAME_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9][a-zA-Z0-9\-]{0,60}[a-zA-Z0-9]\.)'
    r'+[a-zA-Z]{2,6}\b'
)

IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Rough IPv6 match — every candidate is validated via ipaddress.ip_address()
# to eliminate false positives (CSS values, build hashes, etc.).
_IPV6_ROUGH = re.compile(
    r'(?<![:\w/])'
    r'[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}'
    r'(?![:\w])',
    re.IGNORECASE,
)

# Extracts the authority (host[:port]) from a URL, skipping optional
# userinfo (user@ or user:pass@). Shared by whitelist- and allow-matching.
_URL_HOST_PATTERN = re.compile(
    r'https?://(?:[^@/\s:?#]+(?::[^@/\s:?#]*)?@)?([^/\s:?#]+)',
    re.IGNORECASE,
)

# A plain domain literal: letters/digits/hyphens per label, dot-separated,
# at least one dot. Used to tell "mycompany.com" (a real domain the caller
# means literally) apart from a genuine regex like "test.*staging".
_DOMAIN_LITERAL_PATTERN = re.compile(
    r'^[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$'
)

# Positive TLD allowlist: only matches whose last label is in this set are
# reported as hostnames. Using a whitelist is far more stable than maintaining
# a growing blacklist of code-like suffixes (error, name, parent, boot, …).
KNOWN_TLDS = {
    # Generic gTLDs
    "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz",
    # Tech/cloud gTLDs
    "io", "co", "ai", "app", "dev", "tech", "online", "site",
    # Common ccTLDs
    "ac", "ae", "at", "au", "be", "br", "ca", "ch", "cn", "cz",
    "de", "dk", "es", "eu", "fi", "fr", "gr", "hk", "hu",
    "il", "in", "it", "jp", "kr", "mx", "nl", "no", "nz", "pl",
    "pt", "ro", "ru", "se", "sg", "tr", "tw", "uk", "us", "za",
    # Short ccTLDs used as domain hacks
    "me", "ly", "to", "im", "gg", "gl", "fm", "tv", "cc",
    # Cloud / infrastructure gTLDs
    "cloud", "run", "build", "tools", "software", "network",
    "services", "systems", "solutions", "digital",
    # NOTE: "sh" omitted — conflicts with shell scripts (stats.sh, addserver.sh)
    # NOTE: "id" omitted — conflicts with JS/Python attribute access (this.id, obj.id)
}

# Binary file detection: read first 8 KB and look for null bytes
BINARY_CHECK_BYTES = 8192

# Extensions that are always skipped (images, compiled artifacts, …)
ALWAYS_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".webp", ".tiff", ".pdf", ".zip", ".tar", ".gz", ".bz2",
    ".xz", ".7z", ".rar", ".jar", ".war", ".ear", ".class",
    ".pyc", ".pyo", ".so", ".o", ".a", ".dll", ".exe", ".bin",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv",
    ".lock",  # package-lock.json, yarn.lock etc. are noisy
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    category: Category
    value: str
    file: str
    line: int
    context: str


@dataclass
class Whitelist:
    ip_ranges: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    email_domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)


@dataclass
class ScanConfig:
    repo_path: str
    allowlist: list[str] = field(default_factory=list)
    skip_patterns: list[str] = field(default_factory=list)
    categories: set[Category] = field(default_factory=lambda: set(Category))
    skip_tests: bool = False
    output_format: str = "text"   # "text" | "json"
    no_fail: bool = False
    ignore_ips: set[str] = field(default_factory=set)
    ignore_all_ips: bool = False
    whitelist: Whitelist = field(default_factory=Whitelist)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_tracked_files(repo_path: str) -> list[str]:
    """Return all files git would see: tracked files plus untracked files
    that are not excluded by .gitignore (so new, not-yet-committed files
    are scanned too)."""
    result = subprocess.run(
        ["git", "-C", repo_path, "ls-files", "--cached", "--others",
         "--exclude-standard"],
        capture_output=True, text=True, check=True,
    )
    return [
        os.path.join(repo_path, f)
        for f in result.stdout.splitlines()
        if f.strip()
    ]


def is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(BINARY_CHECK_BYTES)
    except OSError:
        return True


def is_test_file(path: str) -> bool:
    lower = path.lower()
    basename = os.path.basename(lower)
    basename_orig = os.path.basename(path)
    test_dir_markers = ("/test/", "/tests/", "/__tests__/", "\\test\\", "\\tests\\", "\\__tests__\\")
    test_suffixes = (
        "_test.py", "_test.go",
        ".test.ts", ".test.tsx", ".test.js", ".test.jsx",
        ".spec.ts", ".spec.tsx", ".spec.js", ".spec.jsx",
        "_spec.rb",
    )
    return (
        any(marker in lower for marker in test_dir_markers)
        or basename.startswith("test_")
        or basename.endswith(test_suffixes)
        or basename_orig.endswith(("Test.java", "Tests.java"))
        or (basename_orig.startswith("Test") and basename_orig.endswith(".java"))
    )


def matches_any(value: str, patterns: list[str]) -> bool:
    value_lower = value.lower()
    for pattern in patterns:
        try:
            if re.search(pattern, value_lower, re.IGNORECASE):
                return True
        except re.error:
            if pattern.lower() in value_lower:
                return True
    return False


def _has_known_tld(value: str) -> bool:
    tld = value.rsplit(".", 1)[-1].lower()
    return tld in KNOWN_TLDS


def _host_matches_any(host: str, hostnames: list[str]) -> bool:
    """True if host equals one of hostnames, or is a subdomain of one."""
    return any(host == h or host.endswith("." + h) for h in hostnames)


def _extract_url_host(value: str) -> str | None:
    m = _URL_HOST_PATTERN.match(value)
    return m.group(1).lower() if m else None


def _as_domain_literal(pattern: str) -> str | None:
    """If pattern is a plain domain (optionally with backslash-escaped dots,
    e.g. "mycompany\\.com"), return the normalized domain; otherwise None,
    meaning it should be treated as a genuine regex."""
    normalized = pattern.replace(r'\.', '.')
    if _DOMAIN_LITERAL_PATTERN.match(normalized):
        return normalized.lower()
    return None


def _extract_host_for_category(category: Category, value: str) -> str | None:
    if category == Category.HOSTNAME:
        return value.lower()
    if category == Category.EMAIL:
        return value.split("@", 1)[-1].lower()
    if category == Category.URL:
        return _extract_url_host(value)
    return None


def is_allowlisted(category: Category, value: str, patterns: list[str]) -> bool:
    """True if a --allow pattern matches this finding.

    A pattern that is a plain domain literal (e.g. "mycompany\\.com") is
    matched against the value's *host* using domain-suffix rules (exact
    match, or a subdomain of it) for url/hostname/email findings. This
    stops a trusted-looking substring match from allowlisting an unrelated
    host such as "evil-mycompany.com.attacker.net".

    Any other pattern is treated as a free-form regex and searched within
    the raw value, as before.
    """
    domain_patterns: list[str] = []
    free_patterns: list[str] = []
    for pattern in patterns:
        domain = _as_domain_literal(pattern)
        if domain is not None and category in (Category.URL, Category.HOSTNAME, Category.EMAIL):
            domain_patterns.append(domain)
        else:
            free_patterns.append(pattern)

    if domain_patterns:
        host = _extract_host_for_category(category, value)
        if host and _host_matches_any(host, domain_patterns):
            return True

    return matches_any(value, free_patterns)


# ---------------------------------------------------------------------------
# Per-category detection
# ---------------------------------------------------------------------------

def _detect_urls(line_text: str, values_so_far: set[str], config: ScanConfig) -> list[str]:
    return [m.group(0) for m in URL_PATTERN.finditer(line_text)]


def _detect_emails(line_text: str, values_so_far: set[str], config: ScanConfig) -> list[str]:
    hits: list[str] = []
    for m in EMAIL_PATTERN.finditer(line_text):
        value = m.group(0)
        # Avoid reporting the same value already caught as a URL
        if any(value in v for v in values_so_far):
            continue
        # Reject file-extension false positives: foo@bar.py, test@schema.go
        if not _has_known_tld(value):
            continue
        hits.append(value)
    return hits


def _detect_hostnames(line_text: str, values_so_far: set[str], config: ScanConfig) -> list[str]:
    hits: list[str] = []
    for m in HOSTNAME_PATTERN.finditer(line_text):
        host = m.group(0)
        # Skip function/method calls: subprocess.run(, os.path.join(
        if m.end() < len(line_text) and line_text[m.end()] == "(":
            continue
        # Skip truncated dotted-path prefixes: a JSON/YAML path like
        # "a.b.meshConfig.ca.address" gets matched only up through the
        # TLD-shaped "ca" segment — a real hostname wouldn't be immediately
        # followed by another ".word" with no separator.
        if (
            m.end() + 1 < len(line_text)
            and line_text[m.end()] == "."
            and line_text[m.end() + 1].isalnum()
        ):
            continue
        # True when this host is the authority of an actual URL (right after
        # "://"), as opposed to a bare dotted identifier or API-group string.
        # A host in that position must still be reported even when "url"
        # isn't itself a scanned category, and the path/apiGroup heuristics
        # below don't apply to it.
        is_url_authority = line_text[max(0, m.start() - 3):m.start()] == "://"
        # Skip file path components: /etc/hostapd/hostapd.conf
        if m.start() > 0 and line_text[m.start() - 1] == "/" and not is_url_authority:
            continue
        # Only report if the TLD is a known real TLD
        if not _has_known_tld(host):
            continue
        # Skip all-uppercase non-TLD part: DOS filenames (MOUSE.COM) or constants
        non_tld = host.rsplit(".", 1)[0]
        if non_tld == non_tld.upper() and any(c.isalpha() for c in non_tld):
            continue
        # Skip Python/JS import statements: "from textual.app import", "import x.y"
        before_stripped = line_text[:m.start()].rstrip()
        if re.search(r'\b(?:from|import)$', before_stripped):
            continue
        # Skip Kubernetes API groups and annotation keys: networking.istio.io/v1
        # or nginx.ingress.kubernetes.io/rewrite-target — hostname followed by /
        if m.end() < len(line_text) and line_text[m.end()] == "/" and not is_url_authority:
            continue
        # Skip bare Kubernetes apiGroup values: "apiGroup: rbac.authorization.k8s.io"
        if re.search(r'\bapiGroups?\s*:\s+' + re.escape(host) + r'\s*$', line_text):
            continue
        # Skip bare YAML list items: "  - containerd.io" (package names, not URLs)
        if re.match(r'^\s*-\s+' + re.escape(host) + r'\s*$', line_text):
            continue
        if any(host in v for v in values_so_far):
            continue
        hits.append(host)
    return hits


def _detect_ips(line_text: str, values_so_far: set[str], config: ScanConfig) -> list[str]:
    if config.ignore_all_ips:
        return []

    hits: list[str] = []
    for m in IP_PATTERN.finditer(line_text):
        ip = m.group(0)
        if ip not in config.ignore_ips:
            hits.append(ip)

    for m in _IPV6_ROUGH.finditer(line_text):
        candidate = m.group(0)
        try:
            addr = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if not isinstance(addr, ipaddress.IPv6Address):
            continue
        if str(addr) not in config.ignore_ips and candidate not in config.ignore_ips:
            hits.append(candidate)

    return hits


# ---------------------------------------------------------------------------
# Per-category whitelisting (whitelist.json)
# ---------------------------------------------------------------------------

def _whitelisted_ip(value: str, wl: Whitelist) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in wl.ip_ranges)


def _whitelisted_hostname(value: str, wl: Whitelist) -> bool:
    return _host_matches_any(value.lower(), wl.hostnames)


def _whitelisted_email(value: str, wl: Whitelist) -> bool:
    domain = value.split("@", 1)[-1].lower()
    return domain in wl.email_domains


def _whitelisted_url(value: str, wl: Whitelist) -> bool:
    value_lower = value.lower()
    if any(value_lower.startswith(u) for u in wl.urls):
        return True
    host = _extract_url_host(value)
    return bool(host and _host_matches_any(host, wl.hostnames))


@dataclass(frozen=True)
class CategorySpec:
    key: Category
    label: str
    detect: Callable[[str, set[str], ScanConfig], list[str]]
    is_whitelisted: Callable[[str, Whitelist], bool]


# Single source of truth for per-category behavior and report order —
# replaces the if/elif chains and parallel label dicts that used to be
# scattered across scan_line(), is_whitelisted() and print_text_report().
CATEGORY_SPECS: tuple[CategorySpec, ...] = (
    CategorySpec(Category.URL, "URL", _detect_urls, _whitelisted_url),
    CategorySpec(Category.EMAIL, "Email", _detect_emails, _whitelisted_email),
    CategorySpec(Category.HOSTNAME, "Hostname", _detect_hostnames, _whitelisted_hostname),
    CategorySpec(Category.IP, "IP Address", _detect_ips, _whitelisted_ip),
)
CATEGORY_SPECS_BY_KEY: dict[Category, CategorySpec] = {spec.key: spec for spec in CATEGORY_SPECS}


def is_whitelisted(category: Category, value: str, wl: Whitelist) -> bool:
    return CATEGORY_SPECS_BY_KEY[category].is_whitelisted(value, wl)


# ---------------------------------------------------------------------------
# Per-line scanning
# ---------------------------------------------------------------------------

def scan_line(line_text: str, config: ScanConfig) -> list[tuple[Category, str]]:
    """Return list of (category, value) matches in a single line."""
    hits: list[tuple[Category, str]] = []
    values_so_far: set[str] = set()

    for spec in CATEGORY_SPECS:
        if spec.key not in config.categories:
            continue
        for value in spec.detect(line_text, values_so_far, config):
            hits.append((spec.key, value))
            values_so_far.add(value)

    return hits


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------

def scan_file(path: str, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []

    # Skip by extension
    ext = Path(path).suffix.lower()
    if ext in ALWAYS_SKIP_EXTENSIONS:
        return findings

    # Skip test files if requested
    if config.skip_tests and is_test_file(path):
        return findings

    # Skip explicitly excluded path patterns
    rel_path = os.path.relpath(path, config.repo_path)
    if matches_any(rel_path, config.skip_patterns):
        return findings

    if is_binary(path):
        return findings

    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return findings

    for line_no, raw_line in enumerate(lines, start=1):
        line_text = raw_line.rstrip("\n\r")
        for category, value in scan_line(line_text, config):
            if is_allowlisted(category, value, config.allowlist):
                continue
            if is_whitelisted(category, value, config.whitelist):
                continue
            findings.append(Finding(
                category=category,
                value=value,
                file=rel_path,
                line=line_no,
                context=line_text.strip()[:120],
            ))

    return findings


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def print_text_report(findings: list[Finding]) -> None:
    if not findings:
        print("No external references found.")
        return

    by_category: dict[Category, list[Finding]] = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)

    print(f"\n{'='*70}")
    print(f"  External reference scan — {len(findings)} finding(s)")
    print(f"{'='*70}\n")

    for spec in CATEGORY_SPECS:
        items = by_category.get(spec.key, [])
        if not items:
            continue
        print(f"  {spec.label}s ({len(items)})")
        print(f"  {'-'*40}")
        for f in items:
            print(f"  {f.file}:{f.line}")
            print(f"    Value  : {f.value}")
            print(f"    Context: {f.context}")
            print()

    print(f"{'='*70}")
    print(f"  Total: {len(findings)} finding(s) in {len({f.file for f in findings})} file(s)")
    print(f"{'='*70}\n")


def print_json_report(findings: list[Finding]) -> None:
    data = [
        {
            "category": f.category.value,
            "value": f.value,
            "file": f.file,
            "line": f.line,
            "context": f.context,
        }
        for f in findings
    ]
    print(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a git repository for external URLs, emails, hostnames, and IPs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan current directory, fail on any finding
  python scan_external_urls.py

  # Scan specific repo, skip test files, allow internal domain
  python scan_external_urls.py /path/to/repo --skip-tests --allow "mycompany\\.com"

  # CI pipeline: JSON output, fail on URL or email only
  python scan_external_urls.py --categories url email --format json

  # Load allowlist from file (one regex per line)
  python scan_external_urls.py --allow-file .scan-allowlist

  # Ignore all IP addresses (e.g. Ansible/infrastructure repos)
  python scan_external_urls.py --ignore-all-ips

  # Ignore specific IP addresses
  python scan_external_urls.py --ignore-ips 192.168.1.1 10.0.0.1

  # Load ignored IPs from file (one IP per line)
  python scan_external_urls.py --ignore-ips-file .scan-ignore-ips

Note on --allow / --allow-file:
  A pattern written as a plain domain (e.g. "mycompany.com" or the escaped
  "mycompany\\.com") is matched against the finding's host using domain-suffix
  rules — it allows that domain and its subdomains only, not any string that
  merely contains it (so it won't match "evil-mycompany.com.attacker.net").
  Any other pattern is used as a free-form regex searched in the raw value.
""",
    )
    parser.add_argument(
        "repo", nargs="?", default=".",
        help="Path to the git repository root (default: current directory)",
    )
    parser.add_argument(
        "--categories", nargs="+",
        choices=[c.value for c in Category],
        default=[c.value for c in Category],
        metavar="CATEGORY",
        help="Categories to scan for: url email hostname ip (default: all)",
    )
    parser.add_argument(
        "--allow", nargs="*", default=[],
        metavar="PATTERN",
        help="Regex patterns to allow (e.g. 'localhost' 'example\\.com')",
    )
    parser.add_argument(
        "--allow-file", metavar="FILE",
        help="File with one allow-pattern per line (comments with # supported)",
    )
    parser.add_argument(
        "--skip", nargs="*", default=[],
        metavar="PATTERN",
        help="Regex path patterns to skip (e.g. 'docs/' 'fixtures/')",
    )
    parser.add_argument(
        "--skip-tests", action="store_true",
        help="Skip common test file/directory patterns",
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        dest="output_format",
        help="Output format: text (default) or json",
    )
    parser.add_argument(
        "--no-fail", action="store_true",
        help="Always exit 0, even when findings are present",
    )
    parser.add_argument(
        "--ignore-all-ips", action="store_true",
        help="Ignore all IP addresses (useful for Ansible or infrastructure repos)",
    )
    parser.add_argument(
        "--ignore-ips", nargs="+", default=[],
        metavar="IP",
        help="IP addresses to ignore (e.g. '192.168.1.1' '10.0.0.1')",
    )
    parser.add_argument(
        "--ignore-ips-file", metavar="FILE",
        help="File with one IP address per line to ignore (comments with # supported)",
    )
    parser.add_argument(
        "--whitelist", metavar="FILE",
        help="JSON file with ip_ranges, hostnames, email_domains, and urls to whitelist",
    )
    return parser


def load_allowlist_file(path: str) -> list[str]:
    patterns: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def load_whitelist_file(path: str) -> Whitelist:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    wl = Whitelist()
    for entry in data.get("ip_ranges", []):
        try:
            wl.ip_ranges.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            print(f"WARNING: Invalid IP range '{entry}' in whitelist: {exc}", file=sys.stderr)

    wl.hostnames = [h.lower().lstrip("*.") for h in data.get("hostnames", [])]
    wl.email_domains = [d.lower() for d in data.get("email_domains", [])]
    wl.urls = [u.lower() for u in data.get("urls", [])]
    return wl


def _find_default_whitelist(repo_path: str) -> str | None:
    candidate = os.path.join(repo_path, "whitelist.json")
    return candidate if os.path.isfile(candidate) else None


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    repo_path = os.path.abspath(args.repo)
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        print(f"ERROR: '{repo_path}' is not a git repository root.", file=sys.stderr)
        return 2

    allowlist = list(args.allow)
    if args.allow_file:
        try:
            allowlist.extend(load_allowlist_file(args.allow_file))
        except OSError as exc:
            print(f"ERROR: Cannot read allow-file: {exc}", file=sys.stderr)
            return 2

    ignore_ips = set(args.ignore_ips)
    if args.ignore_ips_file:
        try:
            ignore_ips.update(load_allowlist_file(args.ignore_ips_file))
        except OSError as exc:
            print(f"ERROR: Cannot read ignore-ips-file: {exc}", file=sys.stderr)
            return 2

    whitelist = Whitelist()
    whitelist_path = args.whitelist or _find_default_whitelist(repo_path)
    if whitelist_path:
        if not args.whitelist:
            print(f"Note: auto-loading whitelist from '{whitelist_path}'", file=sys.stderr)
        try:
            whitelist = load_whitelist_file(whitelist_path)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: Cannot read whitelist file: {exc}", file=sys.stderr)
            return 2

    config = ScanConfig(
        repo_path=repo_path,
        allowlist=allowlist,
        skip_patterns=args.skip or [],
        categories={Category(c) for c in args.categories},
        skip_tests=args.skip_tests,
        output_format=args.output_format,
        no_fail=args.no_fail,
        ignore_ips=ignore_ips,
        ignore_all_ips=args.ignore_all_ips,
        whitelist=whitelist,
    )

    try:
        files = get_tracked_files(repo_path)
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: git ls-files failed: {exc}", file=sys.stderr)
        return 2

    if config.output_format == "text":
        print(f"Scanning {len(files)} tracked file(s) in '{repo_path}' …")

    all_findings: list[Finding] = []
    for path in files:
        all_findings.extend(scan_file(path, config))

    if config.output_format == "json":
        print_json_report(all_findings)
    else:
        print_text_report(all_findings)

    if all_findings and not config.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
