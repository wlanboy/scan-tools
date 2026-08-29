#!/usr/bin/env python3

import glob
import json
import os
import re
import socket
import xml.etree.ElementTree as ET
from collections import namedtuple

# Single source of truth for proxy env var names: PROXY_KEYS (for os.environ
# lookups) and the PROXY_PATTERN regex alternation are both derived from this.
PROXY_VAR_BASE_NAMES = ['http_proxy', 'https_proxy', 'ftp_proxy', 'no_proxy', 'all_proxy']

PROXY_KEYS = [name for base in PROXY_VAR_BASE_NAMES for name in (base, base.upper())]

_PROXY_KEY_ALTERNATION = '|'.join(PROXY_VAR_BASE_NAMES)

PROXY_PATTERN = re.compile(
    r'^(?:export\s+)?(' + _PROXY_KEY_ALTERNATION + r')\s*=\s*["\']?([^"\'#\n\r]+)["\']?',
    re.IGNORECASE
)

YUM_DNF_PATTERN = re.compile(r'^(proxy(?:_username|_password)?)\s*=\s*(.+)$')
WGET_PATTERN = re.compile(r'^(https?_proxy|ftp_proxy|no_proxy)\s*=\s*(.+)$', re.IGNORECASE)
CURL_PATTERN = re.compile(r'^(proxy)\s*=\s*(.+)$', re.IGNORECASE)
ANSIBLE_PATTERN = re.compile(r'^(http_proxy|https_proxy|ftp_proxy|no_proxy|proxy)\s*=\s*(.+)$', re.IGNORECASE)
GIT_PATTERN = re.compile(r'^(proxy)\s*=\s*(.+)$', re.IGNORECASE)
NPM_PATTERN = re.compile(r'^(proxy|https-proxy|noproxy)\s*=\s*(.+)$', re.IGNORECASE)
PIP_PATTERN = re.compile(r'^(proxy)\s*=\s*(.+)$', re.IGNORECASE)
SYSTEMD_ENV_PATTERN = re.compile(
    r'^Environment\s*=\s*"?(HTTP_PROXY|HTTPS_PROXY|FTP_PROXY|NO_PROXY|ALL_PROXY)=([^"]+)"?',
    re.IGNORECASE
)
APT_PROXY_PATTERN = re.compile(r'Acquire::(https?)::Proxy\s+"([^"]*)"\s*;', re.IGNORECASE)

CONFIG_FILES = [
    '/etc/environment',
    '/etc/profile',
    '/etc/bashrc',
    '/etc/bash.bashrc',
    '/etc/sysconfig/proxy',
    '/etc/yum.conf',
    '/etc/dnf/dnf.conf',
    '/etc/wgetrc',
    '/etc/curlrc',
    '/etc/gitconfig',
    '/etc/npmrc',
    '/etc/pip.conf',
    os.path.expanduser('~/.bashrc'),
    os.path.expanduser('~/.bash_profile'),
    os.path.expanduser('~/.profile'),
    os.path.expanduser('~/.wgetrc'),
    os.path.expanduser('~/.curlrc'),
    os.path.expanduser('~/.gitconfig'),
    os.path.expanduser('~/.npmrc'),
    os.path.expanduser('~/.pip/pip.conf'),
    os.path.expanduser('~/.config/pip/pip.conf'),
]

GLOB_PATTERNS = [
    '/etc/profile.d/*.sh',
    '/etc/profile.d/*.csh',
    '/etc/environment.d/*.conf',
]

MAVEN_SETTINGS_FILES = [
    os.path.expanduser('~/.m2/settings.xml'),
    '/etc/maven/settings.xml',
    '/usr/share/maven/conf/settings.xml',
    '/usr/local/maven/conf/settings.xml',
]

MAVEN_HOME_CANDIDATES = [
    os.environ.get('MAVEN_HOME', ''),
    os.environ.get('M2_HOME', ''),
]

ANSIBLE_CFG_FILES = [
    '/etc/ansible/ansible.cfg',
    os.path.expanduser('~/.ansible.cfg'),
    './ansible.cfg',
]

APT_CONFIG_FILES = [
    '/etc/apt/apt.conf',
]

APT_GLOB_PATTERNS = [
    '/etc/apt/apt.conf.d/*',
]

DOCKER_CONFIG_FILES = [
    os.path.expanduser('~/.docker/config.json'),
]

SYSTEMD_GLOB_PATTERNS = [
    '/etc/systemd/system/*.service.d/*.conf',
    '/etc/systemd/system.conf.d/*.conf',
    os.path.expanduser('~/.config/systemd/user/*.service.d/*.conf'),
]

Finding = namedtuple('Finding', ['source', 'key', 'value'])

findings = []


def add_finding(source, key, value):
    value = value.strip()
    if value:
        findings.append(Finding(source, key, value))


def check_env():
    for key in PROXY_KEYS:
        val = os.environ.get(key)
        if val:
            add_finding('ENV', key, val)


def scan_pattern_lines(path, pattern):
    """Match `pattern` against each stripped line; group(1) is the key, group(2) the value."""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                m = pattern.match(line.strip())
                if m:
                    add_finding(path, m.group(1), m.group(2).strip(' \t\'"'))
    except OSError:
        pass


def scan_apt_conf(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                m = APT_PROXY_PATTERN.search(line)
                if m:
                    add_finding(path, f'Acquire::{m.group(1)}::Proxy', m.group(2))
    except OSError:
        pass


def scan_docker_config(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
    except (OSError, ValueError):
        return
    if not isinstance(data, dict):
        return
    for env_name, cfg in data.get('proxies', {}).values():
        if not isinstance(cfg, dict):
            continue
        for key in ('httpProxy', 'httpsProxy', 'ftpProxy', 'noProxy'):
            value = cfg.get(key)
            if value:
                add_finding(path, key, str(value))


def scan_maven_settings(path):
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        # handle optional namespace
        ns = ''
        if root.tag.startswith('{'):
            ns = root.tag.split('}')[0] + '}'
        proxies = root.find(f'{ns}proxies')
        if proxies is None:
            return
        for proxy in proxies.findall(f'{ns}proxy'):
            def txt(tag, proxy=proxy):
                el = proxy.find(f'{ns}{tag}')
                return el.text.strip() if el is not None and el.text else ''
            active = txt('active')
            # Maven treats a proxy as active when <active> is omitted; only an
            # explicit "false" disables it. Ignoring this made disabled example
            # <proxy> entries in settings.xml count as a configured proxy.
            if active and active.lower() != 'true':
                continue
            protocol = txt('protocol')
            host = txt('host')
            port = txt('port')
            username = txt('username')
            nonProxyHosts = txt('nonProxyHosts')
            if host:
                add_finding(path, 'proxy.host', host)
            if port:
                add_finding(path, 'proxy.port', port)
            if protocol:
                add_finding(path, 'proxy.protocol', protocol)
            if username:
                add_finding(path, 'proxy.username', username)
            if nonProxyHosts:
                add_finding(path, 'proxy.nonProxyHosts', nonProxyHosts)
    except (OSError, ET.ParseError):
        pass


def route_file(path):
    lower = path.lower()
    if lower.endswith(('/yum.conf', '/dnf.conf')):
        scan_pattern_lines(path, YUM_DNF_PATTERN)
    elif lower.endswith('wgetrc'):
        scan_pattern_lines(path, WGET_PATTERN)
    elif lower.endswith('curlrc'):
        scan_pattern_lines(path, CURL_PATTERN)
    elif lower.endswith('ansible.cfg'):
        scan_pattern_lines(path, ANSIBLE_PATTERN)
    elif lower.endswith('gitconfig'):
        scan_pattern_lines(path, GIT_PATTERN)
    elif lower.endswith('npmrc'):
        scan_pattern_lines(path, NPM_PATTERN)
    elif lower.endswith(('pip.conf', 'pip.ini')):
        scan_pattern_lines(path, PIP_PATTERN)
    else:
        scan_pattern_lines(path, PROXY_PATTERN)


def collect_maven_files():
    candidates = list(MAVEN_SETTINGS_FILES)
    for home in MAVEN_HOME_CANDIDATES:
        if home:
            candidates.append(os.path.join(home, 'conf', 'settings.xml'))
    return candidates


_NON_ACTIVE_KEY_MARKERS = {'no_proxy', 'noproxy', 'no-proxy'}


def is_real_proxy_key(key):
    """no_proxy / nonProxyHosts are exclusion lists, not an active proxy setting."""
    k = key.lower()
    if k in _NON_ACTIVE_KEY_MARKERS:
        return False
    return not k.endswith('nonproxyhosts')


def main():
    hostname = socket.gethostname()

    check_env()

    # shell / system / tool config files
    all_files = list(CONFIG_FILES)
    for pattern in GLOB_PATTERNS:
        all_files.extend(glob.glob(pattern))

    seen = set()
    for path in all_files:
        if path not in seen:
            seen.add(path)
            route_file(path)

    # maven
    for path in collect_maven_files():
        if path not in seen:
            seen.add(path)
            scan_maven_settings(path)

    # ansible
    for path in ANSIBLE_CFG_FILES:
        if path not in seen:
            seen.add(path)
            route_file(path)

    # apt
    apt_files = list(APT_CONFIG_FILES)
    for pattern in APT_GLOB_PATTERNS:
        apt_files.extend(glob.glob(pattern))
    for path in apt_files:
        if path not in seen:
            seen.add(path)
            scan_apt_conf(path)

    # docker
    for path in DOCKER_CONFIG_FILES:
        if path not in seen:
            seen.add(path)
            scan_docker_config(path)

    # systemd service/unit drop-ins
    systemd_files = []
    for pattern in SYSTEMD_GLOB_PATTERNS:
        systemd_files.extend(glob.glob(pattern))
    for path in systemd_files:
        if path not in seen:
            seen.add(path)
            scan_pattern_lines(path, SYSTEMD_ENV_PATTERN)

    print(f"=== PROXY SCAN REPORT: {hostname} ===")

    has_real_proxy = any(is_real_proxy_key(f.key) for f in findings)

    print("RESULT: PROXY_FOUND" if has_real_proxy else "RESULT: NO_PROXY_FOUND")

    for f in sorted(findings, key=lambda f: (f.source, f.key)):
        print(f"SOURCE={f.source} KEY={f.key} VALUE={f.value}")

    return 1 if has_real_proxy else 0


if __name__ == '__main__':
    raise SystemExit(main())
