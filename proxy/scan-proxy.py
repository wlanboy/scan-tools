#!/usr/bin/env python3

# Must stay runnable on Python 3.6 (CentOS 7 python3, RHEL 8 platform-python):
# no walrus operator, no str.removeprefix, no dataclasses.

import glob
import json
import os
import re
import shlex
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

# csh/tcsh sets environment variables with 'setenv NAME value' instead of NAME=value.
CSH_SETENV_PATTERN = re.compile(
    r'^setenv\s+(' + _PROXY_KEY_ALTERNATION + r')\s+["\']?([^"\'#\n\r]+)["\']?',
    re.IGNORECASE
)

YUM_DNF_PATTERN = re.compile(r'^(proxy(?:_username|_password)?)\s*=\s*(.+)$')
# subscription-manager (RHEL): rhsm.conf ships 'proxy_scheme = http' by default,
# so only the keys that are empty unless a proxy is really configured are read.
RHSM_PATTERN = re.compile(r'^(proxy_hostname|proxy_port|proxy_user|proxy_password|no_proxy)\s*=\s*(.+)$')
WGET_PATTERN = re.compile(r'^(https?_proxy|ftp_proxy|no_proxy)\s*=\s*(.+)$', re.IGNORECASE)
# curl config accepts 'proxy = x', 'proxy x', 'proxy: x', '--proxy x' and '-x x'.
CURL_PATTERN = re.compile(r'^(?:--)?(proxy|noproxy|-x)(?:\s*[=:]\s*|\s+)["\']?([^"\'\s]+)', re.IGNORECASE)
ANSIBLE_PATTERN = re.compile(r'^(http_proxy|https_proxy|ftp_proxy|no_proxy|proxy)\s*=\s*(.+)$', re.IGNORECASE)
GIT_PATTERN = re.compile(r'^(proxy)\s*=\s*(.+)$', re.IGNORECASE)
NPM_PATTERN = re.compile(r'^(proxy|https-proxy|noproxy)\s*=\s*(.+)$', re.IGNORECASE)
PIP_PATTERN = re.compile(r'^(proxy)\s*=\s*(.+)$', re.IGNORECASE)
# Environment= in units/drop-ins, DefaultEnvironment= in system.conf/user.conf.
# The value may hold several NAME=value assignments; scan_systemd_env splits them.
SYSTEMD_ENV_PATTERN = re.compile(r'^(?:Default)?Environment\s*=\s*(.+)$')
APT_PROXY_PATTERN = re.compile(
    r'Acquire::(?P<proto>https?|ftp)::Proxy(?P<auto>-Auto-Detect)?(?:::(?P<host>[^\s"]+))?'
    r'\s+"(?P<value>[^"]*)"\s*;',
    re.IGNORECASE
)
# containers.conf (podman/buildah): env = ["http_proxy=...", ...]
CONTAINERS_ENV_PATTERN = re.compile(
    r'["\'](' + _PROXY_KEY_ALTERNATION + r')=([^"\']+)["\']',
    re.IGNORECASE
)

CONFIG_FILES = [
    '/etc/environment',
    '/etc/profile',
    '/etc/bashrc',
    '/etc/bash.bashrc',
    '/etc/zshenv',
    '/etc/zprofile',
    '/etc/zshrc',
    '/etc/zsh/zshenv',
    '/etc/zsh/zprofile',
    '/etc/zsh/zshrc',
    '/etc/csh.cshrc',
    '/etc/csh.login',
    '/etc/sysconfig/proxy',
    '/etc/sysconfig/docker',
    '/etc/default/docker',
    '/etc/yum.conf',
    '/etc/dnf/dnf.conf',
    '/etc/rhsm/rhsm.conf',
    '/etc/wgetrc',
    '/etc/curlrc',
    '/etc/gitconfig',
    '/etc/npmrc',
    '/etc/pip.conf',
    '/etc/xdg/pip/pip.conf',
    os.path.expanduser('~/.bashrc'),
    os.path.expanduser('~/.bash_profile'),
    os.path.expanduser('~/.bash_login'),
    os.path.expanduser('~/.profile'),
    os.path.expanduser('~/.zshenv'),
    os.path.expanduser('~/.zprofile'),
    os.path.expanduser('~/.zshrc'),
    os.path.expanduser('~/.cshrc'),
    os.path.expanduser('~/.tcshrc'),
    os.path.expanduser('~/.wgetrc'),
    os.path.expanduser('~/.curlrc'),
    os.path.expanduser('~/.config/.curlrc'),
    os.path.expanduser('~/.gitconfig'),
    os.path.expanduser('~/.config/git/config'),
    os.path.expanduser('~/.npmrc'),
    os.path.expanduser('~/.pip/pip.conf'),
    os.path.expanduser('~/.config/pip/pip.conf'),
]

GLOB_PATTERNS = [
    '/etc/profile.d/*.sh',
    '/etc/profile.d/*.csh',
    '/etc/environment.d/*.conf',
    os.path.expanduser('~/.config/environment.d/*.conf'),
    '/etc/yum.repos.d/*.repo',
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

DOCKER_DAEMON_FILES = [
    '/etc/docker/daemon.json',
]

CONTAINERS_GLOB_PATTERNS = [
    '/usr/share/containers/containers.conf',
    '/etc/containers/containers.conf',
    '/etc/containers/containers.conf.d/*.conf',
    os.path.expanduser('~/.config/containers/containers.conf'),
    os.path.expanduser('~/.config/containers/containers.conf.d/*.conf'),
]

SYSTEMD_GLOB_PATTERNS = [
    '/etc/systemd/system.conf',
    '/etc/systemd/user.conf',
    '/etc/systemd/system.conf.d/*.conf',
    '/etc/systemd/user.conf.d/*.conf',
    '/etc/systemd/system/*.service',
    '/etc/systemd/system/*.service.d/*.conf',
    '/etc/systemd/user/*.service.d/*.conf',
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
                stripped = line.strip()
                if stripped.startswith(('//', '#')):
                    continue
                m = APT_PROXY_PATTERN.search(stripped)
                if m:
                    key = 'Acquire::{}::Proxy{}'.format(m.group('proto'), m.group('auto') or '')
                    if m.group('host'):
                        key += '::' + m.group('host')
                    add_finding(path, key, m.group('value'))
    except OSError:
        pass


def scan_systemd_env(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                m = SYSTEMD_ENV_PATTERN.match(line.strip())
                if not m:
                    continue
                try:
                    assignments = shlex.split(m.group(1))
                except ValueError:
                    assignments = m.group(1).split()
                for assignment in assignments:
                    name, sep, value = assignment.partition('=')
                    if sep and name.lower() in PROXY_VAR_BASE_NAMES:
                        add_finding(path, name, value)
    except OSError:
        pass


def scan_containers_conf(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.lstrip().startswith('#'):
                    continue
                for m in CONTAINERS_ENV_PATTERN.finditer(line):
                    add_finding(path, m.group(1), m.group(2))
    except OSError:
        pass


def _load_json_dict(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def scan_docker_config(path):
    data = _load_json_dict(path)
    if data is None:
        return
    for cfg in data.get('proxies', {}).values():
        if not isinstance(cfg, dict):
            continue
        for key in ('httpProxy', 'httpsProxy', 'ftpProxy', 'noProxy'):
            value = cfg.get(key)
            if value:
                add_finding(path, key, str(value))


def scan_docker_daemon(path):
    """/etc/docker/daemon.json (Docker 23+): {"proxies": {"http-proxy": ...}}."""
    data = _load_json_dict(path)
    if data is None:
        return
    proxies = data.get('proxies')
    if not isinstance(proxies, dict):
        return
    for key in ('http-proxy', 'https-proxy', 'no-proxy'):
        value = proxies.get(key)
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


_CSH_SUFFIXES = ('.csh', 'csh.cshrc', 'csh.login', '.cshrc', '.tcshrc')


def route_file(path):
    lower = path.lower()
    if lower.endswith(('/yum.conf', '/dnf.conf', '.repo')):
        scan_pattern_lines(path, YUM_DNF_PATTERN)
    elif lower.endswith('/rhsm.conf'):
        scan_pattern_lines(path, RHSM_PATTERN)
    elif lower.endswith('wgetrc'):
        scan_pattern_lines(path, WGET_PATTERN)
    elif lower.endswith('curlrc'):
        scan_pattern_lines(path, CURL_PATTERN)
    elif lower.endswith('ansible.cfg'):
        scan_pattern_lines(path, ANSIBLE_PATTERN)
    elif lower.endswith(('gitconfig', '/git/config')):
        scan_pattern_lines(path, GIT_PATTERN)
    elif lower.endswith('npmrc'):
        scan_pattern_lines(path, NPM_PATTERN)
    elif lower.endswith(('pip.conf', 'pip.ini')):
        scan_pattern_lines(path, PIP_PATTERN)
    elif lower.endswith(_CSH_SUFFIXES):
        scan_pattern_lines(path, CSH_SETENV_PATTERN)
    else:
        scan_pattern_lines(path, PROXY_PATTERN)


def collect_maven_files():
    candidates = list(MAVEN_SETTINGS_FILES)
    for home in MAVEN_HOME_CANDIDATES:
        if home:
            candidates.append(os.path.join(home, 'conf', 'settings.xml'))
    return candidates


def expand_globs(files, patterns):
    paths = list(files)
    for pattern in patterns:
        paths.extend(sorted(glob.glob(pattern)))
    return paths


_NON_ACTIVE_KEY_MARKERS = {'no_proxy', 'noproxy', 'no-proxy'}

# Values that explicitly switch the proxy off: '_none_' in yum .repo files,
# "DIRECT" in apt (Acquire::http::Proxy::host "DIRECT";).
_NON_ACTIVE_VALUES = {'_none_', 'direct'}


def is_real_proxy_key(key):
    """no_proxy / nonProxyHosts are exclusion lists, not an active proxy setting."""
    k = key.lower()
    if k in _NON_ACTIVE_KEY_MARKERS:
        return False
    return not k.endswith('nonproxyhosts')


def is_real_proxy(finding):
    return is_real_proxy_key(finding.key) and finding.value.lower() not in _NON_ACTIVE_VALUES


def main():
    hostname = socket.gethostname()

    check_env()

    # (paths, scanner) in scan order. A file is read only once, even if several
    # paths lead to it: on RHEL/CentOS 8+ /etc/yum.conf is a symlink to
    # /etc/dnf/dnf.conf, which would otherwise report every entry twice.
    sources = [
        (expand_globs(CONFIG_FILES, GLOB_PATTERNS), route_file),
        (collect_maven_files(), scan_maven_settings),
        (ANSIBLE_CFG_FILES, route_file),
        (expand_globs(APT_CONFIG_FILES, APT_GLOB_PATTERNS), scan_apt_conf),
        (DOCKER_CONFIG_FILES, scan_docker_config),
        (DOCKER_DAEMON_FILES, scan_docker_daemon),
        (expand_globs([], CONTAINERS_GLOB_PATTERNS), scan_containers_conf),
        (expand_globs([], SYSTEMD_GLOB_PATTERNS), scan_systemd_env),
    ]

    seen = set()
    for paths, scanner in sources:
        for path in paths:
            real = os.path.realpath(path)
            if real not in seen:
                seen.add(real)
                scanner(path)

    print(f"=== PROXY SCAN REPORT: {hostname} ===")

    has_real_proxy = any(is_real_proxy(f) for f in findings)

    print("RESULT: PROXY_FOUND" if has_real_proxy else "RESULT: NO_PROXY_FOUND")

    for f in sorted(findings, key=lambda f: (f.source, f.key)):
        print(f"SOURCE={f.source} KEY={f.key} VALUE={f.value}")

    return 1 if has_real_proxy else 0


if __name__ == '__main__':
    raise SystemExit(main())
