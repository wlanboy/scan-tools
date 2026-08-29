#!/usr/bin/env python3
"""
test_scan_proxy.py — Unit-Tests für scan-proxy.py

Teststruktur:
  - Jede Testklasse deckt genau eine Funktion oder einen zusammengehörigen
    Satz von Regex-Mustern ab.
  - Jede Testmethode enthält einen Docstring mit Ziel, Eingabe und Erwartung.

Ausführung:
  python3 -m pytest test_scan_proxy.py -v
  python3 -m unittest discover -v
"""

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

# scan-proxy.py enthält einen Bindestrich im Dateinamen und kann daher nicht
# direkt mit 'import' geladen werden — importlib übernimmt das manuell.
_spec = importlib.util.spec_from_file_location(
    "scan_proxy",
    pathlib.Path(__file__).parent / "scan-proxy.py",
)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
sys.modules["scan_proxy"] = _mod
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

PROXY_KEYS           = _mod.PROXY_KEYS
PROXY_PATTERN        = _mod.PROXY_PATTERN
YUM_DNF_PATTERN      = _mod.YUM_DNF_PATTERN
WGET_PATTERN         = _mod.WGET_PATTERN
CURL_PATTERN         = _mod.CURL_PATTERN
ANSIBLE_PATTERN      = _mod.ANSIBLE_PATTERN
GIT_PATTERN          = _mod.GIT_PATTERN
NPM_PATTERN          = _mod.NPM_PATTERN
PIP_PATTERN          = _mod.PIP_PATTERN
SYSTEMD_ENV_PATTERN  = _mod.SYSTEMD_ENV_PATTERN
APT_PROXY_PATTERN    = _mod.APT_PROXY_PATTERN
Finding              = _mod.Finding
add_finding          = _mod.add_finding
check_env            = _mod.check_env
scan_pattern_lines   = _mod.scan_pattern_lines
scan_apt_conf        = _mod.scan_apt_conf
scan_docker_config   = _mod.scan_docker_config
scan_maven_settings  = _mod.scan_maven_settings
route_file           = _mod.route_file
collect_maven_files  = _mod.collect_maven_files
is_real_proxy_key    = _mod.is_real_proxy_key
main                 = _mod.main


def _clean_environ():
    """Kopie von os.environ ohne jegliche Proxy-Variablen (Groß-/Kleinschreibung egal)."""
    lowered_proxy_keys = {k.lower() for k in PROXY_KEYS}
    return {k: v for k, v in os.environ.items() if k.lower() not in lowered_proxy_keys}


class ScanProxyTestCase(unittest.TestCase):
    """Basisklasse: leert die globale findings-Liste vor jedem Test.

    scan-proxy.py sammelt Befunde in einer modulweiten Liste statt sie
    zurückzugeben — ohne Reset würden Befunde aus vorherigen Tests
    fälschlich in nachfolgenden Tests auftauchen.
    """

    def setUp(self):
        _mod.findings.clear()


# ===========================================================================
# Klasse 1: Tests für add_finding()
# ===========================================================================

class TestAddFinding(ScanProxyTestCase):
    """Testet add_finding(), die zentrale Sammelstelle für alle Befunde."""

    def test_valid_value_appended(self):
        """
        Ziel: Ein Befund mit nicht-leerem Wert soll der findings-Liste hinzugefügt werden.

        Eingabe: source='ENV', key='http_proxy', value='http://proxy.example.com:8080'.

        Erwartung: Genau ein Finding mit exakt diesen Feldern.
        """
        add_finding('ENV', 'http_proxy', 'http://proxy.example.com:8080')
        self.assertEqual(_mod.findings, [Finding('ENV', 'http_proxy', 'http://proxy.example.com:8080')])

    def test_value_is_stripped(self):
        """
        Ziel: Führende/nachgestellte Leerzeichen im Wert sollen entfernt werden,
              damit z. B. Konfigurationszeilen mit Einrückung sauber verglichen werden können.

        Eingabe: value='  http://proxy.example.com:8080  '.

        Erwartung: Der gespeicherte Wert ist getrimmt.
        """
        add_finding('ENV', 'http_proxy', '  http://proxy.example.com:8080  ')
        self.assertEqual(_mod.findings[0].value, 'http://proxy.example.com:8080')

    def test_empty_value_not_appended(self):
        """
        Ziel: Ein leerer (oder nur aus Whitespace bestehender) Wert soll keinen
              Befund erzeugen — sonst würde z. B. 'http_proxy=' einen Fund melden,
              obwohl kein Proxy konfiguriert ist.

        Eingabe: value='   '.

        Erwartung: Keine Einträge in findings.
        """
        add_finding('ENV', 'http_proxy', '   ')
        self.assertEqual(_mod.findings, [])


# ===========================================================================
# Klasse 2: Tests für check_env()
# ===========================================================================

class TestCheckEnv(ScanProxyTestCase):
    """Testet check_env(), das Umgebungsvariablen auf Proxy-Einstellungen prüft."""

    def test_lower_and_upper_case_env_var_found(self):
        """
        Ziel: Sowohl 'http_proxy' als auch 'HTTP_PROXY' sollen erkannt werden,
              da beide Schreibweisen in der Praxis vorkommen (POSIX-Konvention
              ist lowercase, viele Tools nutzen aber UPPERCASE).

        Eingabe: os.environ mit http_proxy und HTTPS_PROXY gesetzt.

        Erwartung: Zwei ENV-Befunde mit den jeweiligen Werten.
        """
        env = _clean_environ()
        env['http_proxy'] = 'http://proxy.example.com:8080'
        env['HTTPS_PROXY'] = 'http://proxy.example.com:8443'
        with mock.patch.dict(os.environ, env, clear=True):
            check_env()
        keys = {f.key: f.value for f in _mod.findings}
        self.assertEqual(keys.get('http_proxy'), 'http://proxy.example.com:8080')
        self.assertEqual(keys.get('HTTPS_PROXY'), 'http://proxy.example.com:8443')

    def test_no_proxy_env_vars_no_findings(self):
        """
        Ziel: Wenn keine Proxy-Umgebungsvariablen gesetzt sind, sollen keine
              ENV-Befunde erzeugt werden.

        Eingabe: os.environ ohne jegliche Proxy-Variable.

        Erwartung: Leere findings-Liste.
        """
        with mock.patch.dict(os.environ, _clean_environ(), clear=True):
            check_env()
        self.assertEqual(_mod.findings, [])


# ===========================================================================
# Klasse 3: Tests für PROXY_PATTERN (generisches shell-style KEY=VALUE)
# ===========================================================================

class TestProxyPattern(unittest.TestCase):
    """Testet PROXY_PATTERN, das generische Muster für shell-style Proxy-Zuweisungen."""

    def test_simple_assignment(self):
        """
        Ziel: Eine einfache Zuweisung ohne 'export' und ohne Anführungszeichen
              soll erkannt werden.

        Eingabe: 'http_proxy=http://proxy.example.com:8080'.

        Erwartung: Match mit key='http_proxy', value='http://proxy.example.com:8080'.
        """
        m = PROXY_PATTERN.match('http_proxy=http://proxy.example.com:8080')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'http_proxy')
        self.assertEqual(m.group(2), 'http://proxy.example.com:8080')

    def test_export_with_double_quotes(self):
        """
        Ziel: 'export KEY="value"' ist die übliche Form in /etc/profile-artigen
              Dateien und soll erkannt werden, ohne die Anführungszeichen im Wert
              zu behalten.

        Eingabe: 'export HTTPS_PROXY="http://proxy.example.com:8443"'.

        Erwartung: Match mit key='HTTPS_PROXY', value ohne die umschließenden Quotes.
        """
        m = PROXY_PATTERN.match('export HTTPS_PROXY="http://proxy.example.com:8443"')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'HTTPS_PROXY')
        self.assertEqual(m.group(2), 'http://proxy.example.com:8443')

    def test_case_insensitive_key(self):
        """
        Ziel: Der Variablenname soll unabhängig von der Groß-/Kleinschreibung
              erkannt werden.

        Eingabe: 'ALL_PROXY=socks5://127.0.0.1:1080'.

        Erwartung: Match, key='ALL_PROXY'.
        """
        m = PROXY_PATTERN.match('ALL_PROXY=socks5://127.0.0.1:1080')
        self.assertIsNotNone(m)

    def test_comment_line_no_match(self):
        """
        Ziel: Eine auskommentierte Zeile soll nicht als aktive Konfiguration
              erkannt werden.

        Eingabe: '# http_proxy=http://proxy.example.com:8080'.

        Erwartung: Kein Match.
        """
        m = PROXY_PATTERN.match('# http_proxy=http://proxy.example.com:8080')
        self.assertIsNone(m)

    def test_unrelated_line_no_match(self):
        """
        Ziel: Zeilen ohne Bezug zu Proxy-Variablen sollen nicht matchen.

        Eingabe: 'PATH=/usr/local/bin:/usr/bin'.

        Erwartung: Kein Match.
        """
        m = PROXY_PATTERN.match('PATH=/usr/local/bin:/usr/bin')
        self.assertIsNone(m)


# ===========================================================================
# Klasse 4: Tests für die werkzeugspezifischen Patterns
# ===========================================================================

class TestToolSpecificPatterns(unittest.TestCase):
    """
    Testet die Regex-Muster für einzelne Tool-Konfigurationsformate
    (yum/dnf, wget, curl, ansible, git, npm, pip, systemd, apt).
    """

    def test_yum_dnf_pattern_proxy_key(self):
        """
        Ziel: yum.conf/dnf.conf verwenden 'proxy=<url>' im INI-Stil.

        Eingabe: 'proxy=http://proxy.example.com:8080'.

        Erwartung: Match mit key='proxy'.
        """
        m = YUM_DNF_PATTERN.match('proxy=http://proxy.example.com:8080')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'proxy')

    def test_yum_dnf_pattern_proxy_username(self):
        """
        Ziel: yum.conf erlaubt auch 'proxy_username' und 'proxy_password'.

        Eingabe: 'proxy_username=svc-account'.

        Erwartung: Match mit key='proxy_username'.
        """
        m = YUM_DNF_PATTERN.match('proxy_username=svc-account')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'proxy_username')

    def test_wget_pattern(self):
        """
        Ziel: .wgetrc verwendet 'https_proxy = <url>' (mit optionalen Leerzeichen
              um das Gleichheitszeichen).

        Eingabe: 'https_proxy = http://proxy.example.com:8080'.

        Erwartung: Match mit key='https_proxy'.
        """
        m = WGET_PATTERN.match('https_proxy = http://proxy.example.com:8080')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'https_proxy')

    def test_curl_pattern(self):
        """
        Ziel: .curlrc verwendet 'proxy = <url>'.

        Eingabe: 'proxy = http://proxy.example.com:8080'.

        Erwartung: Match mit key='proxy'.
        """
        m = CURL_PATTERN.match('proxy = http://proxy.example.com:8080')
        self.assertIsNotNone(m)

    def test_ansible_pattern_generic_proxy_key(self):
        """
        Ziel: ansible.cfg erlaubt sowohl 'http_proxy' als auch das generische
              'proxy'.

        Eingabe: 'proxy=http://proxy.example.com:8080'.

        Erwartung: Match mit key='proxy'.
        """
        m = ANSIBLE_PATTERN.match('proxy=http://proxy.example.com:8080')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'proxy')

    def test_git_pattern(self):
        """
        Ziel: .gitconfig verwendet innerhalb von [http]/[https]-Sektionen
              'proxy = <url>'.

        Eingabe: 'proxy = http://proxy.example.com:8080'.

        Erwartung: Match mit key='proxy'.
        """
        m = GIT_PATTERN.match('proxy = http://proxy.example.com:8080')
        self.assertIsNotNone(m)

    def test_npm_pattern_https_proxy(self):
        """
        Ziel: .npmrc verwendet Bindestrich-Schreibweise 'https-proxy'.

        Eingabe: 'https-proxy=http://proxy.example.com:8080'.

        Erwartung: Match mit key='https-proxy'.
        """
        m = NPM_PATTERN.match('https-proxy=http://proxy.example.com:8080')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'https-proxy')

    def test_npm_pattern_noproxy(self):
        """
        Ziel: .npmrc erlaubt auch 'noproxy' (ohne Unterstrich) als Ausschlussliste.

        Eingabe: 'noproxy=localhost,127.0.0.1'.

        Erwartung: Match mit key='noproxy'.
        """
        m = NPM_PATTERN.match('noproxy=localhost,127.0.0.1')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'noproxy')

    def test_pip_pattern(self):
        """
        Ziel: pip.conf verwendet innerhalb von [global] 'proxy = <url>'.

        Eingabe: 'proxy = http://proxy.example.com:8080'.

        Erwartung: Match mit key='proxy'.
        """
        m = PIP_PATTERN.match('proxy = http://proxy.example.com:8080')
        self.assertIsNotNone(m)

    def test_systemd_env_pattern(self):
        """
        Ziel: systemd-Unit-Drop-ins setzen Proxys über
              'Environment="HTTP_PROXY=<url>"'.

        Eingabe: 'Environment="HTTP_PROXY=http://proxy.example.com:8080"'.

        Erwartung: Match mit group(1)='HTTP_PROXY', group(2) die URL.
        """
        m = SYSTEMD_ENV_PATTERN.match('Environment="HTTP_PROXY=http://proxy.example.com:8080"')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'HTTP_PROXY')
        self.assertEqual(m.group(2), 'http://proxy.example.com:8080')

    def test_apt_proxy_pattern(self):
        """
        Ziel: apt.conf verwendet die C++-artige Syntax
              'Acquire::http::Proxy "<url>";'.

        Eingabe: 'Acquire::http::Proxy "http://proxy.example.com:3128";'.

        Erwartung: Match mit group(1)='http' (Protokoll), group(2) die URL.
        """
        m = APT_PROXY_PATTERN.search('Acquire::http::Proxy "http://proxy.example.com:3128";')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'http')
        self.assertEqual(m.group(2), 'http://proxy.example.com:3128')


# ===========================================================================
# Klasse 5: Tests für is_real_proxy_key()
# ===========================================================================

class TestIsRealProxyKey(unittest.TestCase):
    """
    Testet is_real_proxy_key(), das Ausschlusslisten (no_proxy, nonProxyHosts)
    von tatsächlich aktiven Proxy-Einstellungen unterscheidet. Diese Unterscheidung
    ist wichtig, weil no_proxy typischerweise gesetzt ist, ohne dass überhaupt
    ein Proxy verwendet wird — würde man es mitzählen, gäbe es viele False Positives.
    """

    def test_http_proxy_is_real(self):
        """
        Ziel: 'http_proxy' ist eine echte Proxy-Einstellung.

        Erwartung: True.
        """
        self.assertTrue(is_real_proxy_key('http_proxy'))

    def test_no_proxy_is_not_real(self):
        """
        Ziel: 'no_proxy' ist eine Ausschlussliste, kein aktiver Proxy.

        Erwartung: False.
        """
        self.assertFalse(is_real_proxy_key('no_proxy'))

    def test_no_proxy_case_insensitive(self):
        """
        Ziel: Die Erkennung von 'no_proxy' soll unabhängig von der
              Groß-/Kleinschreibung funktionieren.

        Eingabe: 'NO_PROXY'.

        Erwartung: False.
        """
        self.assertFalse(is_real_proxy_key('NO_PROXY'))

    def test_noproxy_without_underscore_is_not_real(self):
        """
        Ziel: Auch die npm-Schreibweise 'noproxy' (ohne Unterstrich) soll als
              Ausschlussliste erkannt werden.

        Erwartung: False.
        """
        self.assertFalse(is_real_proxy_key('noproxy'))

    def test_no_proxy_with_hyphen_is_not_real(self):
        """
        Ziel: 'no-proxy' (Bindestrich-Variante) soll ebenfalls ausgeschlossen werden.

        Erwartung: False.
        """
        self.assertFalse(is_real_proxy_key('no-proxy'))

    def test_nonproxyhosts_suffix_is_not_real(self):
        """
        Ziel: Maven-Schlüssel wie 'proxy.nonProxyHosts' sind ebenfalls
              Ausschlusslisten und sollen anhand des Suffix erkannt werden.

        Eingabe: 'proxy.nonProxyHosts'.

        Erwartung: False.
        """
        self.assertFalse(is_real_proxy_key('proxy.nonProxyHosts'))

    def test_proxy_host_is_real(self):
        """
        Ziel: 'proxy.host' (Ziel-Host eines aktiven Proxys) ist keine
              Ausschlussliste und soll als echt gelten.

        Erwartung: True.
        """
        self.assertTrue(is_real_proxy_key('proxy.host'))


# ===========================================================================
# Klasse 6: Tests für scan_pattern_lines()
# ===========================================================================

class TestScanPatternLines(ScanProxyTestCase):
    """Testet scan_pattern_lines(), den generischen zeilenbasierten Datei-Scanner."""

    def test_matching_line_produces_finding(self):
        """
        Ziel: Eine Zeile, die dem übergebenen Pattern entspricht, soll einen
              Befund mit dem Dateipfad als source erzeugen.

        Eingabe: Datei mit 'http_proxy=http://proxy.example.com:8080'.

        Erwartung: Ein Finding mit source=Dateipfad, key='http_proxy'.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'envfile')
            with open(path, 'w') as f:
                f.write('http_proxy=http://proxy.example.com:8080\n')
            scan_pattern_lines(path, PROXY_PATTERN)
        self.assertEqual(len(_mod.findings), 1)
        self.assertEqual(_mod.findings[0].source, path)
        self.assertEqual(_mod.findings[0].key, 'http_proxy')

    def test_value_quotes_and_whitespace_stripped(self):
        """
        Ziel: Anführungszeichen und Whitespace um den Wert sollen entfernt werden,
              damit z. B. '"http://x" ' und 'http://x' als derselbe Wert erkannt werden.

        Eingabe: "  proxy = 'http://proxy.example.com:8080'  " unter YUM_DNF_PATTERN.

        Erwartung: value ohne Quotes/Whitespace.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'yum.conf')
            with open(path, 'w') as f:
                f.write("proxy = 'http://proxy.example.com:8080'\n")
            scan_pattern_lines(path, YUM_DNF_PATTERN)
        self.assertEqual(_mod.findings[0].value, 'http://proxy.example.com:8080')

    def test_non_matching_lines_ignored(self):
        """
        Ziel: Zeilen ohne Treffer sollen keine Befunde erzeugen.

        Eingabe: Datei mit nur Kommentaren und unrelated Zeilen.

        Erwartung: Leere findings-Liste.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'envfile')
            with open(path, 'w') as f:
                f.write('# just a comment\nPATH=/usr/bin\n')
            scan_pattern_lines(path, PROXY_PATTERN)
        self.assertEqual(_mod.findings, [])

    def test_missing_file_no_crash(self):
        """
        Ziel: Eine nicht existierende Datei soll den Scan nicht abbrechen lassen —
              viele der in CONFIG_FILES gelisteten Pfade existieren auf einem
              gegebenen System oft nicht.

        Eingabe: Pfad zu einer nicht existierenden Datei.

        Erwartung: Keine Exception, leere findings-Liste.
        """
        scan_pattern_lines('/nonexistent/path/does-not-exist', PROXY_PATTERN)
        self.assertEqual(_mod.findings, [])

    def test_multiple_matching_lines(self):
        """
        Ziel: Mehrere passende Zeilen in derselben Datei sollen jeweils einen
              eigenen Befund erzeugen.

        Eingabe: Datei mit http_proxy und https_proxy.

        Erwartung: Zwei Findings.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'envfile')
            with open(path, 'w') as f:
                f.write('http_proxy=http://proxy.example.com:8080\n')
                f.write('https_proxy=http://proxy.example.com:8443\n')
            scan_pattern_lines(path, PROXY_PATTERN)
        self.assertEqual(len(_mod.findings), 2)


# ===========================================================================
# Klasse 7: Tests für route_file()
# ===========================================================================

class TestRouteFile(unittest.TestCase):
    """
    Testet route_file(), das anhand des Dateinamens das passende Regex-Muster
    auswählt. Statt echte Dateien zu scannen, wird scan_pattern_lines gemockt
    und nur geprüft, welches Pattern für welchen Dateinamen ausgewählt wird —
    das Verhalten der Patterns selbst ist bereits in TestToolSpecificPatterns
    abgedeckt.
    """

    def _routed_pattern(self, path):
        with mock.patch.object(_mod, 'scan_pattern_lines') as mocked:
            route_file(path)
            mocked.assert_called_once()
            called_path, called_pattern = mocked.call_args[0]
            self.assertEqual(called_path, path)
            return called_pattern

    def test_yum_conf_routes_to_yum_dnf_pattern(self):
        """
        Ziel: '/etc/yum.conf' soll an YUM_DNF_PATTERN geroutet werden.

        Erwartung: Aufruf von scan_pattern_lines mit YUM_DNF_PATTERN.
        """
        self.assertIs(self._routed_pattern('/etc/yum.conf'), YUM_DNF_PATTERN)

    def test_dnf_conf_routes_to_yum_dnf_pattern(self):
        """
        Ziel: '/etc/dnf/dnf.conf' soll ebenfalls an YUM_DNF_PATTERN geroutet werden,
              da dnf das Nachfolgeformat von yum ist.

        Erwartung: Aufruf mit YUM_DNF_PATTERN.
        """
        self.assertIs(self._routed_pattern('/etc/dnf/dnf.conf'), YUM_DNF_PATTERN)

    def test_wgetrc_routes_to_wget_pattern(self):
        """
        Ziel: Eine Datei, die auf 'wgetrc' endet, soll an WGET_PATTERN geroutet werden.

        Erwartung: Aufruf mit WGET_PATTERN.
        """
        self.assertIs(self._routed_pattern('/home/user/.wgetrc'), WGET_PATTERN)

    def test_curlrc_routes_to_curl_pattern(self):
        """
        Ziel: Eine Datei, die auf 'curlrc' endet, soll an CURL_PATTERN geroutet werden.

        Erwartung: Aufruf mit CURL_PATTERN.
        """
        self.assertIs(self._routed_pattern('/home/user/.curlrc'), CURL_PATTERN)

    def test_ansible_cfg_routes_to_ansible_pattern(self):
        """
        Ziel: 'ansible.cfg' soll an ANSIBLE_PATTERN geroutet werden.

        Erwartung: Aufruf mit ANSIBLE_PATTERN.
        """
        self.assertIs(self._routed_pattern('./ansible.cfg'), ANSIBLE_PATTERN)

    def test_gitconfig_routes_to_git_pattern(self):
        """
        Ziel: 'gitconfig' soll an GIT_PATTERN geroutet werden.

        Erwartung: Aufruf mit GIT_PATTERN.
        """
        self.assertIs(self._routed_pattern('/home/user/.gitconfig'), GIT_PATTERN)

    def test_npmrc_routes_to_npm_pattern(self):
        """
        Ziel: 'npmrc' soll an NPM_PATTERN geroutet werden.

        Erwartung: Aufruf mit NPM_PATTERN.
        """
        self.assertIs(self._routed_pattern('/home/user/.npmrc'), NPM_PATTERN)

    def test_pip_conf_routes_to_pip_pattern(self):
        """
        Ziel: 'pip.conf' soll an PIP_PATTERN geroutet werden.

        Erwartung: Aufruf mit PIP_PATTERN.
        """
        self.assertIs(self._routed_pattern('/home/user/.pip/pip.conf'), PIP_PATTERN)

    def test_unknown_file_falls_back_to_generic_pattern(self):
        """
        Ziel: Ein unbekannter Dateiname (z. B. /etc/environment) soll auf das
              generische PROXY_PATTERN zurückfallen.

        Erwartung: Aufruf mit PROXY_PATTERN.
        """
        self.assertIs(self._routed_pattern('/etc/environment'), PROXY_PATTERN)

    def test_routing_is_case_insensitive(self):
        """
        Ziel: Die Dateinamens-Erkennung soll unabhängig von der Groß-/
              Kleinschreibung funktionieren (z. B. auf case-insensitive
              Dateisystemen oder bei Tippfehlern in der Konfiguration).

        Eingabe: '/ETC/YUM.CONF'.

        Erwartung: Aufruf mit YUM_DNF_PATTERN.
        """
        self.assertIs(self._routed_pattern('/ETC/YUM.CONF'), YUM_DNF_PATTERN)


# ===========================================================================
# Klasse 8: Tests für scan_apt_conf()
# ===========================================================================

class TestScanAptConf(ScanProxyTestCase):
    """Testet scan_apt_conf(), den Scanner für die apt.conf-C++-Syntax."""

    def test_http_and_https_proxy_found(self):
        """
        Ziel: Sowohl Acquire::http::Proxy als auch Acquire::https::Proxy sollen
              als eigene Befunde erkannt werden.

        Eingabe: apt.conf mit beiden Zeilen.

        Erwartung: Zwei Findings mit key='Acquire::http::Proxy' bzw.
                   'Acquire::https::Proxy'.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'apt.conf')
            with open(path, 'w') as f:
                f.write('Acquire::http::Proxy "http://proxy.example.com:3128";\n')
                f.write('Acquire::https::Proxy "http://proxy.example.com:3128";\n')
            scan_apt_conf(path)
        keys = {f.key: f.value for f in _mod.findings}
        self.assertEqual(keys.get('Acquire::http::Proxy'), 'http://proxy.example.com:3128')
        self.assertEqual(keys.get('Acquire::https::Proxy'), 'http://proxy.example.com:3128')

    def test_non_matching_lines_ignored(self):
        """
        Ziel: Andere apt.conf-Direktiven ohne Proxy-Bezug sollen ignoriert werden.

        Eingabe: 'APT::Install-Recommends "false";'.

        Erwartung: Keine Findings.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'apt.conf')
            with open(path, 'w') as f:
                f.write('APT::Install-Recommends "false";\n')
            scan_apt_conf(path)
        self.assertEqual(_mod.findings, [])

    def test_missing_file_no_crash(self):
        """
        Ziel: Eine fehlende apt.conf.d-Drop-in-Datei soll den Scan nicht abbrechen.

        Erwartung: Keine Exception, keine Findings.
        """
        scan_apt_conf('/nonexistent/apt.conf')
        self.assertEqual(_mod.findings, [])


# ===========================================================================
# Klasse 9: Tests für scan_docker_config()
# ===========================================================================

class TestScanDockerConfig(ScanProxyTestCase):
    """
    Testet scan_docker_config(), den Scanner für ~/.docker/config.json.

    Das Format ist {"proxies": {"<context-name>": {"httpProxy": ..., ...}}} —
    ein context-name (z. B. "default") kann mehrere Konfigurationswerte haben.
    """

    def test_proxies_dict_found(self):
        """
        Ziel: httpProxy/httpsProxy/noProxy innerhalb eines benannten Kontexts
              sollen als eigene Befunde erkannt werden.

        Eingabe: {"proxies": {"default": {"httpProxy": "...", "httpsProxy": "...",
                  "noProxy": "localhost,127.0.0.1"}}}.

        Erwartung: Drei Findings (httpProxy, httpsProxy, noProxy), ftpProxy fehlt
                   und erzeugt keinen Befund.
        """
        data = {
            "proxies": {
                "default": {
                    "httpProxy": "http://proxy.example.com:3128",
                    "httpsProxy": "http://proxy.example.com:3128",
                    "noProxy": "localhost,127.0.0.1",
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'config.json')
            with open(path, 'w') as f:
                json.dump(data, f)
            scan_docker_config(path)
        keys = {f.key for f in _mod.findings}
        self.assertEqual(keys, {'httpProxy', 'httpsProxy', 'noProxy'})

    def test_non_dict_context_config_skipped(self):
        """
        Ziel: Ist der Wert eines Kontexts kein Objekt (defensiv gegen
              unerwartete/kaputte config.json-Strukturen), soll er übersprungen
              werden statt einen Fehler auszulösen.

        Eingabe: {"proxies": {"default": "not-a-dict"}}.

        Erwartung: Keine Findings, kein Crash.
        """
        data = {"proxies": {"default": "not-a-dict"}}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'config.json')
            with open(path, 'w') as f:
                json.dump(data, f)
            scan_docker_config(path)
        self.assertEqual(_mod.findings, [])

    def test_top_level_not_dict_no_crash(self):
        """
        Ziel: Ist die gesamte Datei kein JSON-Objekt (z. B. ein Array), soll
              der Scanner ohne Findings zurückkehren statt abzustürzen.

        Eingabe: JSON-Array statt Objekt.

        Erwartung: Keine Findings, kein Crash.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'config.json')
            with open(path, 'w') as f:
                json.dump([1, 2, 3], f)
            scan_docker_config(path)
        self.assertEqual(_mod.findings, [])

    def test_invalid_json_no_crash(self):
        """
        Ziel: Ungültiges JSON soll keinen Absturz verursachen.

        Erwartung: Keine Findings, kein Crash.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'config.json')
            with open(path, 'w') as f:
                f.write('{ not valid json ]')
            scan_docker_config(path)
        self.assertEqual(_mod.findings, [])

    def test_missing_file_no_crash(self):
        """
        Ziel: Ein fehlendes ~/.docker/config.json (häufigster Fall, wenn Docker
              nie mit einem Proxy konfiguriert wurde) soll keinen Absturz verursachen.

        Erwartung: Keine Findings, kein Crash.
        """
        scan_docker_config('/nonexistent/.docker/config.json')
        self.assertEqual(_mod.findings, [])

    def test_no_proxies_key_no_findings(self):
        """
        Ziel: Ein config.json ohne 'proxies'-Schlüssel (der Normalfall) soll
              keine Findings erzeugen.

        Eingabe: {"auths": {}}.

        Erwartung: Keine Findings.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'config.json')
            with open(path, 'w') as f:
                json.dump({"auths": {}}, f)
            scan_docker_config(path)
        self.assertEqual(_mod.findings, [])


# ===========================================================================
# Klasse 10: Tests für scan_maven_settings()
# ===========================================================================

class TestScanMavenSettings(ScanProxyTestCase):
    """
    Testet scan_maven_settings(), den XML-Scanner für ~/.m2/settings.xml.

    Wichtige Regel: Maven behandelt einen <proxy> als aktiv, wenn <active>
    fehlt — nur ein explizites 'false' deaktiviert ihn.
    """

    def _write(self, tmp, content):
        path = os.path.join(tmp, 'settings.xml')
        with open(path, 'w') as f:
            f.write(content)
        return path

    def test_proxy_without_active_tag_counts_as_active(self):
        """
        Ziel: Ein <proxy>-Eintrag ohne <active>-Element gilt als aktiv,
              weil Maven dies so behandelt. Würde man das ignorieren, würden
              reale konfigurierte Proxys übersehen.

        Eingabe: <proxy> ohne <active>, mit host/port/protocol.

        Erwartung: Findings für proxy.host, proxy.port, proxy.protocol.
        """
        xml = """<settings>
          <proxies>
            <proxy>
              <host>proxy.example.com</host>
              <port>8080</port>
              <protocol>http</protocol>
            </proxy>
          </proxies>
        </settings>"""
        with tempfile.TemporaryDirectory() as tmp:
            scan_maven_settings(self._write(tmp, xml))
        keys = {f.key: f.value for f in _mod.findings}
        self.assertEqual(keys.get('proxy.host'), 'proxy.example.com')
        self.assertEqual(keys.get('proxy.port'), '8080')
        self.assertEqual(keys.get('proxy.protocol'), 'http')

    def test_explicit_active_false_skipped(self):
        """
        Ziel: Ein explizit deaktivierter Proxy (<active>false</active>) soll
              nicht als Befund gemeldet werden — er ist Teil der Konfiguration,
              aber gerade nicht wirksam.

        Eingabe: <proxy><active>false</active><host>disabled.example.com</host>...

        Erwartung: Keine Findings für diesen Proxy.
        """
        xml = """<settings>
          <proxies>
            <proxy>
              <active>false</active>
              <host>disabled.example.com</host>
            </proxy>
          </proxies>
        </settings>"""
        with tempfile.TemporaryDirectory() as tmp:
            scan_maven_settings(self._write(tmp, xml))
        self.assertEqual(_mod.findings, [])

    def test_explicit_active_true_counts(self):
        """
        Ziel: Ein explizit aktivierter Proxy (<active>true</active>) soll
              als Befund gemeldet werden.

        Erwartung: Finding für proxy.host.
        """
        xml = """<settings>
          <proxies>
            <proxy>
              <active>true</active>
              <host>active.example.com</host>
            </proxy>
          </proxies>
        </settings>"""
        with tempfile.TemporaryDirectory() as tmp:
            scan_maven_settings(self._write(tmp, xml))
        keys = {f.key: f.value for f in _mod.findings}
        self.assertEqual(keys.get('proxy.host'), 'active.example.com')

    def test_namespaced_settings_xml(self):
        """
        Ziel: settings.xml-Dateien mit dem offiziellen Maven-Namespace
              (xmlns="http://maven.apache.org/SETTINGS/1.0.0") sollen genauso
              erkannt werden wie Dateien ohne Namespace.

        Eingabe: <settings xmlns="..."> mit einem aktiven Proxy.

        Erwartung: Finding für proxy.host.
        """
        xml = """<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
          <proxies>
            <proxy>
              <host>ns-proxy.example.com</host>
            </proxy>
          </proxies>
        </settings>"""
        with tempfile.TemporaryDirectory() as tmp:
            scan_maven_settings(self._write(tmp, xml))
        keys = {f.key: f.value for f in _mod.findings}
        self.assertEqual(keys.get('proxy.host'), 'ns-proxy.example.com')

    def test_multiple_fields_including_username_and_nonproxyhosts(self):
        """
        Ziel: Alle relevanten Unterfelder (username, nonProxyHosts) sollen
              zusätzlich zu host/port/protocol erkannt werden.

        Erwartung: Findings für proxy.username und proxy.nonProxyHosts.
        """
        xml = """<settings>
          <proxies>
            <proxy>
              <host>proxy.example.com</host>
              <username>svc-account</username>
              <nonProxyHosts>localhost|127.0.0.1</nonProxyHosts>
            </proxy>
          </proxies>
        </settings>"""
        with tempfile.TemporaryDirectory() as tmp:
            scan_maven_settings(self._write(tmp, xml))
        keys = {f.key: f.value for f in _mod.findings}
        self.assertEqual(keys.get('proxy.username'), 'svc-account')
        self.assertEqual(keys.get('proxy.nonProxyHosts'), 'localhost|127.0.0.1')

    def test_missing_proxies_element_no_findings(self):
        """
        Ziel: Ein settings.xml ohne <proxies>-Element (der Normalfall) soll
              keine Findings und keinen Absturz erzeugen.

        Erwartung: Keine Findings.
        """
        xml = "<settings><servers/></settings>"
        with tempfile.TemporaryDirectory() as tmp:
            scan_maven_settings(self._write(tmp, xml))
        self.assertEqual(_mod.findings, [])

    def test_malformed_xml_no_crash(self):
        """
        Ziel: Fehlerhaftes XML soll den Scan nicht abbrechen lassen.

        Erwartung: Keine Findings, kein Crash.
        """
        with tempfile.TemporaryDirectory() as tmp:
            scan_maven_settings(self._write(tmp, "<settings><unclosed>"))
        self.assertEqual(_mod.findings, [])

    def test_missing_file_no_crash(self):
        """
        Ziel: Eine nicht existierende settings.xml (Normalfall auf den meisten
              Systemen) soll keinen Absturz verursachen.

        Erwartung: Keine Findings, kein Crash.
        """
        scan_maven_settings('/nonexistent/.m2/settings.xml')
        self.assertEqual(_mod.findings, [])


# ===========================================================================
# Klasse 11: Tests für collect_maven_files()
# ===========================================================================

class TestCollectMavenFiles(unittest.TestCase):
    """
    Testet collect_maven_files(), das die statische MAVEN_SETTINGS_FILES-Liste
    um settings.xml-Pfade unter MAVEN_HOME/M2_HOME ergänzt.
    """

    def test_static_files_always_included(self):
        """
        Ziel: Die fest hinterlegten Kandidaten (MAVEN_SETTINGS_FILES) sollen
              immer im Ergebnis enthalten sein.

        Erwartung: Alle Einträge aus MAVEN_SETTINGS_FILES sind in der Rückgabe.
        """
        with mock.patch.object(_mod, 'MAVEN_HOME_CANDIDATES', []):
            result = collect_maven_files()
        for f in _mod.MAVEN_SETTINGS_FILES:
            self.assertIn(f, result)

    def test_maven_home_candidate_appends_settings_path(self):
        """
        Ziel: Ist MAVEN_HOME (bzw. M2_HOME) gesetzt, soll zusätzlich
              '<MAVEN_HOME>/conf/settings.xml' als Kandidat aufgenommen werden —
              dort liegt die globale Maven-Konfiguration bei einer manuellen
              Installation.

        Eingabe: MAVEN_HOME_CANDIDATES = ['/opt/maven'].

        Erwartung: '/opt/maven/conf/settings.xml' ist im Ergebnis enthalten.
        """
        with mock.patch.object(_mod, 'MAVEN_HOME_CANDIDATES', ['/opt/maven']):
            result = collect_maven_files()
        self.assertIn(os.path.join('/opt/maven', 'conf', 'settings.xml'), result)

    def test_empty_maven_home_candidate_ignored(self):
        """
        Ziel: Ein leerer String in MAVEN_HOME_CANDIDATES (unset env var) soll
              nicht zu einem ungültigen Pfad wie 'conf/settings.xml' führen.

        Eingabe: MAVEN_HOME_CANDIDATES = [''].

        Erwartung: Kein Eintrag, der nur aus 'conf/settings.xml' besteht.
        """
        with mock.patch.object(_mod, 'MAVEN_HOME_CANDIDATES', ['']):
            result = collect_maven_files()
        self.assertNotIn(os.path.join('conf', 'settings.xml'), result)


# ===========================================================================
# Klasse 12: Integrationstests für main()
# ===========================================================================

class TestMain(ScanProxyTestCase):
    """
    Integrationstests für main(): alle Datei-/Glob-Quellen werden auf leere
    Listen gepatcht und os.environ wird proxy-frei gesetzt, damit die Tests
    unabhängig vom tatsächlichen Host-System reproduzierbar sind.
    """

    def _patch_all_sources(self, **overrides):
        defaults = {
            'CONFIG_FILES': [],
            'GLOB_PATTERNS': [],
            'MAVEN_SETTINGS_FILES': [],
            'MAVEN_HOME_CANDIDATES': [],
            'ANSIBLE_CFG_FILES': [],
            'APT_CONFIG_FILES': [],
            'APT_GLOB_PATTERNS': [],
            'DOCKER_CONFIG_FILES': [],
            'SYSTEMD_GLOB_PATTERNS': [],
        }
        defaults.update(overrides)
        patchers = [mock.patch.object(_mod, name, value) for name, value in defaults.items()]
        for p in patchers:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patchers])

    def test_no_proxy_anywhere_returns_zero(self):
        """
        Ziel: Ohne jegliche Proxy-Konfiguration soll main() 0 zurückgeben und
              'RESULT: NO_PROXY_FOUND' ausgeben.

        Erwartung: Rückgabewert 0, Ausgabe enthält NO_PROXY_FOUND.
        """
        self._patch_all_sources()
        with mock.patch.dict(os.environ, _clean_environ(), clear=True):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = main()
        self.assertEqual(rc, 0)
        self.assertIn('RESULT: NO_PROXY_FOUND', out.getvalue())

    def test_env_proxy_found_returns_one(self):
        """
        Ziel: Ein über die Umgebung gesetzter http_proxy soll main() mit
              Rückgabewert 1 und 'RESULT: PROXY_FOUND' beenden.

        Eingabe: os.environ['http_proxy'] = 'http://proxy.example.com:8080'.

        Erwartung: Rückgabewert 1, Ausgabe enthält PROXY_FOUND und die
                   SOURCE=ENV-Zeile mit dem korrekten Wert.
        """
        self._patch_all_sources()
        env = _clean_environ()
        env['http_proxy'] = 'http://proxy.example.com:8080'
        with mock.patch.dict(os.environ, env, clear=True):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = main()
        self.assertEqual(rc, 1)
        output = out.getvalue()
        self.assertIn('RESULT: PROXY_FOUND', output)
        self.assertIn('SOURCE=ENV KEY=http_proxy VALUE=http://proxy.example.com:8080', output)

    def test_only_no_proxy_env_returns_zero(self):
        """
        Ziel: Ist ausschließlich no_proxy gesetzt (Ausschlussliste, kein aktiver
              Proxy), soll main() trotzdem NO_PROXY_FOUND melden — der Fund
              selbst wird aber weiterhin ausgegeben, damit er sichtbar bleibt.

        Eingabe: os.environ['no_proxy'] = 'localhost,127.0.0.1'.

        Erwartung: Rückgabewert 0, Ausgabe enthält NO_PROXY_FOUND, aber auch
                   die SOURCE=ENV KEY=no_proxy-Zeile.
        """
        self._patch_all_sources()
        env = _clean_environ()
        env['no_proxy'] = 'localhost,127.0.0.1'
        with mock.patch.dict(os.environ, env, clear=True):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = main()
        self.assertEqual(rc, 0)
        output = out.getvalue()
        self.assertIn('RESULT: NO_PROXY_FOUND', output)
        self.assertIn('SOURCE=ENV KEY=no_proxy VALUE=localhost,127.0.0.1', output)

    def test_proxy_from_config_file_found(self):
        """
        Ziel: Ein Proxy, der ausschließlich in einer Konfigurationsdatei
              (nicht in der Umgebung) gefunden wird, soll ebenfalls zu
              PROXY_FOUND und Rückgabewert 1 führen.

        Eingabe: Eine Datei in CONFIG_FILES mit 'http_proxy=http://file-proxy.example.com:3128'.

        Erwartung: Rückgabewert 1, Ausgabe enthält den Dateipfad als SOURCE.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'environment')
            with open(path, 'w') as f:
                f.write('http_proxy=http://file-proxy.example.com:3128\n')
            self._patch_all_sources(CONFIG_FILES=[path])
            with mock.patch.dict(os.environ, _clean_environ(), clear=True):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = main()
        self.assertEqual(rc, 1)
        output = out.getvalue()
        self.assertIn('RESULT: PROXY_FOUND', output)
        self.assertIn(f'SOURCE={path} KEY=http_proxy VALUE=http://file-proxy.example.com:3128', output)

    def test_hostname_header_printed(self):
        """
        Ziel: Der Report soll mit einer Kopfzeile beginnen, die den Hostnamen
              enthält, damit Ergebnisse mehrerer Systeme unterscheidbar sind.

        Erwartung: Ausgabe beginnt mit '=== PROXY SCAN REPORT:'.
        """
        self._patch_all_sources()
        with mock.patch.dict(os.environ, _clean_environ(), clear=True):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                main()
        self.assertTrue(out.getvalue().startswith('=== PROXY SCAN REPORT:'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
