#!/usr/bin/env python3
"""
test_scan_external_urls.py — Umfangreiche Unit-Tests für scan-external-urls.py

Teststruktur:
  - Jede Testklasse deckt genau einen Scanner oder eine Hilfsfunktion ab.
  - Jede Testmethode enthält einen Docstring, der erklärt:
      1. Was das Testziel ist (was soll erkannt werden?)
      2. Welche konkreten Eingabedaten verwendet werden
      3. Was das erwartete Ergebnis ist und warum

Ausführung:
  python3 -m pytest test_scan_external_urls.py -v
  python3 -m unittest discover -v

Exit-Codes:
  0 — Alle Tests bestanden
  1 — Mindestens ein Test fehlgeschlagen
"""

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

# scan-external-urls.py enthält Bindestriche im Dateinamen und kann daher
# nicht direkt mit 'import' geladen werden — importlib übernimmt das manuell.
_spec = importlib.util.spec_from_file_location(
    "scan_external_urls",
    pathlib.Path(__file__).parent / "scan-external-urls.py",
)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
# Modul vor exec_module in sys.modules eintragen: dataclasses löst
# cls.__module__ über sys.modules auf und crasht sonst mit
# AttributeError: 'NoneType' object has no attribute '__dict__'.
sys.modules["scan_external_urls"] = _mod
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

Category               = _mod.Category
Finding                = _mod.Finding
Whitelist              = _mod.Whitelist
ScanConfig             = _mod.ScanConfig
is_test_file           = _mod.is_test_file
matches_any            = _mod.matches_any
_has_known_tld         = _mod._has_known_tld
is_allowlisted         = _mod.is_allowlisted
is_whitelisted         = _mod.is_whitelisted
scan_line              = _mod.scan_line
scan_file              = _mod.scan_file
load_allowlist_file    = _mod.load_allowlist_file
load_whitelist_file    = _mod.load_whitelist_file


# ---------------------------------------------------------------------------
# Hilfsfunktion: ScanConfig mit sinnvollen Defaults erzeugen
# ---------------------------------------------------------------------------

def _config(**overrides) -> ScanConfig:
    """Erzeugt eine ScanConfig mit Default-Werten, überschrieben per kwargs."""
    defaults = {"repo_path": "."}
    defaults.update(overrides)
    return ScanConfig(**defaults)


def _values_for(line: str, category: Category, **config_overrides) -> list[str]:
    """Führt scan_line() aus und gibt nur die Werte einer bestimmten Kategorie zurück."""
    config = _config(categories={category}, **config_overrides)
    return [value for cat, value in scan_line(line, config) if cat == category]


# ===========================================================================
# Klasse 1: Tests für is_test_file()
# ===========================================================================

class TestIsTestFile(unittest.TestCase):
    """Testet die Erkennung von Testdateien, die mit --skip-tests übersprungen werden."""

    def test_python_test_prefix(self):
        """
        Ziel: Python-Dateien mit 'test_'-Präfix sollen als Testdatei erkannt werden.
        Eingabe: 'src/test_foo.py'.
        Erwartung: True.
        """
        self.assertTrue(is_test_file("src/test_foo.py"))

    def test_js_spec_suffix(self):
        """
        Ziel: JavaScript-Dateien mit '.spec.js'-Suffix sollen erkannt werden.
        Eingabe: 'app/component.spec.js'.
        Erwartung: True.
        """
        self.assertTrue(is_test_file("app/component.spec.js"))

    def test_test_directory_marker(self):
        """
        Ziel: Dateien innerhalb eines '/tests/'-Verzeichnisses sollen erkannt werden,
              unabhängig vom Dateinamen selbst.
        Eingabe: 'project/tests/fixtures.py'.
        Erwartung: True.
        """
        self.assertTrue(is_test_file("project/tests/fixtures.py"))

    def test_java_test_suffix(self):
        """
        Ziel: Java-Klassen mit 'Test.java'-Suffix (z. B. FooTest.java) sollen erkannt werden.
        Eingabe: 'src/main/FooTest.java'.
        Erwartung: True.
        """
        self.assertTrue(is_test_file("src/main/FooTest.java"))

    def test_regular_source_file_not_test(self):
        """
        Ziel: Normale Quelldateien ohne Test-Merkmale sollen nicht als Testdatei gelten.
        Eingabe: 'src/main.py'.
        Erwartung: False.
        """
        self.assertFalse(is_test_file("src/main.py"))


# ===========================================================================
# Klasse 2: Tests für matches_any()
# ===========================================================================

class TestMatchesAny(unittest.TestCase):
    """Testet den generischen Pattern-Matcher, der für --allow und --skip genutzt wird."""

    def test_regex_pattern_matches(self):
        """
        Ziel: Ein echtes Regex-Pattern soll gegen den Wert gematcht werden.
        Eingabe: Wert 'api.example.com', Pattern 'example\\.com$'.
        Erwartung: True.
        """
        self.assertTrue(matches_any("api.example.com", [r"example\.com$"]))

    def test_no_pattern_matches(self):
        """
        Ziel: Wenn kein Pattern passt, soll False zurückgegeben werden.
        Eingabe: Wert 'api.example.com', Pattern 'nomatch'.
        Erwartung: False.
        """
        self.assertFalse(matches_any("api.example.com", ["nomatch"]))

    def test_invalid_regex_falls_back_to_substring(self):
        """
        Ziel: Ein ungültiges Regex-Pattern (z. B. unbalancierte Klammer) darf nicht
              crashen, sondern soll auf einen einfachen Substring-Vergleich zurückfallen.
        Eingabe: Wert 'foo(bar', Pattern 'foo(bar' (als Regex ungültig wegen '(').
        Erwartung: True, da der Substring-Vergleich greift statt eine Exception zu werfen.
        """
        self.assertTrue(matches_any("foo(bar", ["foo(bar"]))

    def test_case_insensitive(self):
        """
        Ziel: Der Vergleich soll Groß-/Kleinschreibung ignorieren.
        Eingabe: Wert 'API.EXAMPLE.COM', Pattern 'example'.
        Erwartung: True.
        """
        self.assertTrue(matches_any("API.EXAMPLE.COM", ["example"]))


# ===========================================================================
# Klasse 3: Tests für _has_known_tld()
# ===========================================================================

class TestHasKnownTld(unittest.TestCase):
    """Testet die TLD-Whitelist, die False-Positives wie 'foo.py' oder 'obj.id' verhindert."""

    def test_known_tld_com(self):
        """
        Ziel: '.com' ist eine bekannte TLD und soll akzeptiert werden.
        Eingabe: 'example.com'.
        Erwartung: True.
        """
        self.assertTrue(_has_known_tld("example.com"))

    def test_unknown_tld_py_rejected(self):
        """
        Ziel: '.py' ist keine echte TLD, sondern eine Dateiendung — soll abgelehnt werden,
              damit z. B. 'foo@bar.py' nicht als E-Mail gemeldet wird.
        Eingabe: 'bar.py'.
        Erwartung: False.
        """
        self.assertFalse(_has_known_tld("bar.py"))

    def test_case_insensitive_tld(self):
        """
        Ziel: Die TLD-Prüfung soll Groß-/Kleinschreibung ignorieren.
        Eingabe: 'example.COM'.
        Erwartung: True.
        """
        self.assertTrue(_has_known_tld("example.COM"))


# ===========================================================================
# Klasse 4: Tests für die URL-Erkennung (scan_line / Category.URL)
# ===========================================================================

class TestDetectUrls(unittest.TestCase):
    """Testet die Erkennung von http(s)-URLs in einer Codezeile."""

    def test_simple_https_url(self):
        """
        Ziel: Eine einfache https-URL soll vollständig erkannt werden.
        Eingabe: 'fetch("https://api.example.com/v1/data")'.
        Erwartung: Genau ein Treffer, exakt die URL ohne die umschließenden Anführungszeichen.
        """
        values = _values_for('fetch("https://api.example.com/v1/data")', Category.URL)
        self.assertEqual(values, ["https://api.example.com/v1/data"])

    def test_url_stops_at_trailing_punctuation(self):
        """
        Ziel: Ein Satzzeichen am Ende (z. B. Punkt in einem Kommentar) darf nicht Teil
              der erkannten URL sein.
        Eingabe: '# See https://example.com/docs.'
        Erwartung: URL endet auf 'docs', ohne den abschließenden Satzpunkt.
        """
        values = _values_for("# See https://example.com/docs.", Category.URL)
        self.assertEqual(values, ["https://example.com/docs"])

    def test_no_url_in_plain_text(self):
        """
        Ziel: Text ohne http(s)-Schema soll keinen URL-Treffer erzeugen.
        Eingabe: 'this is just plain text with a.dot.here'.
        Erwartung: Keine Treffer.
        """
        values = _values_for("this is just plain text with a.dot.here", Category.URL)
        self.assertEqual(values, [])

    def test_multiple_urls_in_one_line(self):
        """
        Ziel: Mehrere URLs in derselben Zeile sollen alle erkannt werden.
        Eingabe: Zeile mit zwei durch Komma getrennten URLs.
        Erwartung: Beide URLs werden als separate Treffer gemeldet.
        """
        line = "hosts = https://a.example.com, https://b.example.com"
        values = _values_for(line, Category.URL)
        self.assertEqual(values, ["https://a.example.com", "https://b.example.com"])


# ===========================================================================
# Klasse 5: Tests für die E-Mail-Erkennung (scan_line / Category.EMAIL)
# ===========================================================================

class TestDetectEmails(unittest.TestCase):
    """Testet die Erkennung von E-Mail-Adressen und die TLD-basierte Filterung."""

    def test_simple_email(self):
        """
        Ziel: Eine normale E-Mail-Adresse mit bekannter TLD soll erkannt werden.
        Eingabe: 'contact: admin@example.com'.
        Erwartung: Genau ein Treffer 'admin@example.com'.
        """
        values = _values_for("contact: admin@example.com", Category.EMAIL)
        self.assertEqual(values, ["admin@example.com"])

    def test_false_positive_file_extension_rejected(self):
        """
        Ziel: Ausdrücke wie 'foo@bar.py' (z. B. Decorator-Kommentar oder generierter
              Code) sind keine echten E-Mails, da '.py' keine TLD ist.
        Eingabe: 'user@module.py'.
        Erwartung: Kein Treffer.
        """
        values = _values_for("user@module.py", Category.EMAIL)
        self.assertEqual(values, [])

    def test_email_not_duplicated_with_url(self):
        """
        Ziel: Wenn eine E-Mail bereits als Teil einer zuvor erkannten URL gemeldet wurde
              (z. B. userinfo in einer URL), soll sie nicht zusätzlich als eigenständige
              E-Mail gemeldet werden.
        Eingabe: URL mit eingebettetem 'user@host.com' als Userinfo, beide Kategorien aktiv.
        Erwartung: Der String 'user@host.com' erscheint nicht als eigenständiger
                   EMAIL-Treffer, da er bereits Teil des URL-Treffers ist.
        """
        line = "https://user@host.com/path"
        config = _config(categories={Category.URL, Category.EMAIL})
        hits = scan_line(line, config)
        emails = [v for cat, v in hits if cat == Category.EMAIL]
        self.assertEqual(emails, [])


# ===========================================================================
# Klasse 6: Tests für die Hostname-Erkennung (scan_line / Category.HOSTNAME)
# ===========================================================================

class TestDetectHostnames(unittest.TestCase):
    """Testet die Hostname-Erkennung inkl. der Heuristiken gegen False-Positives."""

    def test_simple_hostname(self):
        """
        Ziel: Ein einfacher, freistehender Hostname mit bekannter TLD soll erkannt werden.
        Eingabe: 'endpoint = "api.example.com"'.
        Erwartung: Genau ein Treffer 'api.example.com'.
        """
        values = _values_for('endpoint = "api.example.com"', Category.HOSTNAME)
        self.assertEqual(values, ["api.example.com"])

    def test_function_call_not_hostname(self):
        """
        Ziel: Ein Methodenaufruf wie 'subprocess.run(' darf nicht als Hostname gemeldet
              werden, da direkt eine öffnende Klammer folgt.
        Eingabe: 'subprocess.run(["ls"])'.
        Erwartung: Keine Treffer.
        """
        values = _values_for('subprocess.run(["ls"])', Category.HOSTNAME)
        self.assertEqual(values, [])

    def test_import_statement_not_hostname(self):
        """
        Ziel: Ein Python-Import wie 'import os.path' darf nicht als Hostname gemeldet
              werden.
        Eingabe: 'import os.path'.
        Erwartung: Keine Treffer, da 'os.path' keine bekannte TLD hat UND es sich um
                   ein Import handelt.
        """
        values = _values_for("import os.path", Category.HOSTNAME)
        self.assertEqual(values, [])

    def test_kubernetes_api_group_not_hostname(self):
        """
        Ziel: Kubernetes-API-Gruppen wie 'rbac.authorization.k8s.io' gefolgt von einem
              '/' (z. B. apiVersion) sollen nicht als Hostname gemeldet werden.
        Eingabe: 'apiVersion: rbac.authorization.k8s.io/v1'.
        Erwartung: Keine Treffer.
        """
        values = _values_for("apiVersion: rbac.authorization.k8s.io/v1", Category.HOSTNAME)
        self.assertEqual(values, [])

    def test_url_authority_still_reported(self):
        """
        Ziel: Ein Hostname, der direkt nach '://' als URL-Autorität auftritt, soll auch
              dann als Hostname gemeldet werden, wenn er von einem '/' gefolgt wird
              (z. B. Pfad) — die apiGroup-Heuristik darf hier nicht greifen.
        Eingabe: 'curl https://api.example.com/v1/data'.
        Erwartung: 'api.example.com' wird als Hostname gemeldet.
        """
        values = _values_for("curl https://api.example.com/v1/data", Category.HOSTNAME)
        self.assertEqual(values, ["api.example.com"])

    def test_all_uppercase_constant_not_hostname(self):
        """
        Ziel: Durchgängig großgeschriebene Bezeichner vor der TLD (z. B. DOS-Dateinamen
              oder Konstanten) sollen nicht als Hostname gemeldet werden.
        Eingabe: 'copy MOUSE.COM'.
        Erwartung: Keine Treffer.
        """
        values = _values_for("copy MOUSE.COM", Category.HOSTNAME)
        self.assertEqual(values, [])

    def test_yaml_list_item_not_hostname(self):
        """
        Ziel: Ein YAML-Listeneintrag mit einem Paketnamen wie 'containerd.io' soll nicht
              als Hostname gemeldet werden.
        Eingabe: '  - containerd.io'.
        Erwartung: Keine Treffer.
        """
        values = _values_for("  - containerd.io", Category.HOSTNAME)
        self.assertEqual(values, [])

    def test_unknown_tld_not_hostname(self):
        """
        Ziel: Dotted-Path-Ausdrücke wie 'self.parent' dürfen nicht als Hostname gemeldet
              werden, da 'parent' keine bekannte TLD ist.
        Eingabe: 'return self.parent'.
        Erwartung: Keine Treffer.
        """
        values = _values_for("return self.parent", Category.HOSTNAME)
        self.assertEqual(values, [])


# ===========================================================================
# Klasse 7: Tests für die IP-Erkennung (scan_line / Category.IP)
# ===========================================================================

class TestDetectIps(unittest.TestCase):
    """Testet die Erkennung von IPv4- und IPv6-Adressen sowie deren Ignorier-Optionen."""

    def test_simple_ipv4(self):
        """
        Ziel: Eine gültige IPv4-Adresse soll erkannt werden.
        Eingabe: 'host = 10.0.0.5'.
        Erwartung: Genau ein Treffer '10.0.0.5'.
        """
        values = _values_for("host = 10.0.0.5", Category.IP)
        self.assertEqual(values, ["10.0.0.5"])

    def test_ipv4_ignored_via_ignore_ips(self):
        """
        Ziel: Eine IP, die explizit über --ignore-ips angegeben wurde, soll nicht
              gemeldet werden.
        Eingabe: 'host = 10.0.0.5', ignore_ips={'10.0.0.5'}.
        Erwartung: Keine Treffer.
        """
        values = _values_for("host = 10.0.0.5", Category.IP, ignore_ips={"10.0.0.5"})
        self.assertEqual(values, [])

    def test_all_ips_ignored_via_ignore_all_ips(self):
        """
        Ziel: Mit --ignore-all-ips sollen überhaupt keine IPs mehr gemeldet werden,
              unabhängig davon, welche konkrete Adresse in der Zeile steht.
        Eingabe: 'host = 192.168.1.1', ignore_all_ips=True.
        Erwartung: Keine Treffer.
        """
        values = _values_for("host = 192.168.1.1", Category.IP, ignore_all_ips=True)
        self.assertEqual(values, [])

    def test_valid_ipv6_detected(self):
        """
        Ziel: Eine gültige IPv6-Adresse soll erkannt werden, auch wenn das Roh-Pattern
              nur grob matcht — die Validierung erfolgt über ipaddress.ip_address().
        Eingabe: 'addr = 2001:db8::1'.
        Erwartung: '2001:db8::1' wird als Treffer gemeldet.
        """
        values = _values_for("addr = 2001:db8::1", Category.IP)
        self.assertIn("2001:db8::1", values)

    def test_invalid_ipv6_like_string_rejected(self):
        """
        Ziel: Ein String, der grob wie IPv6 aussieht (viele Doppelpunkte), aber keine
              gültige Adresse ist, soll NICHT gemeldet werden — das ist der Zweck der
              ipaddress-Validierung.
        Eingabe: 'time = 12:34:56:78:90'  (kein gültiges IPv6-Format).
        Erwartung: Keine Treffer.
        """
        values = _values_for("time = 12:34:56:78:90", Category.IP)
        self.assertEqual(values, [])

    def test_pure_ipv4_string_not_reported_twice_as_ipv6(self):
        """
        Ziel: Eine reine IPv4-Adresse ohne Doppelpunkte darf nicht zusätzlich vom
              IPv6-Grobmuster erfasst werden (sie hat keine Doppelpunkte, kann also
              gar nicht matchen) — Kontrolle, dass IPv4 nur einmal erscheint.
        Eingabe: 'host = 10.0.0.5'.
        Erwartung: Genau ein Treffer, keine Duplikate.
        """
        values = _values_for("host = 10.0.0.5", Category.IP)
        self.assertEqual(len(values), 1)


# ===========================================================================
# Klasse 8: Tests für is_allowlisted() (--allow / --allow-file)
# ===========================================================================

class TestIsAllowlisted(unittest.TestCase):
    """Testet die Unterscheidung zwischen Domain-Literalen und freien Regex-Patterns."""

    def test_domain_literal_allows_exact_host(self):
        """
        Ziel: Ein Domain-Literal wie 'mycompany.com' soll den exakten Host erlauben.
        Eingabe: Kategorie HOSTNAME, Wert 'mycompany.com', Pattern 'mycompany.com'.
        Erwartung: True.
        """
        self.assertTrue(is_allowlisted(Category.HOSTNAME, "mycompany.com", ["mycompany.com"]))

    def test_domain_literal_allows_subdomain(self):
        """
        Ziel: Ein Domain-Literal soll auch Subdomains der erlaubten Domain abdecken.
        Eingabe: Kategorie HOSTNAME, Wert 'api.mycompany.com', Pattern 'mycompany.com'.
        Erwartung: True.
        """
        self.assertTrue(is_allowlisted(Category.HOSTNAME, "api.mycompany.com", ["mycompany.com"]))

    def test_domain_literal_rejects_lookalike_domain(self):
        """
        Ziel: Ein Domain-Literal darf NICHT per Substring auf einen ähnlich aussehenden,
              aber fremden Host matchen — sonst könnte ein Angreifer mit
              'evil-mycompany.com.attacker.net' das Allowlisting umgehen.
        Eingabe: Kategorie HOSTNAME, Wert 'evil-mycompany.com.attacker.net',
                 Pattern 'mycompany.com'.
        Erwartung: False.
        """
        self.assertFalse(
            is_allowlisted(Category.HOSTNAME, "evil-mycompany.com.attacker.net", ["mycompany.com"])
        )

    def test_escaped_domain_literal_treated_as_domain(self):
        """
        Ziel: Ein Pattern mit escaptem Punkt (z. B. 'mycompany\\.com', wie es die
              Kommandozeile typischerweise erwartet) soll ebenfalls als Domain-Literal
              behandelt werden, nicht als freies Regex.
        Eingabe: Kategorie URL, Wert 'https://mycompany.com/x', Pattern 'mycompany\\.com'.
        Erwartung: True.
        """
        self.assertTrue(is_allowlisted(Category.URL, "https://mycompany.com/x", [r"mycompany\.com"]))

    def test_generic_regex_pattern_still_works(self):
        """
        Ziel: Ein echtes Regex-Pattern (kein reines Domain-Literal, z. B. mit '.*') soll
              weiterhin als freies Regex gegen den Rohwert gematcht werden.
        Eingabe: Kategorie URL, Wert 'https://staging.example.com/x', Pattern 'staging.*'.
        Erwartung: True.
        """
        self.assertTrue(is_allowlisted(Category.URL, "https://staging.example.com/x", ["staging.*"]))

    def test_no_matching_pattern_rejected(self):
        """
        Ziel: Wenn kein Pattern passt, soll der Wert nicht allowlisted sein.
        Eingabe: Kategorie HOSTNAME, Wert 'evil.example.com', Pattern 'mycompany.com'.
        Erwartung: False.
        """
        self.assertFalse(is_allowlisted(Category.HOSTNAME, "evil.example.com", ["mycompany.com"]))


# ===========================================================================
# Klasse 9: Tests für is_whitelisted() (whitelist.json)
# ===========================================================================

class TestIsWhitelisted(unittest.TestCase):
    """Testet das Whitelisting über IP-Ranges, Hostnames, E-Mail-Domains und URLs."""

    def test_ip_in_whitelisted_range(self):
        """
        Ziel: Eine IP innerhalb eines whitelisted CIDR-Bereichs soll erkannt werden.
        Eingabe: ip_ranges=['10.0.0.0/8'], Wert '10.1.2.3'.
        Erwartung: True.
        """
        wl = Whitelist(ip_ranges=[_mod.ipaddress.ip_network("10.0.0.0/8")])
        self.assertTrue(is_whitelisted(Category.IP, "10.1.2.3", wl))

    def test_ip_outside_whitelisted_range(self):
        """
        Ziel: Eine IP außerhalb aller whitelisted Bereiche soll nicht als whitelisted gelten.
        Eingabe: ip_ranges=['10.0.0.0/8'], Wert '192.168.1.1'.
        Erwartung: False.
        """
        wl = Whitelist(ip_ranges=[_mod.ipaddress.ip_network("10.0.0.0/8")])
        self.assertFalse(is_whitelisted(Category.IP, "192.168.1.1", wl))

    def test_hostname_exact_match(self):
        """
        Ziel: Ein exakt whitelisteter Hostname soll erkannt werden.
        Eingabe: hostnames=['example.com'], Wert 'example.com'.
        Erwartung: True.
        """
        wl = Whitelist(hostnames=["example.com"])
        self.assertTrue(is_whitelisted(Category.HOSTNAME, "example.com", wl))

    def test_hostname_subdomain_match(self):
        """
        Ziel: Eine Subdomain eines whitelisteten Hostnamens soll ebenfalls erkannt werden.
        Eingabe: hostnames=['example.com'], Wert 'api.example.com'.
        Erwartung: True.
        """
        wl = Whitelist(hostnames=["example.com"])
        self.assertTrue(is_whitelisted(Category.HOSTNAME, "api.example.com", wl))

    def test_email_domain_match(self):
        """
        Ziel: Eine E-Mail mit whitelisteter Domain soll erkannt werden.
        Eingabe: email_domains=['example.com'], Wert 'user@example.com'.
        Erwartung: True.
        """
        wl = Whitelist(email_domains=["example.com"])
        self.assertTrue(is_whitelisted(Category.EMAIL, "user@example.com", wl))

    def test_url_prefix_match(self):
        """
        Ziel: Eine URL, die mit einem whitelisteten URL-Präfix beginnt, soll erkannt werden.
        Eingabe: urls=['https://example.com/'], Wert 'https://example.com/path'.
        Erwartung: True.
        """
        wl = Whitelist(urls=["https://example.com/"])
        self.assertTrue(is_whitelisted(Category.URL, "https://example.com/path", wl))

    def test_url_host_whitelisted_via_hostnames(self):
        """
        Ziel: Eine URL, deren Host in der Hostname-Whitelist steht, soll ebenfalls
              als whitelisted gelten, auch ohne passenden URL-Präfix-Eintrag.
        Eingabe: hostnames=['example.com'], Wert 'https://example.com/other/path'.
        Erwartung: True.
        """
        wl = Whitelist(hostnames=["example.com"])
        self.assertTrue(is_whitelisted(Category.URL, "https://example.com/other/path", wl))

    def test_not_whitelisted_by_default(self):
        """
        Ziel: Eine leere Whitelist darf nichts durchlassen.
        Eingabe: Leere Whitelist, Wert 'evil.example.com'.
        Erwartung: False.
        """
        self.assertFalse(is_whitelisted(Category.HOSTNAME, "evil.example.com", Whitelist()))


# ===========================================================================
# Klasse 10: Tests für scan_file() (End-to-End mit echten Dateien)
# ===========================================================================

class TestScanFile(unittest.TestCase):
    """Testet scan_file() als Ganzes: Extension-Skip, Binary-Skip, Skip-Patterns,
    Test-Datei-Skip, Allowlist- und Whitelist-Filterung sowie die erzeugten Findings."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.repo_path = self._tmpdir.name

    def tearDown(self):
        self._tmpdir.cleanup()

    def _write(self, relname: str, content: str) -> str:
        path = pathlib.Path(self.repo_path) / relname
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return str(path)

    def test_finding_reported_with_file_and_line(self):
        """
        Ziel: Ein gefundener Wert soll mit korrektem relativen Dateipfad und
              1-basierter Zeilennummer gemeldet werden.
        Eingabe: Datei 'app.py' mit einer URL in Zeile 2.
        Erwartung: Ein Finding mit file='app.py', line=2, category=URL.
        """
        path = self._write("app.py", 'print("hi")\nurl = "https://example.com/x"\n')
        config = _config(repo_path=self.repo_path)
        findings = scan_file(path, config)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file, "app.py")
        self.assertEqual(findings[0].line, 2)
        self.assertEqual(findings[0].category, Category.URL)

    def test_always_skip_extension(self):
        """
        Ziel: Dateien mit einer Extension aus ALWAYS_SKIP_EXTENSIONS (z. B. .png) sollen
              nie gescannt werden, selbst wenn sie textuellen Inhalt mit einer URL haben.
        Eingabe: Datei 'image.png' mit URL-Text als Inhalt.
        Erwartung: Keine Findings.
        """
        path = self._write("image.png", "https://example.com")
        config = _config(repo_path=self.repo_path)
        findings = scan_file(path, config)
        self.assertEqual(findings, [])

    def test_binary_file_skipped(self):
        """
        Ziel: Eine Datei mit Null-Bytes im Header soll als binär erkannt und übersprungen
              werden, auch wenn sie eine unauffällige Extension wie '.dat' hat.
        Eingabe: Datei 'blob.dat' mit Null-Byte gefolgt von einer URL.
        Erwartung: Keine Findings.
        """
        path = pathlib.Path(self.repo_path) / "blob.dat"
        path.write_bytes(b"\x00\x01https://example.com")
        config = _config(repo_path=self.repo_path)
        findings = scan_file(str(path), config)
        self.assertEqual(findings, [])

    def test_skip_tests_option(self):
        """
        Ziel: Mit skip_tests=True soll eine erkannte Testdatei komplett übersprungen werden.
        Eingabe: Datei 'test_app.py' mit einer URL, skip_tests=True.
        Erwartung: Keine Findings.
        """
        path = self._write("test_app.py", 'url = "https://example.com/x"\n')
        config = _config(repo_path=self.repo_path, skip_tests=True)
        findings = scan_file(path, config)
        self.assertEqual(findings, [])

    def test_skip_patterns_option(self):
        """
        Ziel: Dateien, deren relativer Pfad einem --skip-Pattern entspricht, sollen
              übersprungen werden.
        Eingabe: Datei 'fixtures/data.py' mit URL, skip_patterns=['fixtures/'].
        Erwartung: Keine Findings.
        """
        path = self._write("fixtures/data.py", 'url = "https://example.com/x"\n')
        config = _config(repo_path=self.repo_path, skip_patterns=["fixtures/"])
        findings = scan_file(path, config)
        self.assertEqual(findings, [])

    def test_allowlisted_value_excluded(self):
        """
        Ziel: Ein Fund, der einem --allow-Pattern entspricht, soll nicht in den
              Findings auftauchen.
        Eingabe: Datei mit 'https://mycompany.com/x', allowlist=['mycompany.com'].
        Erwartung: Keine Findings.
        """
        path = self._write("app.py", 'url = "https://mycompany.com/x"\n')
        config = _config(repo_path=self.repo_path, allowlist=["mycompany.com"])
        findings = scan_file(path, config)
        self.assertEqual(findings, [])

    def test_whitelisted_value_excluded(self):
        """
        Ziel: Ein Fund, dessen Host in der whitelist.json-Hostliste steht, soll nicht
              in den Findings auftauchen.
        Eingabe: Datei mit 'https://trusted.example.com/x', whitelist.hostnames=['trusted.example.com'].
        Erwartung: Keine Findings.
        """
        path = self._write("app.py", 'url = "https://trusted.example.com/x"\n')
        wl = Whitelist(hostnames=["trusted.example.com"])
        config = _config(repo_path=self.repo_path, whitelist=wl)
        findings = scan_file(path, config)
        self.assertEqual(findings, [])

    def test_only_selected_categories_scanned(self):
        """
        Ziel: Wenn categories nur {IP} enthält, sollen URLs in derselben Zeile nicht
              gemeldet werden.
        Eingabe: Datei mit einer URL, categories={IP}.
        Erwartung: Keine Findings, da keine IP in der Zeile vorkommt.
        """
        path = self._write("app.py", 'url = "https://example.com/x"\n')
        config = _config(repo_path=self.repo_path, categories={Category.IP})
        findings = scan_file(path, config)
        self.assertEqual(findings, [])

    def test_context_is_truncated_and_stripped(self):
        """
        Ziel: Das context-Feld eines Findings soll die Zeile getrimmt und auf maximal
              120 Zeichen begrenzt enthalten.
        Eingabe: Zeile mit führenden Leerzeichen und einer URL, gefolgt von sehr langem
                 Kommentar (> 120 Zeichen insgesamt).
        Erwartung: context beginnt nicht mit Leerzeichen und ist höchstens 120 Zeichen lang.
        """
        long_suffix = "x" * 200
        path = self._write("app.py", f'    url = "https://example.com/x"  # {long_suffix}\n')
        config = _config(repo_path=self.repo_path)
        findings = scan_file(path, config)
        self.assertEqual(len(findings), 1)
        self.assertFalse(findings[0].context.startswith(" "))
        self.assertLessEqual(len(findings[0].context), 120)


# ===========================================================================
# Klasse 11: Tests für load_allowlist_file() und load_whitelist_file()
# ===========================================================================

class TestLoadAllowlistFile(unittest.TestCase):
    """Testet das Einlesen von Allow-Pattern-Dateien (--allow-file)."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _write(self, content: str) -> str:
        path = pathlib.Path(self._tmpdir.name) / "allow.txt"
        path.write_text(content, encoding="utf-8")
        return str(path)

    def test_comments_and_blank_lines_ignored(self):
        """
        Ziel: Kommentarzeilen (mit '#') und leere Zeilen sollen ignoriert werden.
        Eingabe: Datei mit einem Kommentar, einer Leerzeile und einem echten Pattern.
        Erwartung: Nur das echte Pattern wird zurückgegeben.
        """
        path = self._write("# comment\n\nmycompany.com\n")
        patterns = load_allowlist_file(path)
        self.assertEqual(patterns, ["mycompany.com"])

    def test_multiple_patterns_preserved_in_order(self):
        """
        Ziel: Mehrere Patterns sollen in der Reihenfolge der Datei zurückgegeben werden.
        Eingabe: Zwei Patterns in zwei Zeilen.
        Erwartung: Liste mit beiden Patterns in derselben Reihenfolge.
        """
        path = self._write("first.com\nsecond.com\n")
        patterns = load_allowlist_file(path)
        self.assertEqual(patterns, ["first.com", "second.com"])


class TestLoadWhitelistFile(unittest.TestCase):
    """Testet das Einlesen der whitelist.json-Struktur."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _write(self, data: dict) -> str:
        path = pathlib.Path(self._tmpdir.name) / "whitelist.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def test_valid_whitelist_loaded(self):
        """
        Ziel: Eine vollständige, gültige whitelist.json soll korrekt in ein
              Whitelist-Objekt geladen werden.
        Eingabe: JSON mit ip_ranges, hostnames (inkl. Wildcard-Präfix '*.'),
                 email_domains und urls.
        Erwartung: ip_ranges enthält ein IPv4Network, hostnames hat den Wildcard-Präfix
                   entfernt, email_domains und urls sind kleingeschrieben übernommen.
        """
        data = {
            "ip_ranges": ["10.0.0.0/8"],
            "hostnames": ["*.Example.com"],
            "email_domains": ["Example.com"],
            "urls": ["HTTPS://Example.com/"],
        }
        path = self._write(data)
        wl = load_whitelist_file(path)
        self.assertEqual(len(wl.ip_ranges), 1)
        self.assertEqual(wl.hostnames, ["example.com"])
        self.assertEqual(wl.email_domains, ["example.com"])
        self.assertEqual(wl.urls, ["https://example.com/"])

    def test_invalid_ip_range_skipped_with_warning(self):
        """
        Ziel: Ein ungültiger CIDR-Eintrag soll übersprungen werden (mit Warnung auf
              stderr), statt das Laden der gesamten Whitelist abzubrechen.
        Eingabe: ip_ranges=['not-an-ip'].
        Erwartung: wl.ip_ranges bleibt leer, kein Crash.
        """
        path = self._write({"ip_ranges": ["not-an-ip"]})
        wl = load_whitelist_file(path)
        self.assertEqual(wl.ip_ranges, [])


# ===========================================================================
# Hauptprogramm
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
