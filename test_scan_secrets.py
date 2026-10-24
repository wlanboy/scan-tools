#!/usr/bin/env python3
"""
test_scan_secrets.py — Unit-Tests für scan-secrets.py

Teststruktur:
  - Jede Testklasse deckt genau eine Funktion oder einen zusammengehörigen
    Satz von Mustern ab.
  - Jede Testmethode enthält einen Docstring mit Ziel, Eingabe und Erwartung.

Ausführung:
  python3 -m pytest test_scan_secrets.py -v
  python3 -m unittest discover -v
"""

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

# scan-secrets.py enthält einen Bindestrich im Dateinamen und kann daher nicht
# direkt mit 'import' geladen werden — importlib übernimmt das manuell.
_spec = importlib.util.spec_from_file_location(
    "scan_secrets",
    pathlib.Path(__file__).parent / "scan-secrets.py",
)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
sys.modules["scan_secrets"] = _mod
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

ScanOptions       = _mod.ScanOptions
scan_line         = _mod.scan_line
scan_file         = _mod.scan_file
is_placeholder    = _mod.is_placeholder
is_test_file      = _mod.is_test_file
get_tracked_files = _mod.get_tracked_files
load_whitelist    = _mod.load_whitelist


def categories(line, **options):
    """Kategorien aller Funde in einer Zeile."""
    return [cat for cat, _, _ in scan_line(line, ScanOptions(**options))]


class TestKeyValueSyntax(unittest.TestCase):
    """Schlüssel/Wert-Schreibweisen aus verschiedenen Sprachen und Formaten."""

    def test_yaml_and_env(self):
        """YAML- und .env-Zuweisungen werden als Passwort erkannt."""
        self.assertEqual(categories('password: Xk9mQ2vL7pR!'), ['password'])
        self.assertEqual(categories('DB_PASSWORD=Xk9mQ2vL7pR!'), ['password'])

    def test_json_key(self):
        """Quotierter JSON-Key: "password": "..." wird erkannt."""
        self.assertEqual(categories('{"password": "Xk9mQ2vL7pR!"}'), ['password'])

    def test_python_dict_key(self):
        """Quotierter Dict-Key mit einfachen Anführungszeichen wird erkannt."""
        self.assertEqual(
            categories("cfg = {'client_secret': 'Q8f3kLmQ9xZ2'}"), ['oauth_secret'],
        )

    def test_go_and_php_assignment(self):
        """Go (:=) und PHP/Ruby (=>) werden als Zuweisung erkannt."""
        self.assertEqual(categories('password := "Xk9mQ2vL7pR"'), ['password'])
        self.assertEqual(categories("'password' => 'Xk9mQ2vL7pR'"), ['password'])

    def test_json_authorization_header(self):
        """"Authorization": "Bearer ..." in JSON wird erkannt."""
        line = '"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz123"'
        self.assertEqual(categories(line), ['bearer_token'])

    def test_hash_inside_quotes(self):
        """'#' in einem quotierten Wert gehört zum Passwort, nicht zum Kommentar."""
        self.assertEqual(categories('password: "Xk9#mQ2vL7pR"'), ['password'])

    def test_hash_after_bare_value_is_comment(self):
        """Bei unquotierten Werten beendet '#' den Wert (Kommentar)."""
        self.assertEqual(categories('password: Xk9 # comment'), [])

    def test_etc_passwd_path(self):
        """'/etc/passwd: root' ist ein Pfad, kein Schlüssel."""
        self.assertEqual(categories('"/etc/passwd: root entry has no password"'), [])


class TestCodeReferences(unittest.TestCase):
    """Unquotierte Werte, die Code sind, werden nicht als Secret gemeldet."""

    def test_environment_lookup(self):
        """os.environ / process.env sind Variablenzugriffe."""
        self.assertEqual(categories('password = os.environ["DB_PW"]'), [])
        self.assertEqual(
            categories('const secret = process.env.AWS_SECRET_ACCESS_KEY;'), [],
        )

    def test_function_call(self):
        """getpass.getpass() ist ein Funktionsaufruf."""
        self.assertEqual(categories('password = getpass.getpass()'), [])

    def test_type_annotation(self):
        """TypeScript-Typannotation 'password: string;' ist kein Wert."""
        self.assertEqual(categories('  password: string;'), [])

    def test_quoted_value_is_literal(self):
        """Ein quotierter Wert wird nie als Code-Referenz verworfen."""
        self.assertEqual(categories('password = "config.Xk9mQ2"'), ['password'])


class TestPlaceholder(unittest.TestCase):
    """is_placeholder() und der eingebaute Platzhalter-Filter."""

    def test_templates(self):
        """Template- und Variablensyntax gilt als Platzhalter."""
        for value in ('${DB_PW}', '<your-key>', '{{token}}', '$API_KEY', '****'):
            with self.subTest(value=value):
                self.assertTrue(is_placeholder(value))

    def test_placeholder_words(self):
        """N/A, TODO und your-... gelten als Platzhalter."""
        for value in ('N/A', 'TODO_SET_ME', 'your-client-secret-here'):
            with self.subTest(value=value):
                self.assertTrue(is_placeholder(value))

    def test_words_inside_other_words(self):
        """'na' und 'todo' mitten im Wort machen ein Secret nicht zum Platzhalter."""
        self.assertFalse(is_placeholder('Kx9Lpqna'))
        self.assertFalse(is_placeholder('Photodoc4u'))


class TestOverlappingPatterns(unittest.TestCase):
    """Generische Muster werden von spezifischen Mustern verdrängt."""

    def test_specific_wins(self):
        """Ein Fund pro Secret, in der spezifischsten Kategorie."""
        self.assertEqual(
            categories('BITBUCKET_APP_PASSWORD=Ab12Cd34Ef56Gh78Ij90'), ['bitbucket_token'],
        )
        self.assertEqual(
            categories('ARTIFACTORY_API_KEY=Ab12Cd34Ef56Gh78Ij90Kl'), ['artifactory_token'],
        )

    def test_separate_secrets_on_one_line(self):
        """Zwei verschiedene Secrets auf einer Zeile bleiben zwei Funde."""
        line = 'password=Xk9mQ2vL7pR! api_key=Ab12Cd34Ef56Gh78Ij90'
        self.assertEqual(categories(line), ['password', 'api_key'])

    def test_generic_alone_with_category_filter(self):
        """Mit --categories generic_secret bleibt der generische Fund erhalten."""
        line = "client_secret: 'Q8f3kLmQ9xZ2'"
        self.assertEqual(
            categories(line, categories={'generic_secret'}), ['generic_secret'],
        )


class TestIsTestFile(unittest.TestCase):
    """is_test_file() arbeitet auf dem repo-relativen Pfad."""

    def test_top_level_tests_dir(self):
        """tests/ direkt im Repo-Root gilt als Testverzeichnis."""
        self.assertTrue(is_test_file(os.path.join('tests', 'conf.yml')))

    def test_regular_file(self):
        """Eine normale Datei gilt nicht als Test."""
        self.assertFalse(is_test_file(os.path.join('config', 'app.yml')))


class TestRepositoryScan(unittest.TestCase):
    """get_tracked_files() und scan_file() gegen ein echtes Git-Repository."""

    def setUp(self):
        # Repo unter einem Verzeichnis namens 'test', damit --skip-tests
        # nicht versehentlich den absoluten Pfad auswertet.
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = os.path.join(self._tmp.name, 'test', 'repo')
        os.makedirs(self.repo)
        subprocess.run(['git', 'init', '-q', self.repo], check=True)
        for name in ('app.yml', 'zugänge.yml', 'gone.yml'):
            with open(os.path.join(self.repo, name), 'w', encoding='utf-8') as fh:
                fh.write('password: Xk9mQ2vL7pR!\n')
        subprocess.run(['git', '-C', self.repo, 'add', '.'], check=True)
        os.remove(os.path.join(self.repo, 'gone.yml'))

    def tearDown(self):
        self._tmp.cleanup()

    def scan(self, **options):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            findings = []
            for path in get_tracked_files(self.repo):
                findings.extend(scan_file(path, self.repo, ScanOptions(**options)))
        return sorted(f.file for f in findings), stderr.getvalue()

    def test_non_ascii_and_deleted_files(self):
        """Umlaut-Dateinamen werden gescannt, gelöschte Dateien still übersprungen."""
        files, stderr = self.scan()
        self.assertEqual(files, ['app.yml', 'zugänge.yml'])
        self.assertEqual(stderr, '')

    def test_skip_tests_uses_relative_path(self):
        """--skip-tests überspringt nicht alles, nur weil das Repo unter test/ liegt."""
        files, _ = self.scan(skip_tests=True)
        self.assertEqual(files, ['app.yml', 'zugänge.yml'])


class TestLoadWhitelist(unittest.TestCase):
    """load_whitelist() akzeptiert Array- und entries-Format."""

    def load(self, data):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as fh:
            json.dump(data, fh)
        try:
            return load_whitelist(fh.name)
        finally:
            os.remove(fh.name)

    def test_entries_object(self):
        """Objekt mit 'entries' liefert die Einträge."""
        self.assertEqual(self.load({'entries': [{'file': 'a'}]}), [{'file': 'a'}])

    def test_non_object_entry(self):
        """Ein Eintrag, der kein Objekt ist, führt zu ValueError statt Traceback."""
        with self.assertRaises(ValueError):
            self.load([1])

    def test_bundled_template(self):
        """Die mitgelieferte secrets-whitelist.json ist gültig."""
        path = pathlib.Path(__file__).parent / 'secrets-whitelist.json'
        self.assertTrue(load_whitelist(str(path)))


if __name__ == '__main__':
    unittest.main()
