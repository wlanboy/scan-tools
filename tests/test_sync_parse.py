#!/usr/bin/env python3
"""
test_sync_parse.py — Unit-Tests für sync/bb_parse.py und sync/fj_parse.py

Teststruktur:
  - Je Hilfsskript eine Testklasse, je Kommando mindestens ein Test.
  - Die Skripte werden wie von den Shell-Skripten aufgerufen: JSON auf stdin,
    Ergebnis zeilenweise auf stdout.

Ausführung:
  python3 -m pytest tests/test_sync_parse.py -v
"""

import json
import pathlib
import subprocess
import sys
import unittest

SYNC_DIR = pathlib.Path(__file__).parent.parent / "sync"


def run(script, cmd, payload):
    """Startet das Hilfsskript mit `cmd` und `payload` als JSON auf stdin."""
    stdin = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(
        [sys.executable, str(SYNC_DIR / script), cmd],
        input=stdin, capture_output=True, text=True, check=False,
    )


class TestBbParse(unittest.TestCase):
    def test_cloud_urls_picks_https(self):
        """Cloud: nur der https-Link wird ausgegeben, ssh ignoriert."""
        data = {"values": [{"links": {"clone": [
            {"name": "https", "href": "https://bitbucket.org/ws/a.git"},
            {"name": "ssh", "href": "git@bitbucket.org:ws/a.git"}]}}]}
        self.assertEqual(run("bb_parse.py", "cloud-urls", data).stdout, "https://bitbucket.org/ws/a.git\n")

    def test_cloud_next_missing_is_empty(self):
        """Cloud: ohne `next` (letzte Seite) kommt eine Leerzeile."""
        self.assertEqual(run("bb_parse.py", "cloud-next", {"values": []}).stdout, "\n")

    def test_server_urls_picks_http(self):
        """Server: der Link heißt `http`, auch bei https-URL."""
        data = {"values": [{"links": {"clone": [
            {"name": "ssh", "href": "ssh://git@bb:7999/p/a.git"},
            {"name": "http", "href": "https://bb/scm/p/a.git"}]}}]}
        self.assertEqual(run("bb_parse.py", "server-urls", data).stdout, "https://bb/scm/p/a.git\n")

    def test_server_paging(self):
        """Server: isLastPage/nextPageStart, fehlendes isLastPage gilt als letzte Seite."""
        data = {"values": [], "isLastPage": False, "nextPageStart": 100}
        self.assertEqual(run("bb_parse.py", "server-islast", data).stdout, "false\n")
        self.assertEqual(run("bb_parse.py", "server-nextstart", data).stdout, "100\n")
        self.assertEqual(run("bb_parse.py", "server-islast", {}).stdout, "true\n")

    def test_unknown_command(self):
        """Unbekanntes Kommando: Exit-Code 1 und Usage auf stderr."""
        res = run("bb_parse.py", "nope", {})
        self.assertEqual(res.returncode, 1)
        self.assertIn("Usage", res.stderr)


REPOS = [
    {"name": "a", "clone_url": "https://fj.example/org/a.git", "ssh_url": "ssh://git@fj.example/org/a.git"},
    {"name": "b", "clone_url": "https://fj.example/org/b.git"},
    {"name": "c"},
]


class TestFjParse(unittest.TestCase):

    def test_urls(self):
        """Eine clone_url pro Zeile, Repo ohne clone_url ergibt Leerzeile."""
        res = run("fj_parse.py", "urls", REPOS)
        self.assertEqual(res.stdout, "https://fj.example/org/a.git\nhttps://fj.example/org/b.git\n\n")

    def test_count(self):
        """Anzahl der Einträge der Seite, 0 bei leerer Seite (Ende der Paginierung)."""
        self.assertEqual(run("fj_parse.py", "count", REPOS).stdout, "3\n")
        self.assertEqual(run("fj_parse.py", "count", []).stdout, "0\n")

    def test_error_object(self):
        """Forgejo-Fehlerobjekt statt Liste: Exit-Code 1 mit Meldung auf stderr."""
        res = run("fj_parse.py", "count", {"message": "GetOrgByName", "url": "https://fj.example/api/swagger"})
        self.assertEqual(res.returncode, 1)
        self.assertEqual(res.stdout, "")
        self.assertIn("GetOrgByName", res.stderr)

    def test_invalid_json(self):
        """Kein JSON auf stdin: Exit-Code ungleich 0."""
        self.assertNotEqual(run("fj_parse.py", "urls", "<html>").returncode, 0)

    def test_unknown_command(self):
        """Unbekanntes Kommando: Exit-Code 1 und Usage auf stderr."""
        res = run("fj_parse.py", "", [])
        self.assertEqual(res.returncode, 1)
        self.assertIn("Usage", res.stderr)


if __name__ == "__main__":
    unittest.main()
