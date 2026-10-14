import json
import tempfile
import unittest
from pathlib import Path
from v5.sqli_signals import safe_sql_signal_check, write_reports, _normalise_url

class V5SafeSqlSignalTests(unittest.TestCase):
    def test_requires_authorisation(self):
        with self.assertRaises(PermissionError):
            safe_sql_signal_check("https://example.test/?q=x", authorised=False, allowlisted=True)

    def test_requires_allowlist(self):
        with self.assertRaises(PermissionError):
            safe_sql_signal_check("https://example.test/?q=x", authorised=True, allowlisted=False)

    def test_url_validation(self):
        with self.assertRaises(ValueError):
            _normalise_url("file:///etc/passwd")
        with self.assertRaises(ValueError):
            _normalise_url("https://user:pass@example.test/")

    def test_no_query_is_not_applicable(self):
        result = safe_sql_signal_check("https://example.test/search", authorised=True, allowlisted=True)
        self.assertEqual(result[0]["status"], "not_applicable")

    def test_writes_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as d:
            jp, mp = write_reports([{"check":"test","status":"no_signal","severity":"info",
                "url":"https://example.test","evidence":{"ok":True},"confidence":"low",
                "impact":"none","remediation":"none"}], d, "https://example.test")
            self.assertTrue(Path(jp).exists())
            self.assertTrue(Path(mp).exists())
            self.assertEqual(json.loads(Path(jp).read_text())["tool"], "CyberScope V5")
            self.assertIn("# CyberScope V5 Report", Path(mp).read_text())

if __name__ == "__main__":
    unittest.main()
