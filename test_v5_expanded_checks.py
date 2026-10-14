import json, tempfile, unittest
from pathlib import Path
from v5.expanded_checks import (
    validate_target, limited_port_scan, directory_discovery, review_checklist,
    redact_secret, write_expanded_reports
)

class ExpandedChecksTests(unittest.TestCase):
    def test_auth_gate(self):
        with self.assertRaises(PermissionError):
            validate_target("https://example.test", False, True)
    def test_bad_scheme(self):
        with self.assertRaises(ValueError):
            validate_target("file:///etc/passwd", True, True)
    def test_port_scan_gate(self):
        with self.assertRaises(PermissionError):
            limited_port_scan("127.0.0.1", [80], False, True)
    def test_port_limit(self):
        with self.assertRaises(ValueError):
            limited_port_scan("127.0.0.1", list(range(1,22)), True, True)
    def test_directory_paths_are_root_relative(self):
        with self.assertRaises(ValueError):
            directory_discovery("https://example.test", ["https://other.test"], True, True)
    def test_manual_checklist_categories(self):
        c=review_checklist()
        for key in ["idor_bola_bopla","xss","ssrf","csrf","authentication_session_password_reset",
                    "rate_limiting","file_upload","business_logic","github_osint","subdomain_takeover"]:
            self.assertIn(key,c)
    def test_redaction(self):
        self.assertIn("[REDACTED_SECRET_LIKE_VALUE]", redact_secret("api_key=verysecretvalue"))
    def test_report_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            jp,mp=write_expanded_reports([{"category":"test","title":"test","status":"observed",
                "severity":"info","target":"https://example.test","confidence":"low",
                "evidence":{"note":"safe"},"impact":"none","remediation":"none"}],d,"https://example.test")
            self.assertTrue(Path(jp).exists()); self.assertTrue(Path(mp).exists())
            self.assertIn("manual_review_templates",json.loads(Path(jp).read_text()))
if __name__ == "__main__": unittest.main()
