import json
import os
import tempfile
import unittest

from core.models import ParsedCookie
from database.database_manager import DatabaseManager
from reports.json_exporter import ExportError, export_json, to_json
from reports.markdown_exporter import export_markdown, to_markdown
from tests.helpers import resp, run_scan


def sample_scan():
    cookies = [ParsedCookie("sessionid", False, False, None, "https")]
    routes = {"https://example.test/": resp("https://example.test/", cookies=cookies),
              "http://example.test/": resp("http://example.test/")}
    result, _ = run_scan(routes)
    scan = result.to_dict()
    scan["findings"][0]["user_note"] = "checked by me, password=hunter2"
    scan["findings"][0]["evidence"]["leak"] = "Set-Cookie: sessionid=TOPSECRETVALUE; Path=/"
    return scan


class ReportTests(unittest.TestCase):
    def test_json_is_valid_and_complete(self):
        data = json.loads(to_json(sample_scan()))
        for key in ("application_version", "scan_id", "scan_timestamp", "target", "scan_configuration", "summary",
                    "findings", "limitations", "scope_statement"):
            self.assertIn(key, data)
        f = data["findings"][0]
        for key in ("evidence", "confidence", "severity", "cwe", "validation_status", "remediation"):
            self.assertIn(key, f)
        self.assertEqual(data["summary"]["total_findings"], len(data["findings"]))

    def test_markdown_structure(self):
        md = to_markdown(sample_scan())
        for heading in ("# CyberScope Security Assessment Report", "## Executive Summary", "## Scope Statement",
                        "## Summary of Findings", "## Findings", "## Limitations", "## Disclaimer"):
            self.assertIn(heading, md)
        self.assertIn("Potential impact", md)
        self.assertIn("Remediation", md)

    def test_exports_never_contain_secrets(self):
        scan = sample_scan()
        for text in (to_json(scan), to_markdown(scan)):
            for secret in ("TOPSECRETVALUE", "hunter2"):
                self.assertNotIn(secret, text)

    def test_export_to_files_and_permission_error(self):
        scan = sample_scan()
        with tempfile.TemporaryDirectory() as d:
            j, m = os.path.join(d, "r.json"), os.path.join(d, "r.md")
            export_json(scan, j)
            export_markdown(scan, m)
            with open(j, encoding="utf-8") as fh:
                json.load(fh)
            with open(m, encoding="utf-8") as fh:
                self.assertIn("CyberScope", fh.read())
            with self.assertRaises(ExportError):
                export_json(scan, os.path.join(d, "missing_dir", "r.json"))

    def test_report_from_database_includes_user_validation(self):
        with tempfile.TemporaryDirectory() as d:
            db = DatabaseManager(os.path.join(d, "t.db"))
            result, _ = run_scan({"https://example.test/": resp("https://example.test/")})
            db.save_scan(result)
            fid = result.findings[0].finding_id
            db.update_validation(result.scan_id, fid, "Accepted Risk", "approved by owner")
            md = to_markdown(db.get_scan(result.scan_id))
            self.assertIn("Accepted Risk", md)
            self.assertIn("approved by owner", md)


if __name__ == "__main__":
    unittest.main()
