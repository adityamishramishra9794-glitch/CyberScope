import unittest

from core.catalog import CATALOG
from core.models import CONFIDENCES, SEVERITIES, severity_rank
from core.severity import assign_confidence, assign_severity


class SeverityTests(unittest.TestCase):
    def test_every_catalog_entry_is_well_formed(self):
        for key, e in CATALOG.items():
            with self.subTest(key=key):
                self.assertIn(e["severity"], SEVERITIES)
                self.assertIn(e["confidence"], CONFIDENCES)
                self.assertTrue(e["confidence_reason"])
                self.assertTrue(e["proves"] and e["not_proves"] and e["remediation"] and e["verify"])
                self.assertTrue(e["cwe"] is None or e["cwe"].startswith("CWE-"))
                if e["cwe"] is None:
                    self.assertTrue(e["cwe_note"])          # uncertain mapping must say "needs review"

    def test_missing_header_never_exceeds_low(self):
        for k, e in CATALOG.items():
            if e["category"] == "HTTP Security Headers":
                sev, _ = assign_severity(k, {"response_is_html": True, "status": 200})
                self.assertLessEqual(severity_rank(sev), severity_rank("Low"), k)

    def test_header_on_redirect_or_non_html_is_informational(self):
        self.assertEqual(assign_severity("csp_missing", {"is_redirect": True})[0], "Informational")
        self.assertEqual(assign_severity("csp_missing", {"response_is_html": False})[0], "Informational")
        self.assertEqual(assign_severity("hsts_missing", {"status": 503})[0], "Informational")

    def test_no_automatic_high_or_critical(self):
        for k in CATALOG:
            sev, _ = assign_severity(k, {})
            self.assertLess(severity_rank(sev), severity_rank("High"), k)

    def test_httponly_is_context_dependent(self):
        self.assertEqual(assign_severity("cookie_missing_httponly", {"sensitive_name": False})[0], "Informational")
        self.assertEqual(assign_severity("cookie_missing_httponly", {"sensitive_name": True})[0], "Low")

    def test_secure_flag_over_http_not_reported_as_issue_severity(self):
        self.assertEqual(assign_severity("cookie_missing_secure", {"received_over": "http"})[0], "Informational")
        self.assertEqual(assign_severity("cookie_missing_secure", {"received_over": "https"})[0], "Low")

    def test_confidence_is_independent_and_degrades(self):
        base, _ = assign_confidence("csp_missing", {})
        degraded, reason = assign_confidence("csp_missing", {"response_degraded": True})
        self.assertEqual(base, "Medium")
        self.assertEqual(degraded, "Low")
        self.assertIn("reduced", reason)

    def test_severity_comes_with_reason(self):
        self.assertTrue(assign_severity("hsts_missing", {})[1])


if __name__ == "__main__":
    unittest.main()
