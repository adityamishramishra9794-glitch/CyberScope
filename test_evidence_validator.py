import unittest

from core.evidence_validator import FindingRegistry, validate_evidence
from tests.helpers import keys, resp, run_scan


def draft(**kw):
    d = {"check": "headers", "target": "example.test", "observation": "header absent", "expected": "present",
         "evidence_timestamp": "2026-01-01T00:00:00Z", "classification": "Potential concern",
         "severity": "Low", "response_ok": True, "error_kind": None}
    d.update(kw)
    return d


class EvidenceTests(unittest.TestCase):
    def test_valid_draft_passes(self):
        self.assertTrue(validate_evidence(draft()).ok)

    def test_missing_fields_rejected(self):
        for k in ("observation", "expected", "check", "evidence_timestamp", "target"):
            self.assertFalse(validate_evidence(draft(**{k: ""})).ok, k)

    def test_timeout_cannot_create_security_finding(self):
        r = validate_evidence(draft(response_ok=False, error_kind="timeout"))
        self.assertFalse(r.ok)

    def test_observation_may_describe_a_failure(self):
        self.assertTrue(validate_evidence(draft(classification="Observation", severity="Informational",
                                                response_ok=False, error_kind="timeout")).ok)

    def test_high_requires_demonstrated_impact(self):
        self.assertFalse(validate_evidence(draft(severity="High")).ok)
        self.assertTrue(validate_evidence(draft(severity="High", demonstrated_impact=True)).ok)

    def test_observation_cannot_have_severity(self):
        self.assertFalse(validate_evidence(draft(classification="Observation", severity="Medium")).ok)

    def test_duplicate_prevention(self):
        reg = FindingRegistry()
        self.assertTrue(reg.register("hsts_missing", "example.test"))
        self.assertFalse(reg.register("hsts_missing", "example.test"))
        self.assertTrue(reg.register("cookie_missing_secure", "example.test", "sid"))
        self.assertTrue(reg.register("cookie_missing_secure", "example.test", "other"))
        self.assertFalse(reg.register("cookie_missing_secure", "example.test", "sid"))

    def test_scan_does_not_duplicate_findings(self):
        # same cookie arrives on two responses -> exactly one finding per issue
        from core.models import ParsedCookie
        c = ParsedCookie("sid", False, False, None, "https")
        routes = {"https://example.test/": resp("https://example.test/", cookies=[c]),
                  "http://example.test/": resp("http://example.test/", cookies=[c])}
        result, _ = run_scan(routes, checks=["http", "redirects", "cookies"])
        self.assertEqual(keys(result).count("cookie_missing_httponly"), 1)

    def test_timeout_produces_no_security_findings(self):
        routes = {"https://example.test/": resp("https://example.test/", error="timeout"),
                  "http://example.test/": resp("http://example.test/", error="timeout")}
        result, _ = run_scan(routes)
        self.assertTrue(result.findings)
        self.assertTrue(all(f.classification == "Observation" for f in result.findings))
        self.assertNotIn("hsts_missing", keys(result))
        self.assertNotIn("csp_missing", keys(result))
        self.assertIn("check_incomplete", keys(result))


if __name__ == "__main__":
    unittest.main()
