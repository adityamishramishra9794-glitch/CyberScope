import threading
import unittest

from core.checks.dns_check import DnsError
from core.checks.headers_check import csp_is_weak
from core.checks.tls_check import TlsProbeError
from core.http_client import parse_set_cookie
from core.models import ParsedCookie
from tests.helpers import keys, resp, run_scan

U = "https://example.test/"
HTML = {"content-type": "text/html"}


def site(**extra):
    r = {U: resp(U, headers=HTML, **extra), "http://example.test/": resp("http://example.test/", headers=HTML)}
    return r


class CheckTests(unittest.TestCase):
    def test_full_scan_on_bare_site_is_calibrated(self):
        result, _ = run_scan(site())
        k = keys(result)
        for expected in ("dns_resolved", "http_summary", "tls_info", "header_inventory", "hsts_missing",
                         "csp_missing", "http_no_https_redirect", "security_txt_missing", "technology_indicators"):
            self.assertIn(expected, k)
        self.assertEqual(result.status, "Completed")
        self.assertTrue(all(f.severity in ("Informational", "Low") for f in result.findings))
        for f in result.findings:            # every finding carries the required evidence fields
            self.assertTrue(f.observation and f.expected and f.timestamp and f.confidence_reason)
            self.assertIn(f.validation_status, ("Observed", "Needs Review"))
        self.assertEqual(result.summary["by_severity"]["High"], 0)

    def test_hardened_site_has_no_header_findings(self):
        hdr = {"content-type": "text/html", "strict-transport-security": "max-age=31536000",
               "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
               "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
               "permissions-policy": "camera=()"}
        routes = {U: resp(U, headers=hdr), "http://example.test/": resp("http://example.test/", 301, {"location": U})}
        result, _ = run_scan(routes)
        self.assertFalse([k for k in keys(result) if k.endswith("_missing") and "security_txt" not in k])
        self.assertNotIn("xfo_missing", keys(result))      # CSP frame-ancestors is an alternative protection
        self.assertNotIn("http_no_https_redirect", keys(result))

    def test_non_html_response_skips_html_only_headers(self):
        routes = {U: resp(U, headers={"content-type": "application/json"})}
        result, _ = run_scan(routes, checks=["http", "headers"])
        self.assertNotIn("csp_missing", keys(result))
        self.assertNotIn("xfo_missing", keys(result))

    def test_headers_on_error_page_are_not_flagged(self):
        routes = {U: resp(U, 503, HTML)}
        result, _ = run_scan(routes, checks=["http", "headers"])
        self.assertNotIn("csp_missing", keys(result))
        self.assertIn("http_unexpected_status", keys(result))

    def test_weak_csp_and_hsts(self):
        self.assertTrue(csp_is_weak("script-src 'self' 'unsafe-inline'"))
        self.assertFalse(csp_is_weak("script-src 'nonce-abc' 'unsafe-inline'"))
        self.assertFalse(csp_is_weak("default-src 'self'"))
        routes = {U: resp(U, headers={"content-type": "text/html", "strict-transport-security": "max-age=60"})}
        result, _ = run_scan(routes, checks=["http", "headers"])
        self.assertIn("hsts_weak", keys(result))

    def test_cookie_findings_and_no_values(self):
        cookies = [ParsedCookie("PHPSESSID", False, False, None, "https"),
                   ParsedCookie("prefs", True, False, "Lax", "https"),
                   ParsedCookie("x", False, True, "None", "https")]
        result, _ = run_scan(site(cookies=cookies), checks=["http", "redirects", "cookies"])
        k = keys(result)
        self.assertIn("cookie_missing_secure", k)
        self.assertIn("cookie_samesite_none_insecure", k)
        httponly = [f for f in result.findings if f.issue_key == "cookie_missing_httponly"]
        sev = {f.evidence["cookie"]: f.severity for f in httponly}
        self.assertEqual(sev["PHPSESSID"], "Low")            # session-like name
        self.assertEqual(sev["prefs"], "Informational")      # HttpOnly not universally mandatory
        self.assertTrue(all(f.evidence["value"] == "[REDACTED]" for f in result.findings if "cookie" in f.evidence))

    def test_parse_set_cookie_discards_value(self):
        c = parse_set_cookie("sessionid=SUPERSECRET; Path=/; Secure; HttpOnly; SameSite=lax", "https")
        self.assertEqual((c.name, c.secure, c.httponly, c.samesite), ("sessionid", True, True, "Lax"))
        self.assertNotIn("SUPERSECRET", repr(c))
        self.assertIsNone(parse_set_cookie("garbage", "https"))

    def test_metadata_states(self):
        base = "https://example.test"
        routes = site()
        routes[base + "/robots.txt"] = resp(base + "/robots.txt", headers={"content-type": "text/plain"},
                                            body=b"User-agent: *\nDisallow: /admin\nDisallow: /x\n")
        routes[base + "/sitemap.xml"] = resp(base + "/sitemap.xml", headers={"content-type": "text/html"},
                                             body=b"<!doctype html><html>spa fallback</html>")
        routes[base + "/.well-known/security.txt"] = resp(
            base + "/.well-known/security.txt", headers={"content-type": "text/plain"},
            body=b"Contact: mailto:sec@example.test\nExpires: 2099-01-01T00:00:00Z\n")
        result, client = run_scan(routes, checks=["http", "redirects", "metadata"])
        summary = next(f for f in result.findings if f.issue_key == "metadata_summary")
        self.assertIn("PRESENT", summary.evidence["/robots.txt"])
        self.assertIn("Disallow directives=2", summary.evidence["/robots.txt"])
        self.assertIn("UNCLEAR", summary.evidence["/sitemap.xml"])      # soft-404 not treated as a sitemap
        self.assertIn("security_txt_present", keys(result))
        self.assertFalse(any("/admin" in c for c in client.calls))      # discovered paths are never crawled
        fetched = {c.replace(base, "") for c in client.calls if c.startswith(base)} - {"/"}
        self.assertEqual(fetched, {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"})

    def test_expired_security_txt_flagged(self):
        base = "https://example.test"
        routes = site()
        routes[base + "/.well-known/security.txt"] = resp(
            base + "/.well-known/security.txt", headers={"content-type": "text/plain"},
            body=b"Contact: a@b.test\nExpires: 2001-01-01T00:00:00Z\n")
        result, _ = run_scan(routes, checks=["http", "redirects", "metadata"])
        self.assertIn("security_txt_invalid", keys(result))

    def test_technology_version_disclosure_makes_no_vuln_claim(self):
        routes = site()
        routes[U] = resp(U, headers={"content-type": "text/html", "server": "nginx/1.18.0"})
        result, _ = run_scan(routes, checks=["http", "technology"])
        f = next(f for f in result.findings if f.issue_key == "version_disclosure")
        self.assertEqual(f.severity, "Informational")
        self.assertIn("NOT mean", f.impact)
        ind = next(f for f in result.findings if f.issue_key == "technology_indicators")
        self.assertEqual(ind.confidence, "Low")

    def test_dns_failure_is_informational(self):
        def bad(host, timeout):
            raise DnsError("not_found", "no such host")
        result, _ = run_scan({}, checks=["dns"], resolve=bad)
        self.assertEqual(keys(result), ["dns_failed"])
        self.assertEqual(result.findings[0].severity, "Informational")

    def test_dns_resolution_is_not_a_vulnerability(self):
        result, _ = run_scan({}, checks=["dns"])
        self.assertEqual((result.findings[0].issue_key, result.findings[0].severity), ("dns_resolved", "Informational"))

    def test_tls_failures_map_accurately(self):
        for kind, expected in (("hostname_mismatch", "tls_hostname_mismatch"), ("invalid_dates", "tls_cert_invalid_dates"),
                               ("untrusted_chain", "tls_untrusted_chain"), ("timeout", "tls_unavailable"),
                               ("connection_error", "tls_unavailable")):
            def tls(h, p, t, kind=kind):
                raise TlsProbeError(kind, "simulated")
            result, _ = run_scan({}, checks=["tls"], tls=tls)
            self.assertEqual(keys(result), [expected], kind)

    def test_tls_timeout_is_not_a_certificate_finding(self):
        def tls(h, p, t):
            raise TlsProbeError("timeout", "timed out")
        result, _ = run_scan({}, checks=["tls"], tls=tls)
        self.assertNotIn("tls_cert_invalid_dates", keys(result))

    def test_tls_expiring_soon(self):
        from datetime import datetime, timedelta, timezone
        soon = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
        info = {"version": "TLSv1.3", "cipher": "x", "subject": "a", "issuer": "b", "not_before": "", "not_after": soon,
                "san_count": 1}
        result, _ = run_scan({}, checks=["tls"], tls=lambda h, p, t: info)
        self.assertIn("tls_cert_expiring_soon", keys(result))

    def test_one_failing_check_does_not_crash_scan(self):
        def boom(host, timeout):
            raise RuntimeError("unexpected")
        result, _ = run_scan(site(), checks=["dns", "http", "redirects", "headers"], resolve=boom)
        self.assertEqual(result.status, "Completed with errors")
        self.assertIn("hsts_missing", keys(result))     # later checks still ran

    def test_cancel_before_start(self):
        ev = threading.Event()
        ev.set()
        result, client = run_scan(site(), cancel=ev)
        self.assertEqual(result.status, "Cancelled")
        self.assertEqual(client.calls, [])


if __name__ == "__main__":
    unittest.main()
