import threading
import unittest
from unittest import mock

from config.settings import Settings
from core.http_client import RequestBudgetExceeded, SafeHttpClient, ScanCancelled
from core.scope_manager import ScopeManager, ScopeViolation
from tests.helpers import FakeClient, keys, resp, run_scan


class AllowlistTests(unittest.TestCase):
    def test_exact_match_only(self):
        s = ScopeManager(["example.com"])
        self.assertTrue(s.is_allowed("EXAMPLE.com"))
        self.assertFalse(s.is_allowed("www.example.com"))     # subdomains are NOT implied
        self.assertFalse(s.is_allowed("evilexample.com"))
        self.assertFalse(s.is_allowed("example.com.evil.com"))

    def test_wildcards_rejected(self):
        with self.assertRaises(Exception):
            ScopeManager(["*.example.com"])

    def test_add_normalizes_url_input(self):
        s = ScopeManager()
        self.assertEqual(s.add("https://Example.com/path"), "example.com")
        s.remove("example.com")
        self.assertEqual(s.allowed_hosts(), [])

    def test_check_url_blocks_other_hosts_and_schemes(self):
        s = ScopeManager(["example.com"])
        s.check_url("https://example.com/robots.txt")
        for bad in ("https://other.com/", "ftp://example.com/", "https://example.com@evil.com/"):
            with self.subTest(bad=bad), self.assertRaises(ScopeViolation):
                s.check_url(bad)


class ClientEnforcementTests(unittest.TestCase):
    def test_client_refuses_out_of_scope_without_network(self):
        client = SafeHttpClient(ScopeManager(["a.test"]), Settings())
        with mock.patch.object(client._session, "get") as g:
            with self.assertRaises(ScopeViolation):
                client.get("http://b.test/")
            g.assert_not_called()
        self.assertEqual(client.requests_made, 0)

    def test_request_budget_enforced(self):
        client = SafeHttpClient(ScopeManager(["a.test"]), Settings(max_requests=5, request_delay=0.25))
        for _ in range(5):
            client.reserve("a.test")
        with self.assertRaises(RequestBudgetExceeded):
            client.reserve("a.test")

    def test_cancel_stops_requests(self):
        ev = threading.Event()
        client = SafeHttpClient(ScopeManager(["a.test"]), Settings(), ev)
        ev.set()
        with self.assertRaises(ScanCancelled):
            client.reserve("a.test")

    def test_settings_are_clamped_by_client(self):
        client = SafeHttpClient(ScopeManager(["a.test"]), Settings(max_requests=10**6, request_delay=0, timeout=999))
        self.assertEqual((client.settings.max_requests, client.settings.request_delay, client.settings.timeout),
                         (100, 0.25, 30.0))


class RedirectScopeTests(unittest.TestCase):
    def test_redirect_to_unapproved_host_is_not_followed(self):
        routes = {"http://example.test/": resp("http://example.test/", 301, {"location": "https://evil.test/x?token=abc"}),
                  "https://example.test/": resp("https://example.test/", 200)}
        result, client = run_scan(routes, checks=["http", "redirects"])
        self.assertFalse(any("evil.test" in c for c in client.calls))
        self.assertIn("redirect_out_of_scope", keys(result))
        f = next(f for f in result.findings if f.issue_key == "redirect_out_of_scope")
        self.assertNotIn("token=abc", str(f.to_dict()))        # query string stripped

    def test_redirect_to_allowed_host_is_followed(self):
        routes = {"https://example.test/": resp("https://example.test/", 301, {"location": "https://www.example.test/"}),
                  "https://www.example.test/": resp("https://www.example.test/", 200)}
        result, client = run_scan(routes, hosts=("example.test", "www.example.test"), checks=["http", "redirects"])
        self.assertIn("https://www.example.test/", client.calls)

    def test_redirect_loop_detected(self):
        a, b = "https://example.test/", "https://example.test/a"
        routes = {a: resp(a, 302, {"location": b}), b: resp(b, 302, {"location": a})}
        result, _ = run_scan(routes, checks=["http", "redirects"])
        self.assertIn("redirect_loop", keys(result))

    def test_excessive_redirects_detected(self):
        routes = {}
        for i in range(10):
            u = "https://example.test/" if i == 0 else f"https://example.test/{i}"
            routes[u] = resp(u, 302, {"location": f"https://example.test/{i + 1}"})
        result, _ = run_scan(routes, checks=["http", "redirects"])
        self.assertIn("redirect_excessive", keys(result))

    def test_engine_refuses_unlisted_target_and_unconfirmed_auth(self):
        from core.scan_engine import ScanRefused
        with self.assertRaises(ScanRefused):
            run_scan({}, hosts=("other.test",))
        with self.assertRaises(ScanRefused):
            run_scan({}, authorized=False)
        with self.assertRaises(ScanRefused):
            run_scan({}, target="ftp://example.test")


if __name__ == "__main__":
    unittest.main()
