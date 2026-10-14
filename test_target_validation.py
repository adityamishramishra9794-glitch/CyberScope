import unittest

from core.target_validation import TargetValidationError, normalize_hostname, normalize_target


class TargetValidationTests(unittest.TestCase):
    def test_plain_domain_defaults_to_https(self):
        t = normalize_target("Example.COM")
        self.assertEqual((t.hostname, t.scheme, t.port, t.url), ("example.com", "https", 443, "https://example.com/"))

    def test_url_path_query_fragment_dropped(self):
        t = normalize_target("https://example.com/a/b?x=1#frag")
        self.assertEqual(t.url, "https://example.com/")

    def test_trailing_dot_and_whitespace(self):
        self.assertEqual(normalize_target("  example.com.  ").hostname, "example.com")

    def test_explicit_port_kept(self):
        t = normalize_target("http://example.com:8080/")
        self.assertTrue(t.explicit_port)
        self.assertEqual(t.url, "http://example.com:8080/")

    def test_default_port_not_explicit(self):
        self.assertFalse(normalize_target("https://example.com:443").explicit_port)

    def test_idn_converted(self):
        self.assertEqual(normalize_target("bücher.example").hostname, "xn--bcher-kva.example")

    def test_ip_literals(self):
        self.assertTrue(normalize_target("http://127.0.0.1:8000").is_ip)
        self.assertEqual(normalize_target("https://[::1]/").hostname, "::1")

    def test_unsupported_schemes_blocked(self):
        for bad in ("ftp://example.com", "file:///etc/passwd", "javascript:alert(1)", "data:text/html,x",
                    "mailto:a@b.com", "gopher://example.com"):
            with self.subTest(bad=bad), self.assertRaises(TargetValidationError):
                normalize_target(bad)

    def test_invalid_inputs_blocked(self):
        for bad in ("", "   ", "exa mple.com", "http://", "-bad.com", "a..b.com", "*.example.com",
                    "http://user:pw@example.com", "http://example.com:99999", "2130706433", "//evil.com",
                    "x" * 3000):
            with self.subTest(bad=bad[:20]), self.assertRaises(TargetValidationError):
                normalize_target(bad)

    def test_normalize_hostname_rejects_empty(self):
        with self.assertRaises(TargetValidationError):
            normalize_hostname("")


if __name__ == "__main__":
    unittest.main()
