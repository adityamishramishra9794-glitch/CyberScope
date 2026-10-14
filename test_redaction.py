import unittest

from core.redaction import redact_cookie_header, redact_obj, redact_text, safe_url


class RedactionTests(unittest.TestCase):
    def test_cookie_value_redacted_name_kept(self):
        out = redact_cookie_header("sessionid=abc123SECRET; Path=/; Secure; HttpOnly")
        self.assertNotIn("abc123SECRET", out)
        self.assertIn("sessionid=[REDACTED]", out)
        self.assertIn("Secure; HttpOnly", out)

    def test_set_cookie_line_in_text(self):
        out = redact_text("Set-Cookie: sid=TOPSECRET; Path=/\nOther: fine")
        self.assertNotIn("TOPSECRET", out)
        self.assertIn("Other: fine", out)

    def test_headers_and_tokens(self):
        txt = "Authorization: Bearer abcdefgh12345678\nCookie: a=b; c=d\npassword=hunter2 api_key: XYZ123"
        out = redact_text(txt)
        for secret in ("abcdefgh12345678", "a=b", "hunter2", "XYZ123"):
            self.assertNotIn(secret, out)

    def test_nested_objects(self):
        out = redact_obj({"a": ["token=abc123"], "b": {"c": "Set-Cookie: x=y"}})
        self.assertNotIn("abc123", str(out))
        self.assertNotIn("x=y", str(out))

    def test_safe_url_strips_query_and_credentials(self):
        self.assertEqual(safe_url("https://u:p@example.com:8443/a?token=1#f"), "https://example.com:8443/a")


if __name__ == "__main__":
    unittest.main()
