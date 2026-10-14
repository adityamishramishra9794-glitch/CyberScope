"""End-to-end test of the REAL http client against a throw-away server on 127.0.0.1.
No external network is used."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from config.settings import Settings
from core.models import ScanConfig
from core.scan_engine import ScanEngine
from core.scope_manager import ScopeManager
from reports.json_exporter import to_json

SEEN_HOSTS = []
MODE = {"redirect": False}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        SEEN_HOSTS.append(self.headers.get("Host", ""))
        if MODE["redirect"] and self.path == "/":
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.server.server_port}/elsewhere")
            self.end_headers()
            return
        routes = {"/": ("text/html", b"<html><meta name='generator' content='DemoCMS 2.1'></html>"),
                  "/robots.txt": ("text/plain", b"User-agent: *\nDisallow: /private\n")}
        if self.path in routes:
            ctype, body = routes[self.path]
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Server", "demo-server/1.2.3")
            if self.path == "/":
                self.send_header("Set-Cookie", "sessionid=SUPERSECRETVALUE; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


class LocalIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_port
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def scan(self):
        SEEN_HOSTS.clear()
        scope = ScopeManager(["127.0.0.1"])
        engine = ScanEngine(f"http://127.0.0.1:{self.port}", ScanConfig.safe_default(True), Settings(), scope)
        return engine.run()

    def test_real_client_end_to_end(self):
        MODE["redirect"] = False
        result = self.scan()
        keys = [f.issue_key for f in result.findings]
        self.assertEqual(result.status, "Completed", result.errors)
        for k in ("dns_ip_literal", "http_summary", "header_inventory", "cookies_summary", "version_disclosure",
                  "metadata_summary", "security_txt_missing"):
            self.assertIn(k, keys)
        self.assertLessEqual(result.requests_made, 40)
        self.assertNotIn("SUPERSECRETVALUE", json.dumps(result.to_dict()))
        self.assertNotIn("SUPERSECRETVALUE", to_json(result.to_dict()))

    def test_redirect_to_other_hostname_is_not_followed(self):
        MODE["redirect"] = True
        try:
            result = self.scan()
        finally:
            MODE["redirect"] = False
        self.assertIn("redirect_out_of_scope", [f.issue_key for f in result.findings])
        self.assertFalse(any(h.startswith("localhost") for h in SEEN_HOSTS))   # never contacted


if __name__ == "__main__":
    unittest.main()
