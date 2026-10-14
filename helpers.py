"""Test helpers: a fake network client so no test touches a real website."""
from __future__ import annotations

import threading

from config.settings import Settings
from core.checks.tls_check import TlsProbeError  # noqa: F401
from core.models import HttpObservation, ParsedCookie, ScanConfig
from core.scan_engine import ScanEngine
from core.scope_manager import ScopeManager


def resp(url, status=200, headers=None, cookies=None, body=b"", error=None):
    h = {k.lower(): v for k, v in (headers or {"content-type": "text/html"}).items()}
    if error:
        return HttpObservation(url=url, error_kind=error, error_message=f"simulated {error}")
    return HttpObservation(url=url, status=status, headers=h, cookies=cookies or [], body=body, elapsed_ms=12)


class FakeClient:
    def __init__(self, scope, routes):
        self.scope, self.routes, self.requests_made, self.calls = scope, routes, 0, []

    def reserve(self, host):
        self.scope.require_host(host)
        self.requests_made += 1

    def get(self, url):
        target = self.scope.check_url(url)
        self.reserve(target.hostname)
        self.calls.append(url)
        return self.routes.get(url) or resp(url, 404)

    def close(self):
        pass


GOOD_TLS = {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "subject": "example.test",
            "issuer": "Test CA", "not_before": "Jan  1 00:00:00 2026 GMT",
            "not_after": "Jan  1 00:00:00 2099 GMT", "san_count": 2}


def run_scan(routes, hosts=("example.test",), target="example.test", checks=None, resolve=None, tls=None,
             cancel=None, authorized=True):
    scope = ScopeManager(hosts)
    client = FakeClient(scope, routes)
    config = ScanConfig.safe_default(authorized=authorized)
    if checks is not None:
        config.checks = {k: (k in checks) for k in config.checks}

    def default_resolve(host, timeout):
        return ["93.184.216.34"]

    def default_tls(host, port, timeout):
        return GOOD_TLS

    engine = ScanEngine(target, config, Settings(), scope, client=client,
                        resolve_fn=resolve or default_resolve, tls_fn=tls or default_tls,
                        cancel_event=cancel or threading.Event())
    return engine.run(), client


def keys(result):
    return [f.issue_key for f in result.findings]
