"""Controlled HTTP client. Scope, request budget, pacing, cancellation and size limits are
enforced HERE, on every single request, regardless of what the GUI or a check asks for."""
from __future__ import annotations

import logging
import threading
import time

import requests

from config.settings import Settings
from core.models import HttpObservation, ParsedCookie
from core.redaction import redact_text
from core.scope_manager import ScopeManager

log = logging.getLogger("cyberscope.http")


class ScanCancelled(Exception):
    """The user cancelled the scan."""


class RequestBudgetExceeded(Exception):
    """The per-scan request limit was reached."""


def parse_set_cookie(raw: str, scheme: str) -> ParsedCookie | None:
    """Parse a Set-Cookie header into name + flags. The cookie VALUE is discarded immediately."""
    parts = [p.strip() for p in raw.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    secure = httponly = False
    samesite = None
    for attr in parts[1:]:
        key, _, val = attr.partition("=")
        key = key.strip().lower()
        if key == "secure":
            secure = True
        elif key == "httponly":
            httponly = True
        elif key == "samesite":
            samesite = val.strip().capitalize() or None
    return ParsedCookie(name=name, secure=secure, httponly=httponly, samesite=samesite, received_over=scheme)


def _classify(exc: Exception) -> tuple[str, str]:
    text = str(exc)
    low = text.lower()
    if isinstance(exc, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout,
                        requests.exceptions.Timeout)):
        return "timeout", "The server did not answer within the timeout."
    if isinstance(exc, requests.exceptions.SSLError):
        return "tls_error", "The TLS/SSL handshake or certificate validation failed."
    if any(s in low for s in ("name or service not known", "getaddrinfo failed",
                              "temporary failure in name resolution", "nodename nor servname",
                              "failed to resolve")):
        return "dns_error", "The hostname could not be resolved."
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection_error", "The connection was refused, reset or unreachable."
    return "request_error", "The request could not be completed."


class SafeHttpClient:
    def __init__(self, scope: ScopeManager, settings: Settings, cancel_event: threading.Event | None = None):
        self.scope = scope
        self.settings = settings.clamped()
        self.cancel_event = cancel_event or threading.Event()
        self.requests_made = 0
        self._last = 0.0
        self._session = requests.Session()
        self._session.trust_env = False  # ignore proxy env vars and .netrc credentials
        self._session.headers.update({"User-Agent": self.settings.user_agent,
                                      "Accept": "*/*", "Connection": "close"})

    # -- shared guards used by HTTP, TLS and any other network operation ----------------------
    def reserve(self, hostname: str) -> None:
        """Gate before ANY network operation: cancel -> scope -> budget -> pacing."""
        if self.cancel_event.is_set():
            raise ScanCancelled()
        self.scope.require_host(hostname)
        if self.requests_made >= self.settings.max_requests:
            raise RequestBudgetExceeded(
                f"The request limit for this scan ({self.settings.max_requests}) was reached.")
        wait = self.settings.request_delay - (time.monotonic() - self._last)
        if wait > 0 and self.cancel_event.wait(wait):
            raise ScanCancelled()
        if self.cancel_event.is_set():
            raise ScanCancelled()
        self.requests_made += 1
        self._last = time.monotonic()

    def get(self, url: str) -> HttpObservation:
        target = self.scope.check_url(url)          # raises ScopeViolation for out-of-scope URLs
        self.reserve(target.hostname)
        obs = HttpObservation(url=url)
        started = time.monotonic()
        resp = None
        try:
            resp = self._session.get(
                url, timeout=(self.settings.timeout, self.settings.timeout), stream=True,
                allow_redirects=False, verify=True)       # TLS verification is never disabled
            body, truncated, limit = b"", False, self.settings.max_body_bytes
            for chunk in resp.iter_content(chunk_size=8192):
                body += chunk
                if len(body) >= limit:
                    body, truncated = body[:limit], True
                    break
            obs.status = resp.status_code
            obs.headers = {k.lower(): v for k, v in resp.headers.items()}
            try:
                raw_cookies = resp.raw.headers.getlist("Set-Cookie")
            except Exception:
                raw_cookies = [resp.headers["Set-Cookie"]] if "Set-Cookie" in resp.headers else []
            for raw in raw_cookies:
                parsed = parse_set_cookie(raw, target.scheme)
                if parsed:
                    obs.cookies.append(parsed)
            obs.body, obs.truncated = body, truncated
        except requests.exceptions.RequestException as exc:
            obs.error_kind, obs.error_message = _classify(exc)
            log.debug("Request failed (%s): %s", obs.error_kind, redact_text(str(exc)))
        finally:
            obs.elapsed_ms = int((time.monotonic() - started) * 1000)
            if resp is not None:
                resp.close()
        return obs

    def close(self) -> None:
        self._session.close()
