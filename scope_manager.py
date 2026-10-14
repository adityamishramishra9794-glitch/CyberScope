"""Authorized-target allowlist. Exact hostname matching only; no wildcards, no subdomain expansion."""
from __future__ import annotations

import threading
from typing import Iterable

from core.target_validation import NormalizedTarget, TargetValidationError, normalize_target


class ScopeViolation(Exception):
    """Raised when a request would leave the authorized scope."""


class ScopeManager:
    def __init__(self, allowed_hosts: Iterable[str] = ()):
        self._lock = threading.Lock()
        self._hosts: set[str] = set()
        for h in allowed_hosts:
            self.add(h)

    def add(self, raw: str) -> str:
        """Add a host (domain or URL). Returns the normalized hostname."""
        host = normalize_target(raw).hostname
        with self._lock:
            self._hosts.add(host)
        return host

    def remove(self, host: str) -> None:
        with self._lock:
            self._hosts.discard(host.strip().lower().rstrip("."))

    def allowed_hosts(self) -> list[str]:
        with self._lock:
            return sorted(self._hosts)

    def is_allowed(self, hostname: str) -> bool:
        try:
            host = normalize_target(hostname).hostname
        except TargetValidationError:
            return False
        with self._lock:
            return host in self._hosts

    def require_host(self, hostname: str) -> str:
        if not self.is_allowed(hostname):
            raise ScopeViolation(
                f"'{hostname}' is not in the authorized-target allowlist, so it was not contacted.")
        return hostname

    def check_url(self, url: str) -> NormalizedTarget:
        """Validate a full URL (scheme + host) against the allowlist before any request."""
        try:
            target = normalize_target(url)
        except TargetValidationError as exc:
            raise ScopeViolation(f"Blocked an invalid or unsupported URL: {exc}") from None
        self.require_host(target.hostname)
        return target
