"""Scan engine: authorization, scope and limits are enforced here, independent of any GUI."""
from __future__ import annotations

import logging
import threading
import time
import uuid

from config.app_config import APP_VERSION
from config.settings import Settings
from core.checks import PIPELINE
from core.checks.dns_check import resolve_host
from core.checks.tls_check import probe_tls
from core.context import ScanContext
from core.http_client import RequestBudgetExceeded, SafeHttpClient, ScanCancelled
from core.models import ScanConfig, ScanResult, now_iso, severity_rank, summarize
from core.scope_manager import ScopeManager, ScopeViolation
from core.target_validation import TargetValidationError, normalize_target

log = logging.getLogger("cyberscope.engine")


class ScanRefused(Exception):
    """The scan was refused before any network activity (bad target, no authorization, out of scope)."""


class ScanEngine:
    def __init__(self, target_input: str, config: ScanConfig, settings: Settings, scope: ScopeManager,
                 progress=None, cancel_event: threading.Event | None = None,
                 client=None, resolve_fn=None, tls_fn=None):
        self.target_input, self.config = target_input, config
        self.settings = settings.clamped()
        self.scope = scope
        self.progress = progress or (lambda pct, name, msg: None)
        self.cancel_event = cancel_event or threading.Event()
        self._client = client
        self.resolve_fn = resolve_fn or resolve_host
        self.tls_fn = tls_fn or probe_tls

    def _preflight(self):
        if not self.config.authorization_confirmed:
            raise ScanRefused("You must confirm that you own the target or have explicit permission to test it.")
        try:
            target = normalize_target(self.target_input)
        except TargetValidationError as exc:
            raise ScanRefused(str(exc)) from None
        if not self.scope.is_allowed(target.hostname):
            raise ScanRefused(f"'{target.hostname}' is not in your authorized-target allowlist. "
                              "Add it on the New Scan page first.")
        if not any(self.config.enabled(k) for ks, _, _ in PIPELINE for k in ks):
            raise ScanRefused("Select at least one check to run.")
        return target

    def run(self) -> ScanResult:
        target = self._preflight()
        started = time.monotonic()
        client = self._client or SafeHttpClient(self.scope, self.settings, self.cancel_event)
        ctx = ScanContext(target, self.config, self.settings, self.scope, client, self.resolve_fn,
                          self.tls_fn, self.cancel_event, self.progress)
        steps = [(ks, name, fn) for ks, name, fn in PIPELINE if any(self.config.enabled(k) for k in ks)]
        errors, status = [], "Completed"
        try:
            for i, (_, name, fn) in enumerate(steps):
                ctx.current_check = name
                self.progress(int(i * 100 / len(steps)), name, f"Starting: {name}")
                try:
                    ctx.check_cancel()
                    fn(ctx)
                except ScanCancelled:
                    status = "Cancelled"
                    break
                except RequestBudgetExceeded as exc:
                    errors.append(str(exc))
                    status = "Completed with errors"
                    break
                except ScopeViolation as exc:
                    errors.append(f"{name}: blocked by scope protection - {exc}")
                    status = "Completed with errors"
                except Exception as exc:  # one failing check must never crash the scan
                    log.exception("Check %s failed", name)
                    errors.append(f"{name} could not be completed ({type(exc).__name__}). See the log for details.")
                    status = "Completed with errors"
            else:
                self.progress(100, "Done", "Scan finished")
            if status == "Completed with errors" and self.cancel_event.is_set():
                status = "Cancelled"
        finally:
            requests_made = getattr(client, "requests_made", 0)
            if self._client is None:
                client.close()
        findings = sorted(ctx.findings, key=lambda f: (-severity_rank(f.severity), f.finding_id))
        for n, f in enumerate(findings, 1):   # re-number after sorting so IDs read top-down
            f.finding_id = f"F-{n:03d}"
        notes = list(ctx.rejected)
        return ScanResult(scan_id=uuid.uuid4().hex[:12], timestamp=now_iso(), target=target.url,
                          hostname=target.hostname, status=status, config=self.config.to_dict(),
                          findings=findings, summary=summarize(findings), requests_made=requests_made,
                          errors=errors, notes=notes, duration_s=round(time.monotonic() - started, 2),
                          app_version=APP_VERSION)
