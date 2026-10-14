"""Per-scan context shared by all checks: findings, responses, redirect-safe fetching."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin

from config.app_config import MAX_REDIRECTS
from core.catalog import CATALOG
from core.evidence_validator import FindingRegistry, validate_evidence
from core.http_client import ScanCancelled
from core.models import Finding, HttpObservation, now_iso
from core.redaction import redact_obj, safe_url
from core.scope_manager import ScopeViolation
from core.severity import assign_confidence, assign_severity

log = logging.getLogger("cyberscope.context")
REDIRECT_CODES = (301, 302, 303, 307, 308)


class _SafeDict(dict):
    def __missing__(self, key):
        return "n/a"


@dataclass
class Chain:
    hops: list = field(default_factory=list)
    final: HttpObservation | None = None
    loop: bool = False
    excessive: bool = False
    blocked_redirect: str | None = None
    error: HttpObservation | None = None


class ScanContext:
    def __init__(self, target, config, settings, scope, client, resolve_fn, tls_fn,
                 cancel_event, progress=None):
        self.target, self.config, self.settings = target, config, settings
        self.scope, self.client = scope, client
        self.resolve_fn, self.tls_fn = resolve_fn, tls_fn
        self.cancel_event = cancel_event
        self._progress = progress or (lambda pct, name, msg: None)
        self.registry = FindingRegistry()
        self.findings: list[Finding] = []
        self.responses: list[HttpObservation] = []
        self.chains: dict[str, Chain] = {}
        self.primary: HttpObservation | None = None
        self._primary_resolved = False
        self.current_check = ""
        self.rejected: list[str] = []

    # ---- control ----------------------------------------------------------------------------
    def check_cancel(self) -> None:
        if self.cancel_event.is_set():
            raise ScanCancelled()

    def status(self, message: str, pct: int | None = None) -> None:
        self._progress(-1 if pct is None else pct, self.current_check, message)

    # ---- fetching ---------------------------------------------------------------------------
    def fetch_chain(self, url: str, follow: bool = True, max_hops: int = MAX_REDIRECTS) -> Chain:
        """GET url, following redirects manually. Scope is re-validated before EVERY hop."""
        chain, visited, current = Chain(), {url}, url
        for _ in range(max_hops + 1):
            self.check_cancel()
            obs = self.client.get(current)
            chain.hops.append(obs)
            self.responses.append(obs)
            chain.final = obs
            if not obs.ok:
                chain.error = obs
                break
            if follow and obs.status in REDIRECT_CODES and obs.location:
                nxt = urljoin(current, obs.location)
                try:
                    self.scope.check_url(nxt)
                except ScopeViolation:
                    chain.blocked_redirect = nxt
                    break
                if nxt in visited:
                    chain.loop = True
                    break
                visited.add(nxt)
                current = nxt
                continue
            break
        else:
            chain.excessive = True
        return chain

    def primary_response(self) -> HttpObservation | None:
        """Best response for header/cookie/technology analysis (HTTPS preferred)."""
        if self.primary is None and not self._primary_resolved:
            self._primary_resolved = True
            for scheme in ("https", "http"):
                chain = self.chains.get(scheme)
                if chain is None:
                    if self.target.explicit_port and scheme != self.target.scheme:
                        continue
                    port = f":{self.target.port}" if self.target.explicit_port else ""
                    chain = self.fetch_chain(f"{scheme}://{self.target.host_for_url}{port}/",
                                             follow=self.config.enabled("redirects"))
                    self.chains[scheme] = chain
                if chain.final is not None and chain.final.ok:
                    self.primary = chain.final
                    break
        return self.primary

    # ---- findings ---------------------------------------------------------------------------
    def add_finding(self, issue_key: str, observation: str, evidence: dict | None = None,
                    sev_ctx: dict | None = None, params: dict | None = None, response_ok: bool = True,
                    qualifier: str = "", check: str | None = None, error_kind: str | None = None,
                    classification: str | None = None, confidence: str | None = None,
                    confidence_reason: str | None = None) -> Finding | None:
        entry = CATALOG[issue_key]
        params = _SafeDict(params or {})
        severity, sev_reason = assign_severity(issue_key, sev_ctx)
        conf, conf_reason = assign_confidence(issue_key, sev_ctx)
        if confidence:
            conf, conf_reason = confidence, confidence_reason or conf_reason
        cls = classification or entry["classification"]
        ts = now_iso()
        draft = {"check": check or self.current_check, "target": self.target.hostname,
                 "observation": observation, "expected": entry["expected"], "evidence_timestamp": ts,
                 "classification": cls, "severity": severity, "response_ok": response_ok,
                 "error_kind": error_kind}
        result = validate_evidence(draft)
        if not result.ok:
            self.rejected.append(f"{issue_key}: {'; '.join(result.reasons)}")
            log.info("Finding %s rejected by evidence validation: %s", issue_key, result.reasons)
            return None
        if not self.registry.register(issue_key, self.target.hostname, qualifier):
            return None  # duplicate
        fmt = lambda s: s.format_map(params)  # noqa: E731
        ev = redact_obj({str(k): str(v) for k, v in (evidence or {}).items()})
        finding = Finding(
            finding_id=f"F-{len(self.findings) + 1:03d}", issue_key=issue_key, title=fmt(entry["title"]),
            severity=severity, confidence=conf, confidence_reason=conf_reason,
            category=entry["category"], check_type=draft["check"], target=self.target.hostname,
            classification=cls, validation_status="Needs Review" if cls == "Potential concern" else "Observed",
            description=fmt(entry["description"]), observation=redact_obj(observation), evidence=ev,
            expected=entry["expected"], impact=entry["impact"], proves=entry["proves"],
            not_proves=entry["not_proves"], false_positive_notes=entry["fp"],
            remediation=entry["remediation"], manual_verification=entry["verify"],
            cwe=entry["cwe"], cwe_note=entry["cwe_note"] if entry["cwe"] is None
            else f"{entry['cwe_note']}".strip(), timestamp=ts)
        finding.evidence["severity_reasoning"] = sev_reason
        self.findings.append(finding)
        return finding

    def incomplete(self, check_name: str, obs: HttpObservation | None, reason: str = "") -> None:
        kind = obs.error_kind if obs else None
        self.add_finding("check_incomplete",
                         observation=f"{check_name}: {reason or (obs.error_message if obs else 'no response')}",
                         params={"check_name": check_name, "reason": reason or (obs.error_message if obs else "no response")},
                         evidence={"error_kind": kind or "none", "url": safe_url(obs.url) if obs else "n/a"},
                         qualifier=check_name, error_kind=None)
