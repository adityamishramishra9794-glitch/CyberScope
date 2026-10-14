"""Shared data models and vocabulary."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ["Informational", "Low", "Medium", "High", "Critical"]
CONFIDENCES = ["High", "Medium", "Low"]
VALIDATION_STATES = ["Observed", "Needs Review", "Not Reproduced", "False Positive", "Accepted Risk"]
CLASSIFICATIONS = ["Observation", "Confirmed misconfiguration", "Potential concern"]

CHECKS = [
    ("dns", "DNS resolution", "Looks up the IP addresses of the target hostname."),
    ("http", "HTTP/HTTPS responses", "Checks whether the site answers over HTTP and HTTPS (status code, speed)."),
    ("redirects", "Redirect behavior", "Follows redirects one step at a time, only to hosts you authorized."),
    ("tls", "TLS certificate", "Inspects the HTTPS certificate: validity dates, hostname match, issuer."),
    ("headers", "HTTP security headers", "Reviews browser-protection headers such as HSTS and CSP."),
    ("cookies", "Cookie attributes", "Checks Secure/HttpOnly/SameSite flags. Cookie values are never stored."),
    ("metadata", "Public metadata files", "Fetches only /robots.txt, /sitemap.xml and /.well-known/security.txt."),
    ("technology", "Technology indicators", "Reads server/technology hints from ordinary responses."),
]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0


@dataclass
class ScanConfig:
    checks: dict = field(default_factory=lambda: {k: True for k, _, _ in CHECKS})
    authorization_confirmed: bool = False

    @classmethod
    def safe_default(cls, authorized: bool = False) -> "ScanConfig":
        return cls(checks={k: True for k, _, _ in CHECKS}, authorization_confirmed=authorized)

    def enabled(self, key: str) -> bool:
        return bool(self.checks.get(key, False))

    def to_dict(self) -> dict:
        return {"checks": dict(self.checks), "authorization_confirmed": self.authorization_confirmed}


@dataclass
class Finding:
    finding_id: str
    issue_key: str
    title: str
    severity: str
    confidence: str
    confidence_reason: str
    category: str
    check_type: str
    target: str
    classification: str
    validation_status: str
    description: str
    observation: str
    evidence: dict
    expected: str
    impact: str
    proves: str
    not_proves: str
    false_positive_notes: str
    remediation: str
    manual_verification: str
    cwe: str | None
    cwe_note: str
    timestamp: str
    user_note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        names = cls.__dataclass_fields__.keys()
        return cls(**{k: d.get(k, "" if k != "evidence" else {}) for k in names if k != "cwe"},
                   cwe=d.get("cwe"))


@dataclass
class ParsedCookie:
    """A cookie described by NAME and ATTRIBUTES only. The value is discarded at parse time."""
    name: str
    secure: bool
    httponly: bool
    samesite: str | None
    received_over: str  # "http" or "https"


@dataclass
class HttpObservation:
    url: str
    status: int | None = None
    headers: dict = field(default_factory=dict)   # lower-case name -> value
    cookies: list = field(default_factory=list)   # list[ParsedCookie]
    elapsed_ms: int = 0
    body: bytes = b""
    truncated: bool = False
    error_kind: str | None = None  # timeout|tls_error|connection_error|dns_error|request_error
    error_message: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and self.error_kind is None

    @property
    def location(self) -> str | None:
        return self.headers.get("location")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()


@dataclass
class ScanResult:
    scan_id: str
    timestamp: str
    target: str
    hostname: str
    status: str
    config: dict
    findings: list
    summary: dict
    requests_made: int = 0
    errors: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    duration_s: float = 0.0
    app_version: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() if isinstance(f, Finding) else f for f in self.findings]
        return d


def summarize(findings: list) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        d = f.to_dict() if isinstance(f, Finding) else f
        counts[d["severity"]] = counts.get(d["severity"], 0) + 1
    return {"total": len(findings), "by_severity": counts}
