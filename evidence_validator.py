"""Evidence validation and duplicate prevention: runs BEFORE any finding is created."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from core.models import CLASSIFICATIONS, SEVERITIES, severity_rank

REQUIRED = ("check", "target", "observation", "expected", "evidence_timestamp")


@dataclass
class ValidationResult:
    ok: bool
    reasons: list = field(default_factory=list)


def validate_evidence(draft: dict) -> ValidationResult:
    """Reject drafts that are not grounded in a real, successfully obtained observation."""
    reasons = []
    for key in REQUIRED:
        if not str(draft.get(key) or "").strip():
            reasons.append(f"Missing required evidence field: {key}.")
    cls = draft.get("classification")
    if cls not in CLASSIFICATIONS:
        reasons.append("Unknown finding classification.")
    sev = draft.get("severity", "Informational")
    if sev not in SEVERITIES:
        reasons.append("Unknown severity.")
    is_security_finding = cls != "Observation"
    if is_security_finding and not draft.get("response_ok"):
        reasons.append("A security finding requires a successfully obtained response; "
                       "timeouts and errors are not evidence of a weakness.")
    if is_security_finding and draft.get("error_kind"):
        reasons.append(f"The underlying request failed ({draft['error_kind']}).")
    if sev != "Informational" and cls == "Observation":
        reasons.append("Plain observations cannot carry a severity above Informational.")
    if severity_rank(sev) >= severity_rank("High") and not draft.get("demonstrated_impact"):
        reasons.append("High/Critical severity requires demonstrated impact.")
    return ValidationResult(ok=not reasons, reasons=reasons)


class FindingRegistry:
    """Thread-safe duplicate guard: one finding per (issue, target, qualifier)."""

    def __init__(self):
        self._seen: set = set()
        self._lock = threading.Lock()

    def register(self, issue_key: str, target: str, qualifier: str = "") -> bool:
        key = (issue_key, target, qualifier)
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            return True

    def __len__(self) -> int:
        return len(self._seen)
