"""Severity and confidence assignment. Severity reflects demonstrated impact and context;
confidence reflects how certain we are that the OBSERVATION is accurate. They are independent."""
from __future__ import annotations

from core.catalog import CATALOG
from core.models import CONFIDENCES, SEVERITIES, severity_rank

HEADER_CATEGORY = "HTTP Security Headers"
HEADER_CAP = "Low"  # a header gap alone can never exceed Low


def assign_severity(issue_key: str, context: dict | None = None) -> tuple[str, str]:
    """Return (severity, reason). `context` may contain:
    response_is_html (bool), is_redirect (bool), status (int), sensitive_name (bool),
    demonstrated_impact (bool: only set when real exploit evidence exists - no check sets it)."""
    context = context or {}
    entry = CATALOG[issue_key]
    sev = entry["severity"]
    reasons = [f"Base severity for this issue type is {sev}."]

    if entry["category"] == HEADER_CATEGORY and issue_key != "header_inventory":
        if issue_key in ("csp_missing", "xfo_missing", "referrer_policy_missing",
                         "permissions_policy_missing") and context.get("response_is_html") is False:
            sev = "Informational"
            reasons.append("Response is not an HTML page, so this header is largely irrelevant.")
        if context.get("is_redirect") or (context.get("status") and context["status"] >= 400):
            sev = "Informational"
            reasons.append("The inspected response was a redirect/error, not the real page.")
        if severity_rank(sev) > severity_rank(HEADER_CAP):
            sev = HEADER_CAP
            reasons.append("Header findings are capped at Low: a missing header alone proves no exploitable flaw.")
    if issue_key == "cookie_missing_httponly" and context.get("sensitive_name"):
        sev = "Low"
        reasons.append("Cookie name suggests a session/auth purpose, raising relevance slightly.")
    if issue_key == "cookie_missing_secure" and context.get("received_over") == "http":
        sev = "Informational"
        reasons.append("Cookie was received over plain HTTP, where the Secure flag cannot apply.")
    if severity_rank(sev) >= severity_rank("High") and not context.get("demonstrated_impact"):
        sev = "Medium"
        reasons.append("High/Critical require demonstrated impact; none was demonstrated by a safe check.")
    return sev, " ".join(reasons)


def assign_confidence(issue_key: str, context: dict | None = None) -> tuple[str, str]:
    """Return (confidence, reason). Confidence may be lowered by context, never raised above catalog."""
    context = context or {}
    entry = CATALOG[issue_key]
    conf, reason = entry["confidence"], entry["confidence_reason"]
    if context.get("response_degraded"):
        conf = "Low" if conf == "Medium" else "Medium" if conf == "High" else conf
        reason += " Confidence reduced: the supporting response was an error/redirect or truncated."
    return conf, reason


def max_severity(severities: list[str]) -> str:
    return max(severities, key=severity_rank) if severities else "Informational"
