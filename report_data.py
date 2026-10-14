"""Builds the sanitized report structure shared by the JSON and Markdown exporters."""
from __future__ import annotations

from config.app_config import APP_VERSION
from core.models import SEVERITIES
from core.redaction import redact_obj

LIMITATIONS = [
    "CyberScope performs a small set of safe, passive, non-destructive checks; it is not a full vulnerability scan.",
    "Findings describe observations from unauthenticated requests made at one point in time; results can differ by location, client and time.",
    "A missing security header or cookie flag is a hardening observation, not proof of an exploitable vulnerability.",
    "Only the home page and three standard metadata files were requested; other pages and authenticated areas were not tested.",
    "TLS inspection covers the single certificate and protocol negotiated in one handshake; protocol/cipher enumeration was not performed.",
    "Technology indicators are self-reported by the server and may be inaccurate. No vulnerability claims are made about them.",
    "Timeouts and connection errors are reported as incomplete checks, never as security weaknesses.",
    "Cookie values, passwords and tokens are never collected or exported.",
]
DISCLAIMER = ("This report is provided for defensive purposes for systems the user owns or is explicitly authorized to test. "
              "It carries no warranty and does not replace a professional security assessment.")


def build_report(scan: dict) -> dict:
    """Return a redacted, export-ready dict from a scan record (as returned by DatabaseManager.get_scan)."""
    findings = scan.get("findings", [])
    by = {s: 0 for s in SEVERITIES}
    for f in findings:
        by[f["severity"]] = by.get(f["severity"], 0) + 1
    report = {
        "application": "CyberScope", "application_version": APP_VERSION,
        "scan_id": scan["scan_id"], "scan_timestamp": scan["timestamp"],
        "target": scan["target"], "hostname": scan["hostname"], "scan_status": scan["status"],
        "scan_configuration": scan.get("config", {}),
        "summary": {"total_findings": len(findings), "by_severity": by,
                    "requests_made": scan.get("requests_made", 0), "duration_seconds": scan.get("duration_s", 0)},
        "scope_statement": (f"Only the authorized host '{scan['hostname']}' was assessed. Redirects to other hosts "
                            "were not followed. Subdomains were not scanned unless separately authorized."),
        "findings": findings,
        "scan_errors": scan.get("errors", []),
        "limitations": LIMITATIONS, "disclaimer": DISCLAIMER,
    }
    return redact_obj(report)
