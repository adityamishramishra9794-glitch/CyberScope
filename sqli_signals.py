"""
CyberScope V5: conservative SQL-injection signal checks.
Only run against targets you own or are explicitly authorised to test.

This module deliberately does NOT:
- extract database contents or enumerate schemas/tables/users,
- run password cracking,
- invoke sqlmap or exploit payload collections,
- attempt stacked queries, time-delay exploitation, or destructive statements.

It performs a small number of paired, low-impact requests and reports signals
as "needs review", never as confirmed SQL injection based on an error string alone.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
import json
import re
import subprocess
import time
import urllib.error
import urllib.request

SQL_ERROR_PATTERNS = [
    re.compile(r"sql syntax.*(?:mysql|mariadb)", re.I),
    re.compile(r"mysql_fetch|mysqli?_query|pdoexception", re.I),
    re.compile(r"postgresql.*(?:error|exception)|psycopg", re.I),
    re.compile(r"sqlite(?:3)?\.OperationalError|sqlite error", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"SQL Server.*(?:error|exception)|Unclosed quotation mark", re.I),
    re.compile(r"ODBC SQL Server Driver", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
]

@dataclass
class CheckResult:
    check: str
    status: str
    severity: str
    url: str
    evidence: dict[str, Any]
    confidence: str
    impact: str
    remediation: str

def _normalise_url(url: str) -> str:
    p = urlsplit(url.strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Target must be a full http:// or https:// URL")
    if p.username or p.password:
        raise ValueError("Credentials embedded in URLs are not allowed")
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))

def _fetch_stdlib(url: str, timeout: float = 8.0) -> tuple[int, str, dict[str, str]]:
    req = urllib.request.Request(
        url, headers={"User-Agent": "CyberScope-V5/1.0 (authorised-safe-check)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(512_000)
            return resp.status, raw.decode("utf-8", "replace"), dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        body = e.read(512_000).decode("utf-8", "replace")
        return e.code, body, dict(e.headers.items())
    except Exception as e:
        return 0, "", {"x-cyberscope-error": type(e).__name__}

def curl_request(url: str, timeout: int = 8) -> tuple[int, str, str]:
    """Use curl when installed; return status, body, stderr. Safe GET only."""
    if not shutil_which("curl"):
        status, body, headers = _fetch_stdlib(url, timeout)
        return status, body, "curl not installed; used Python HTTP client"
    cmd = [
        "curl", "--silent", "--show-error", "--location", "--max-redirs", "3",
        "--max-time", str(timeout), "--connect-timeout", "4",
        "--user-agent", "CyberScope-V5/1.0 (authorised-safe-check)",
        "--output", "-", "--write-out", "\n__CS_HTTP_STATUS__:%{http_code}",
        url,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2, check=False)
        marker = "\n__CS_HTTP_STATUS__:"
        body = p.stdout
        status = 0
        if marker in body:
            body, tail = body.rsplit(marker, 1)
            try: status = int(tail.strip())
            except ValueError: status = 0
        return status, body[:512_000], p.stderr[:1000]
    except Exception as e:
        return 0, "", f"curl execution failed: {type(e).__name__}"

def shutil_which(name: str):
    import shutil
    return shutil.which(name)

def _error_matches(body: str) -> list[str]:
    return [p.pattern for p in SQL_ERROR_PATTERNS if p.search(body)]

def safe_sql_signal_check(url: str, authorised: bool = False,
                          allowlisted: bool = False) -> list[dict[str, Any]]:
    """
    Conservative URL-query parameter signal check.
    Requires explicit authorisation and an allowlist pass from the calling app.
    Uses only baseline GET plus harmless quote-character comparison.
    This is a signal check, not proof of exploitability.
    """
    if not authorised or not allowlisted:
        raise PermissionError("Explicit authorisation and allowlist validation are required")
    base_url = _normalise_url(url)
    parts = urlsplit(base_url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return [asdict(CheckResult(
            check="SQLi signal check", status="not_applicable", severity="info",
            url=base_url, evidence={"reason": "No query parameters to assess"},
            confidence="none", impact="No query parameter was available for this limited check.",
            remediation="If relevant, test parameter handling in a dedicated staging environment."
        ))]
    # Limit scope and request count: inspect only first 3 query parameters.
    results = []
    for key, value in params[:3]:
        baseline_url = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                  urlencode([(k, v) for k, v in params]), ""))
        altered = list(params)
        # Only append a single quote; no boolean/time/stacked/extraction payloads.
        replaced = False
        for i, (k, v) in enumerate(altered):
            if k == key and not replaced:
                altered[i] = (k, v + "'")
                replaced = True
                break
        test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(altered), ""))
        t0 = time.monotonic()
        b_status, b_body, b_err = curl_request(baseline_url)
        baseline_ms = round((time.monotonic() - t0) * 1000)
        time.sleep(0.6)  # gentle pacing
        t1 = time.monotonic()
        t_status, t_body, t_err = curl_request(test_url)
        test_ms = round((time.monotonic() - t1) * 1000)
        baseline_errors = _error_matches(b_body)
        test_errors = _error_matches(t_body)
        new_errors = [p for p in test_errors if p not in baseline_errors]
        status_changed = b_status != t_status and b_status and t_status
        if new_errors:
            status, severity, confidence = "needs_review", "medium", "low"
            summary = "A database-like error signature appeared only in the modified response."
        elif status_changed or (b_status and t_status and abs(len(t_body)-len(b_body)) > max(1200, int(len(b_body)*0.5))):
            status, severity, confidence = "needs_review", "low", "low"
            summary = "Response changed after a quote-character input; this is not proof of SQL injection."
        else:
            status, severity, confidence = "no_signal", "info", "low"
            summary = "No obvious SQL error signature or large response change was detected."
        results.append(asdict(CheckResult(
            check="SQLi signal check", status=status, severity=severity, url=test_url,
            evidence={
                "parameter": key, "baseline_http_status": b_status, "test_http_status": t_status,
                "baseline_body_length": len(b_body), "test_body_length": len(t_body),
                "baseline_duration_ms": baseline_ms, "test_duration_ms": test_ms,
                "new_error_signatures": new_errors,
                "baseline_transport_note": b_err, "test_transport_note": t_err,
                "note": summary,
            },
            confidence=confidence,
            impact="If confirmed manually, unsafe query construction may expose or alter database-backed application behaviour. This check does not access database contents.",
            remediation="Use parameterised queries/prepared statements, avoid string concatenation in SQL, apply least-privilege database accounts, and keep detailed database errors out of user-facing responses."
        )))
        time.sleep(0.6)
    return results

def write_reports(results: list[dict[str, Any]], out_dir: str, target: str) -> tuple[str, str]:
    """Write both JSON and Markdown reports into a dedicated reports directory."""
    from pathlib import Path
    p = Path(out_dir)
    p.mkdir(parents=True, exist_ok=True)
    stem = "cyberscope_v5_report"
    json_path = p / f"{stem}.json"
    md_path = p / f"{stem}.md"
    payload = {
        "tool": "CyberScope V5",
        "target": target,
        "disclaimer": "Signals require manual verification; no database contents were extracted.",
        "findings": results,
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# CyberScope V5 Report", "",
        f"- **Target:** `{target}`",
        "- **Mode:** Conservative, non-destructive signal checks",
        "- **Important:** Signals are not confirmed vulnerabilities; manually verify in an authorised test environment.",
        "", "## Findings", ""
    ]
    if not results:
        lines.append("No checks were run.")
    for i, item in enumerate(results, 1):
        ev = item.get("evidence", {})
        lines += [
            f"### {i}. {item.get('check', 'Check')}",
            f"- **Status:** {item.get('status')}",
            f"- **Severity:** {item.get('severity')}",
            f"- **Confidence:** {item.get('confidence')}",
            f"- **URL:** `{item.get('url')}`",
            f"- **Impact:** {item.get('impact')}",
            f"- **Remediation:** {item.get('remediation')}",
            "- **Evidence:**",
            "```json",
            json.dumps(ev, indent=2, ensure_ascii=False),
            "```", ""
        ]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return str(json_path), str(md_path)
