"""
CyberScope V5 expanded, conservative assessment helpers.

Only use against assets you own or have explicit permission to assess.
These helpers prioritise observation and low-impact validation. They do not
brute-force credentials, exploit vulnerabilities, dump databases, or bypass
access controls. Sensitive-looking strings are redacted in output.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from html.parser import HTMLParser
from urllib.parse import urlsplit, urljoin, parse_qsl
from typing import Any
import json, re, socket, ssl, time, urllib.request, urllib.error
from pathlib import Path

@dataclass
class Finding:
    category: str
    title: str
    status: str
    severity: str
    target: str
    confidence: str
    evidence: dict[str, Any]
    impact: str
    remediation: str
    manual_validation_required: bool = True

def validate_target(url: str, authorised: bool, allowlisted: bool) -> str:
    if not authorised or not allowlisted:
        raise PermissionError("Explicit authorisation and allowlist validation are required.")
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Use a complete http:// or https:// URL.")
    if p.username or p.password:
        raise ValueError("Credentials embedded in target URLs are not allowed.")
    return url

def _get(url: str, timeout: float = 7.0, limit: int = 300_000):
    req = urllib.request.Request(url, headers={"User-Agent": "CyberScope-V5/1.0 (authorised assessment)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(limit).decode("utf-8", "replace")
            return r.status, dict(r.headers.items()), body, None
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), e.read(limit).decode("utf-8", "replace"), None
    except Exception as e:
        return 0, {}, "", type(e).__name__

def technology_profile(url: str, authorised=False, allowlisted=False) -> list[dict]:
    validate_target(url, authorised, allowlisted)
    status, headers, body, err = _get(url)
    clues = {}
    for k in ("server", "x-powered-by", "x-generator", "via"):
        if k in {x.lower() for x in headers}:
            clues[k] = next((v for hk,v in headers.items() if hk.lower() == k), "")
    html_clues = []
    for pattern, label in [
        (r"wp-content|wp-includes", "WordPress indicator"),
        (r"content=\"Drupal", "Drupal indicator"),
        (r"__NEXT_DATA__|/_next/", "Next.js indicator"),
        (r"ng-version|angular", "Angular indicator"),
        (r"data-reactroot|react-dom", "React indicator"),
        (r"cdn\.shopify\.com", "Shopify indicator"),
    ]:
        if re.search(pattern, body, re.I): html_clues.append(label)
    return [asdict(Finding(
        "technology", "Technology profiling", "observed" if status else "error", "info",
        url, "low" if clues or html_clues else "none",
        {"http_status": status, "headers": clues, "html_indicators": html_clues, "transport_error": err},
        "Technology clues can help defenders inventory exposed stack details; fingerprinting is not a vulnerability by itself.",
        "Avoid unnecessarily exposing precise server versions and keep frameworks and CMS components patched."
    ))]

def limited_port_scan(host: str, ports: list[int], authorised=False, allowlisted=False,
                      timeout: float = 0.5, max_ports: int = 20) -> list[dict]:
    """TCP connect checks for at most 20 caller-selected ports; no banner grabbing."""
    if not authorised or not allowlisted:
        raise PermissionError("Explicit authorisation and allowlist validation are required.")
    if not host or any(c in host for c in "/@ "):
        raise ValueError("Provide a hostname only, without URL path or credentials.")
    if len(ports) > max_ports or any(not isinstance(p, int) or p < 1 or p > 65535 for p in ports):
        raise ValueError("Supply up to 20 valid TCP port numbers.")
    out = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            code = s.connect_ex((host, port))
            state = "open" if code == 0 else "closed_or_filtered"
        except OSError as e:
            state = "error:" + type(e).__name__
        finally:
            s.close()
        out.append(asdict(Finding(
            "port_scan", f"TCP port {port}", state, "info", f"{host}:{port}", "medium",
            {"port": port, "state": state, "method": "TCP connect; no service probing"},
            "An open port is not automatically a vulnerability; confirm that the service is expected.",
            "Close unused services, restrict management interfaces, and patch exposed services."
        )))
        time.sleep(0.05)
    return out

class _HTMLLinks(HTMLParser):
    def __init__(self):
        super().__init__(); self.scripts=[]; self.links=[]; self.forms=[]
    def handle_starttag(self, tag, attrs):
        a=dict(attrs)
        if tag == "script" and a.get("src"): self.scripts.append(a["src"])
        if tag == "a" and a.get("href"): self.links.append(a["href"])
        if tag == "form":
            self.forms.append({"action":a.get("action",""), "method":a.get("method","get").lower(),
                               "has_csrf_like_field":False})
    def handle_startendtag(self, tag, attrs): self.handle_starttag(tag, attrs)
    def handle_data(self, data):
        if data.strip().lower() in ("csrf", "csrf_token", "authenticity_token", "_token"):
            for f in self.forms: f["has_csrf_like_field"] = True

def javascript_and_forms(url: str, authorised=False, allowlisted=False) -> list[dict]:
    """Collect same-origin script URLs and basic form metadata; does not execute JS."""
    validate_target(url, authorised, allowlisted)
    status, headers, body, err = _get(url)
    parser = _HTMLLinks()
    try: parser.feed(body)
    except Exception: pass
    base = urlsplit(url)
    scripts = []
    for item in parser.scripts[:80]:
        resolved = urljoin(url, item)
        p = urlsplit(resolved)
        if p.scheme in ("http", "https") and p.hostname == base.hostname:
            scripts.append(resolved)
    forms = parser.forms[:50]
    return [asdict(Finding(
        "javascript_analysis", "JavaScript and form inventory", "observed" if status else "error",
        "info", url, "medium", {"http_status":status, "same_origin_scripts":sorted(set(scripts)),
        "forms":forms, "transport_error":err},
        "Inventory can reveal exposed endpoints and forms, but does not prove a security issue.",
        "Review client-side code for secrets; never place private API keys in browser JavaScript. Enforce CSRF and server-side authorisation."
    ))]

def passive_security_headers(url: str, authorised=False, allowlisted=False) -> list[dict]:
    validate_target(url, authorised, allowlisted)
    status, headers, body, err = _get(url)
    lower = {k.lower():v for k,v in headers.items()}
    checks = [
        ("content-security-policy", "Content-Security-Policy"),
        ("strict-transport-security", "Strict-Transport-Security"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
    ]
    results=[]
    for key, label in checks:
        missing = key not in lower
        results.append(asdict(Finding(
            "security_headers", f"{label} header", "needs_review" if missing else "present",
            "low" if missing else "info", url, "high",
            {"http_status":status, "header":label, "present":not missing, "value":lower.get(key,""), "transport_error":err},
            "Missing headers may weaken browser-side protections depending on application context.",
            f"Assess whether {label} is appropriate for this application and configure a policy compatible with its functionality."
        )))
    # CORS is only observed using an ordinary request; do not spoof arbitrary Origin.
    cors = {k:v for k,v in lower.items() if k.startswith("access-control-")}
    results.append(asdict(Finding(
        "cors", "CORS response headers", "observed" if cors else "no_cors_headers_observed",
        "info", url, "low", {"headers":cors},
        "CORS headers alone do not prove exploitable cross-origin access.",
        "If credentials are used, avoid wildcard origins and validate allowed origins server-side."
    )))
    return results

def directory_discovery(url: str, paths: list[str], authorised=False, allowlisted=False,
                        max_paths: int = 25) -> list[dict]:
    """Small caller-supplied path list, GET only, paced, no wordlist expansion."""
    validate_target(url, authorised, allowlisted)
    if len(paths) > max_paths: raise ValueError(f"At most {max_paths} paths per run.")
    origin = urlsplit(url)
    results=[]
    for path in paths:
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise ValueError("Each path must begin with a single slash.")
        target = urljoin(url, path)
        if urlsplit(target).hostname != origin.hostname:
            raise ValueError("Cross-origin paths are not allowed.")
        status, headers, body, err = _get(target)
        results.append(asdict(Finding(
            "directory_discovery", "Path response observed", "observed" if status else "error",
            "info", target, "medium", {"http_status":status, "content_length":len(body),
            "content_type":next((v for k,v in headers.items() if k.lower()=="content-type"),""),
            "transport_error":err},
            "A reachable path is not inherently a vulnerability; verify whether its content should be public.",
            "Restrict sensitive administrative or backup paths and avoid exposing debug files."
        )))
        time.sleep(0.25)
    return results

def review_checklist() -> dict:
    """Human-led workflow templates for issues that cannot safely be confirmed by blind automation."""
    return {
      "idor_bola_bopla": {
        "mode":"manual_two_account_validation",
        "steps":["Use two test accounts you control and create test records in each.",
                 "Record each account's own object identifier.",
                 "Request only the other test account's test object using the normal UI/API.",
                 "Verify server-side access denial; do not read or modify real users' data."],
        "evidence":["sanitised request/response","account roles used","expected versus actual access"]
      },
      "xss": {"mode":"staging_only_safe_marker",
              "steps":["Use a non-executable unique text marker in an authorised test field.",
                       "Check whether it is returned as text or encoded in HTML.",
                       "Do not use script execution payloads on production targets."],
              "evidence":["input field","encoded response context","browser rendering screenshot if applicable"]},
      "ssrf": {"mode":"configuration_and_code_review_first",
               "steps":["Review URL-fetch features and server-side allowlists.",
                        "In staging, use an organisation-controlled callback endpoint only.",
                        "Never target cloud metadata IPs, localhost, or internal networks."],
               "evidence":["sanitised feature request","controlled callback log","allowlist behaviour"]},
      "csrf": {"mode":"manual_workflow_review",
               "steps":["Use a test account and a non-destructive state-changing action.",
                        "Check CSRF token validation, SameSite cookie policy, and Origin/Referer validation.",
                        "Do not submit cross-site actions against real accounts."],
               "evidence":["sanitised request","token behaviour","cookie attributes"]},
      "authentication_session_password_reset": {
        "mode":"manual_test_accounts_only",
        "steps":["Review logout invalidation, session rotation after login, reset-token expiry and single use.",
                 "Use only test accounts and issued reset links.",
                 "Do not guess passwords, OTPs, or reset tokens."],
        "evidence":["test account state","expiry/reuse result","sanitised timestamps and response codes"]},
      "rate_limiting": {"mode":"configuration_or_low_volume_staging_check",
                        "steps":["Inspect configured limits and server-side counters.",
                                 "Use a tiny, pre-agreed request budget in staging.",
                                 "Do not automate password/OTP guessing or lock out users."],
                        "evidence":["request budget","response status","Retry-After or rate-limit headers"]},
      "file_upload": {"mode":"benign_fixture_only",
                      "steps":["Use a harmless text fixture in staging.",
                               "Verify extension/content-type validation, storage location and access controls.",
                               "Do not upload web shells, malware, or polyglot payloads."],
                      "evidence":["sanitised upload request","stored filename/type","download access policy"]},
      "business_logic": {"mode":"manual_test_account_only",
                         "steps":["Use sandbox products/orders and test payment methods.",
                                  "Verify price, discount, quantity and ownership on the server.",
                                  "Never bypass payment or create real unpaid orders."],
                         "evidence":["expected server-calculated value","observed sandbox result"]},
      "github_osint": {"mode":"public_metadata_review",
                       "steps":["Review only public repositories and organisation-approved assets.",
                                "Use provider search/API within its terms and scope.",
                                "Do not attempt to use discovered credentials; redact any secret-like values."],
                       "evidence":["public repository URL","file path and line range","redacted token fingerprint"]},
      "subdomain_takeover": {"mode":"dns_and_provider_configuration_review",
                             "steps":["Check DNS CNAME and provider response metadata.",
                                      "Do not claim a takeover from a dangling CNAME alone.",
                                      "Do not claim or register the dangling resource."],
                             "evidence":["DNS answer","provider response","manual ownership verification"]}
    }

def redact_secret(text: str) -> str:
    """Redact common token/key shapes before reports; not a secret scanner guarantee."""
    patterns = [
        r"""(?i)(api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*["']?[^\s,"']+""",
        r'\bgh[pousr]_[A-Za-z0-9_]{20,}\b',
        r'\bAKIA[0-9A-Z]{16}\b',
        r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b',
    ]
    result=text
    for pat in patterns:
        result=re.sub(pat, "[REDACTED_SECRET_LIKE_VALUE]", result)
    return result

def write_expanded_reports(findings: list[dict], out_dir: str, target: str) -> tuple[str,str]:
    p=Path(out_dir); p.mkdir(parents=True,exist_ok=True)
    clean=[]
    for f in findings:
        item=dict(f)
        item["evidence"]=json.loads(json.dumps(item.get("evidence",{}), default=str))
        item["evidence"]={k:(redact_secret(v) if isinstance(v,str) else v) for k,v in item["evidence"].items()}
        clean.append(item)
    payload={"tool":"CyberScope V5 Expanded","target":target,
             "disclaimer":"Use only with explicit authorisation. Findings may need manual verification.",
             "findings":clean,"manual_review_templates":review_checklist()}
    jp=p/"cyberscope_v5_expanded.json"; mp=p/"cyberscope_v5_expanded.md"
    jp.write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")
    lines=["# CyberScope V5 Expanded Report","",f"- **Target:** `{target}`",
           "- **Scope:** Authorised assets only; conservative checks.",
           "- **Caution:** Automated signals are not proof. Manually verify before reporting.","","## Findings",""]
    if not clean: lines.append("No findings supplied.")
    for i,f in enumerate(clean,1):
        lines += [f"### {i}. {f.get('title',f.get('category','Finding'))}",
                  f"- **Category:** {f.get('category')}",f"- **Status:** {f.get('status')}",
                  f"- **Severity:** {f.get('severity')}",f"- **Confidence:** {f.get('confidence')}",
                  f"- **Target:** `{f.get('target')}`",
                  f"- **Impact:** {f.get('impact')}",f"- **Remediation:** {f.get('remediation')}",
                  "- **Evidence:**","```json",json.dumps(f.get("evidence",{}),indent=2,ensure_ascii=False),"```",""]
    lines += ["## Manual review templates","",
              "The JSON report contains checklists for IDOR/BOLA/BOPLA, XSS, SSRF, CSRF, authentication/session/password-reset, rate limits, file uploads, business logic, public GitHub OSINT, and subdomain-takeover review."]
    mp.write_text("\n".join(lines),encoding="utf-8")
    return str(jp),str(mp)
