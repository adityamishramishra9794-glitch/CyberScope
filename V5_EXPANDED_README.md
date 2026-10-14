# CyberScope V5 Expanded Checks

This adds conservative, modular checks and manual validation templates. Use only on owned or explicitly authorised assets and wire `authorised` + `allowlisted` to the app's real scope-confirmation state.

## Added modules
- Limited TCP connect scan: up to 20 caller-selected ports; no service banner probing.
- Technology profiling: passive HTTP headers and HTML indicators.
- JavaScript/form inventory: collects same-origin script URLs and basic form metadata; does not execute JS or crawl external hosts.
- Directory/path discovery: caller-supplied paths only, maximum 25 per run, GET-only, paced; no huge wordlists.
- Security headers and CORS observation.
- Expanded JSON and Markdown reporting with secret-like string redaction.
- Manual validation templates for IDOR/BOLA/BOPLA, XSS, SSRF, CSRF, authentication/session/password reset, rate limiting, file uploads, business logic, public GitHub OSINT, and subdomain takeover.

## Intentionally not automated
No password/OTP brute force, no database dumping or schema enumeration, no exploit payloads, no SSRF to internal/cloud metadata addresses, no malicious upload files, no use of discovered credentials, no registering dangling subdomains, and no tests against other users' data. These areas require controlled test accounts, staging systems, and human-led validation.

## Integration
```python
from v5.expanded_checks import (
    limited_port_scan, technology_profile, javascript_and_forms,
    passive_security_headers, directory_discovery, review_checklist,
    write_expanded_reports
)

# Example only; replace with a system you own or have written permission to test.
# Wire flags to the app's actual authorisation/allowlist controls.
findings = technology_profile(
    "https://staging.example.test/", authorised=True, allowlisted=True
)
json_path, markdown_path = write_expanded_reports(
    findings, "reports", "https://staging.example.test/"
)
```

Do not expose a public API that lets a user set the authorisation flags arbitrarily. They must reflect independently verified scope and consent.
