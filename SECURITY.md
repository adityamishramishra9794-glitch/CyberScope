# CyberScope V4 - Security Design

## Safety guarantees (enforced in code, not only in the GUI)
| Control | Where enforced |
|---|---|
| Authorization must be confirmed | `ScanEngine._preflight` refuses otherwise |
| Exact-hostname allowlist, no wildcards | `ScopeManager`; engine pre-flight; **`SafeHttpClient.get/reserve` before every request** |
| Redirects revalidated per hop, never followed off-scope | `ScanContext.fetch_chain` |
| Per-scan request cap (<=100), pacing (>=0.25 s), timeout (<=30 s), body cap (<=2 MB) | `SafeHttpClient`; settings are clamped again by the engine |
| Global cancellation | `threading.Event` checked before each request and check |
| TLS verification never disabled | `requests verify=True`; `ssl.create_default_context()` |
| Proxy env vars / .netrc ignored | `session.trust_env = False` |
| Cookie values never stored | Parsed to name+flags at the HTTP layer (`ParsedCookie` has no value field) |
| Secrets redacted in DB, logs, reports | `core/redaction.py`, applied at save/export/log time |
| No findings from failed requests | `core/evidence_validator.py` |

## Not included by design
Exploits, injection payloads, credential attacks, auth bypass, DoS, brute-forcing, crawling, port scanning.

## Residual risks and limitations
* An allowlisted hostname is trusted; if its DNS is changed to point elsewhere, the scanner follows DNS.
* Passive checks cannot prove or rule out exploitable vulnerabilities.
* TLS: one handshake only; protocol/cipher enumeration is not performed.
* Authenticated areas, JavaScript-rendered content and non-root pages are not assessed.
* Redaction is pattern-based; review reports before sharing.
* The GUI layer is not covered by automated tests.
