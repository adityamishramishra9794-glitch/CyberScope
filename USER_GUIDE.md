# CyberScope V4 - User Guide

## Glossary
* **Allowlist** - the hosts you confirmed you may test. Nothing else is ever contacted.
* **HSTS** - header telling browsers to always use HTTPS for a site.
* **CSP** - header limiting where scripts/styles may load from; reduces the impact of injected code.
* **Cookie flags** - `Secure` (HTTPS only), `HttpOnly` (hidden from JavaScript), `SameSite` (limits cross-site sending).
* **TLS certificate** - proves a server's identity for HTTPS; must be in date, trusted and match the hostname.
* **CWE** - a public catalogue of weakness types. Shown only when the mapping is accurate; otherwise "needs review".

## Pages
* **Dashboard** - totals, severity counts, recent scans (double-click to open), delete / clear history (with confirmation).
* **New Scan** - target, authorization, allowlist, check selection, progress. Checks: DNS, HTTP/HTTPS, redirects, TLS, headers, cookies, metadata, technology.
* **Findings** - filter by text/severity/validation, sort by clicking headers, read full details, triage, export.
* **Settings** - timeout (1-30 s), response size (16-2048 KB), request limit (5-100), delay (0.25-10 s), export folder, theme, user-agent.

## Interpreting results
* A missing header is a *hardening gap*, not proof of a vulnerability; header findings never exceed **Low**.
* A timeout or connection error creates a "check incomplete" note, never a security finding.
* Validation **Needs Review** means a person should decide; **False Positive / Accepted Risk** record your decision locally.
* Each finding lists *what the evidence proves*, *what it does not prove*, false-positive considerations and manual verification steps.

## What CyberScope requests
Home page over HTTPS and HTTP (up to 5 redirects, only to allowlisted hosts), one TLS handshake, and exactly
`/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`. URLs listed inside those files are never requested.
