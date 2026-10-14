"""Redaction helpers: cookie values and secrets must never be stored, logged or exported."""
from __future__ import annotations

import re

REDACTED = "[REDACTED]"

_SET_COOKIE = re.compile(r"(?im)^(\s*set-cookie\s*:\s*)([^=;\s]+)=([^;\r\n]*)")
_COOKIE_HDR = re.compile(r"(?im)^(\s*cookie\s*:\s*)(.*)$")
_AUTH_HDR = re.compile(r"(?im)^(\s*(?:proxy-)?authorization\s*:\s*)(.*)$")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_KV_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|session(?:id)?|sid|jwt|auth)\b(\s*[=:]\s*)([^\s;&,\"']+)")


def redact_cookie_header(raw: str) -> str:
    """'sid=abc; Secure; HttpOnly' -> 'sid=[REDACTED]; Secure; HttpOnly'."""
    parts = raw.split(";")
    first = parts[0]
    name = first.split("=", 1)[0].strip()
    parts[0] = f"{name}={REDACTED}"
    return ";".join(parts)


def redact_text(text: str) -> str:
    """Scrub anything that looks like a cookie value, credential or token."""
    if not text:
        return text
    text = _SET_COOKIE.sub(lambda m: f"{m.group(1)}{m.group(2)}={REDACTED}", text)
    text = _COOKIE_HDR.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    text = _AUTH_HDR.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    text = _KV_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    return text


def redact_obj(obj):
    """Recursively redact every string inside dicts/lists (used before export)."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v) for v in obj]
    return obj


def safe_url(url: str) -> str:
    """Drop query string, fragment and credentials from a URL before it is stored."""
    from urllib.parse import urlsplit
    try:
        p = urlsplit(url)
        host = p.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        port = f":{p.port}" if p.port else ""
        return f"{p.scheme}://{host}{port}{p.path or '/'}"
    except ValueError:
        return "[unparseable URL]"
