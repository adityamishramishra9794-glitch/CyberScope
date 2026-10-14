"""Target validation and normalization. Only http(s) origins are accepted."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_BAD_SCHEME = re.compile(r"^(javascript|data|mailto|file|ftp|vbscript|ws|wss|gopher|ssh|telnet):", re.I)
_DEFAULT_PORTS = {"http": 80, "https": 443}


class TargetValidationError(ValueError):
    """Raised with a beginner-friendly message when a target is not acceptable."""


@dataclass(frozen=True)
class NormalizedTarget:
    hostname: str
    scheme: str
    port: int
    explicit_port: bool
    is_ip: bool
    scheme_given: bool

    @property
    def host_for_url(self) -> str:
        return f"[{self.hostname}]" if ":" in self.hostname else self.hostname

    @property
    def url(self) -> str:
        port = f":{self.port}" if self.explicit_port else ""
        return f"{self.scheme}://{self.host_for_url}{port}/"

    @property
    def display(self) -> str:
        return self.url


def normalize_hostname(host: str) -> str:
    """Lower-case, strip trailing dot, convert IDN to ASCII, validate. Returns normalized host."""
    if not host:
        raise TargetValidationError("The target has no hostname.")
    host = host.strip().rstrip(".").lower()
    if not host:
        raise TargetValidationError("The target has no hostname.")
    try:  # IP literal?
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise TargetValidationError(f"'{host}' is not a valid hostname.") from None
    if len(host) > 253:
        raise TargetValidationError("The hostname is too long.")
    labels = host.split(".")
    if not all(_LABEL.match(lbl) for lbl in labels):
        raise TargetValidationError(
            f"'{host}' is not a valid hostname (use letters, digits and hyphens; wildcards are not allowed).")
    if labels[-1].isdigit():
        raise TargetValidationError(f"'{host}' looks like a malformed IP address.")
    return host


def normalize_target(raw: str) -> NormalizedTarget:
    """Turn user input into a normalized origin. Raises TargetValidationError on bad input."""
    if raw is None or not str(raw).strip():
        raise TargetValidationError("Enter a domain name or an http(s) URL.")
    raw = str(raw).strip()
    if len(raw) > 2048:
        raise TargetValidationError("The target is too long.")
    if any(ch.isspace() or ord(ch) < 32 for ch in raw):
        raise TargetValidationError("The target must not contain spaces or control characters.")
    scheme_given = "://" in raw
    if not scheme_given:
        if _BAD_SCHEME.match(raw):
            raise TargetValidationError("Unsupported URL scheme. Only http and https are allowed.")
        if raw.startswith("//"):
            raise TargetValidationError("Enter a domain or a full http(s) URL.")
        raw_url = "https://" + raw
    else:
        raw_url = raw
    try:
        parts = urlsplit(raw_url)
        port = parts.port
    except ValueError:
        raise TargetValidationError("The URL is malformed or has an invalid port.") from None
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise TargetValidationError(f"Unsupported URL scheme '{scheme}'. Only http and https are allowed.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise TargetValidationError("URLs containing a username or password are not allowed.")
    host = normalize_hostname(parts.hostname or "")
    is_ip = True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_ip = False
    explicit = port is not None and port != _DEFAULT_PORTS[scheme]
    return NormalizedTarget(hostname=host, scheme=scheme, port=port or _DEFAULT_PORTS[scheme],
                            explicit_port=explicit, is_ip=is_ip, scheme_given=scheme_given)
