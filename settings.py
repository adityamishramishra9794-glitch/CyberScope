"""Validated, persistent application settings with safe upper limits."""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from config.app_config import LIMITS, USER_AGENT_DEFAULT, app_data_dir

log = logging.getLogger(__name__)
THEMES = ("light", "dark")


@dataclass
class Settings:
    timeout: float = 8.0
    max_body_kb: int = 512
    max_requests: int = 40
    request_delay: float = 0.5
    export_dir: str = ""
    theme: str = "light"
    user_agent: str = USER_AGENT_DEFAULT

    @property
    def max_body_bytes(self) -> int:
        return int(self.max_body_kb) * 1024

    def to_dict(self) -> dict:
        return asdict(self)

    def clamped(self) -> "Settings":
        """Return a copy forced inside the safe limits (defence in depth for the engine)."""
        def clamp(v, key, cast):
            lo, hi = LIMITS[key]
            return cast(min(max(float(v), lo), hi))
        ua = self.user_agent if _valid_ua(self.user_agent) else USER_AGENT_DEFAULT
        return Settings(
            timeout=clamp(self.timeout, "timeout", float),
            max_body_kb=clamp(self.max_body_kb, "max_body_kb", int),
            max_requests=clamp(self.max_requests, "max_requests", int),
            request_delay=clamp(self.request_delay, "request_delay", float),
            export_dir=self.export_dir, theme=self.theme if self.theme in THEMES else "light",
            user_agent=ua,
        )


def _valid_ua(ua: Any) -> bool:
    return (isinstance(ua, str) and 1 <= len(ua.strip()) <= 200
            and all(32 <= ord(c) < 127 for c in ua))


def validate_settings(data: dict) -> tuple[Settings, list[str]]:
    """Validate a settings dict. Returns (settings_with_defaults_for_bad_values, errors)."""
    defaults, errors, out = Settings(), [], {}
    labels = {"timeout": "Connection timeout (s)", "max_body_kb": "Maximum response size (KB)",
              "max_requests": "Request limit per scan", "request_delay": "Request delay (s)"}
    for key, cast in (("timeout", float), ("max_body_kb", int),
                      ("max_requests", int), ("request_delay", float)):
        lo, hi = LIMITS[key]
        try:
            value = cast(data.get(key, getattr(defaults, key)))
        except (TypeError, ValueError):
            errors.append(f"{labels[key]} must be a number.")
            out[key] = getattr(defaults, key)
            continue
        if not (lo <= value <= hi):
            errors.append(f"{labels[key]} must be between {lo:g} and {hi:g}.")
            out[key] = getattr(defaults, key)
        else:
            out[key] = value
    export_dir = str(data.get("export_dir", "") or "").strip()
    if export_dir and not Path(export_dir).is_dir():
        errors.append("Default export directory does not exist.")
        export_dir = ""
    out["export_dir"] = export_dir
    theme = data.get("theme", "light")
    if theme not in THEMES:
        errors.append("Theme must be 'light' or 'dark'.")
        theme = "light"
    out["theme"] = theme
    ua = data.get("user_agent", USER_AGENT_DEFAULT)
    if not _valid_ua(ua):
        errors.append("User-agent must be 1-200 printable ASCII characters.")
        ua = USER_AGENT_DEFAULT
    out["user_agent"] = ua.strip()
    return Settings(**out), errors


def _path() -> Path:
    return app_data_dir() / "settings.json"


def load_settings(path: Path | None = None) -> Settings:
    path = path or _path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        settings, errors = validate_settings(data)
        if errors:
            log.warning("Some saved settings were invalid and were reset: %s", errors)
        return settings
    except FileNotFoundError:
        return Settings()
    except (OSError, ValueError) as exc:
        log.warning("Could not read settings (%s); using defaults.", type(exc).__name__)
        return Settings()


def save_settings(settings: Settings, path: Path | None = None) -> None:
    path = path or _path()
    path.write_text(json.dumps(settings.to_dict(), indent=2), encoding="utf-8")
