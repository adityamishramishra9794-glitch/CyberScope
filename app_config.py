"""Application-wide constants and path helpers."""
from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "CyberScope"
APP_VERSION = "4.0.0"
USER_AGENT_DEFAULT = f"CyberScope/{APP_VERSION} (authorized defensive assessment)"

# Hard safety ceilings: (minimum, maximum). Enforced by validation AND by the engine.
LIMITS = {
    "timeout": (1.0, 30.0),          # seconds
    "max_body_kb": (16, 2048),       # kilobytes read per response
    "max_requests": (5, 100),        # network operations per scan
    "request_delay": (0.25, 10.0),   # seconds between requests
}
MAX_REDIRECTS = 5
MAX_COOKIES_REPORTED = 25


def app_data_dir() -> Path:
    """Folder for the database, settings and logs (override with CYBERSCOPE_HOME)."""
    override = os.environ.get("CYBERSCOPE_HOME")
    if override:
        base = Path(override)
    elif os.name == "nt":
        base = Path(os.environ.get("APPDATA", str(Path.home()))) / "CyberScope"
    else:
        base = Path.home() / ".cyberscope"
    base.mkdir(parents=True, exist_ok=True)
    return base
