"""JSON report export."""
from __future__ import annotations

import json
from pathlib import Path

from reports.report_data import build_report


class ExportError(Exception):
    """User-presentable export failure."""


def to_json(scan: dict) -> str:
    return json.dumps(build_report(scan), indent=2, ensure_ascii=False)


def export_json(scan: dict, path: str | Path) -> Path:
    path = Path(path)
    try:
        path.write_text(to_json(scan), encoding="utf-8")
    except PermissionError:
        raise ExportError(f"Permission denied writing to {path}. Choose a folder you can write to.") from None
    except OSError as exc:
        raise ExportError(f"The report could not be saved: {exc.strerror or exc}") from None
    return path
