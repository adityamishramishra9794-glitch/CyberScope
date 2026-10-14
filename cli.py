"""Minimal headless interface (smoke tests, automation). Scope rules are identical to the GUI."""
from __future__ import annotations

import argparse

from config.app_config import app_data_dir
from config.settings import load_settings
from core.models import CHECKS, ScanConfig
from core.scan_engine import ScanEngine, ScanRefused
from core.scope_manager import ScopeManager
from core.target_validation import TargetValidationError, normalize_target
from database.database_manager import DatabaseManager
from reports.json_exporter import ExportError, export_json
from reports.markdown_exporter import export_markdown


def run_cli(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="main.py --cli", description="CyberScope headless scan")
    p.add_argument("--cli", required=True, metavar="TARGET", help="domain or http(s) URL to scan")
    p.add_argument("--confirm-authorized", action="store_true",
                   help="confirm you own the target or have explicit permission (required)")
    p.add_argument("--only", help="comma-separated checks: " + ",".join(k for k, _, _ in CHECKS))
    p.add_argument("--json"), p.add_argument("--markdown")
    args = p.parse_args(argv[1:])
    if not args.confirm_authorized:
        print("Refusing to scan: pass --confirm-authorized to confirm you may test this target.")
        return 2
    try:
        host = normalize_target(args.cli).hostname
    except TargetValidationError as exc:
        print(f"Invalid target: {exc}")
        return 2
    db = DatabaseManager(app_data_dir() / "cyberscope.db")
    db.add_allowlist(host)             # the explicit flag above is the authorization statement
    scope = ScopeManager(db.list_allowlist())
    config = ScanConfig.safe_default(authorized=True)
    if args.only:
        wanted = {c.strip() for c in args.only.split(",")}
        config.checks = {k: k in wanted for k in config.checks}
    try:
        result = ScanEngine(args.cli, config, load_settings(), scope,
                            progress=lambda pct, name, msg: print(f"[{pct:>3}%] {msg}" if pct >= 0 else f"       {msg}")).run()
    except ScanRefused as exc:
        print(f"Scan refused: {exc}")
        return 2
    db.save_scan(result)
    print(f"\n{result.status}: {len(result.findings)} findings, {result.requests_made} requests, scan id {result.scan_id}")
    for f in result.findings:
        print(f"  {f.finding_id}  {f.severity:<13} {f.confidence:<6} {f.title}")
    scan = db.get_scan(result.scan_id)
    try:
        if args.json:
            print("JSON report:", export_json(scan, args.json))
        if args.markdown:
            print("Markdown report:", export_markdown(scan, args.markdown))
    except ExportError as exc:
        print(exc)
        return 1
    return 0
