"""SQLite persistence: scan history, findings (with validation state + notes), allowlist.
A fresh connection is used per call, so the manager is safe to use from worker threads.
No cookie values, passwords or tokens are ever stored (evidence is redacted before it reaches here)."""
from __future__ import annotations

import json
import logging
import shutil
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from core.models import SEVERITIES, VALIDATION_STATES, now_iso
from core.redaction import redact_obj, redact_text

log = logging.getLogger("cyberscope.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, target TEXT NOT NULL, hostname TEXT NOT NULL,
    status TEXT NOT NULL, config_json TEXT NOT NULL, summary_json TEXT NOT NULL,
    requests_made INTEGER DEFAULT 0, duration_s REAL DEFAULT 0, app_version TEXT DEFAULT '',
    errors_json TEXT DEFAULT '[]', notes_json TEXT DEFAULT '[]');
CREATE TABLE IF NOT EXISTS findings (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, finding_id TEXT NOT NULL,
    severity TEXT NOT NULL, validation_status TEXT NOT NULL, user_note TEXT DEFAULT '',
    data_json TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE TABLE IF NOT EXISTS authorized_targets (hostname TEXT PRIMARY KEY, added_at TEXT NOT NULL);
"""


class DatabaseError(Exception):
    """User-presentable database problem."""


class DatabaseManager:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.recovered_from: Path | None = None   # set when a corrupted DB was moved aside
        self._init()

    # ---- connection helpers -----------------------------------------------------------------
    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            log.error("Database error: %s", redact_text(str(exc)))
            raise DatabaseError("The local database reported an error. Details were saved to the log.") from None
        finally:
            conn.close()

    def _init(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._conn() as c:
                if c.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise sqlite3.DatabaseError("integrity check failed")
                c.executescript(SCHEMA)
        except (sqlite3.DatabaseError, DatabaseError):
            self._recover()

    def _recover(self) -> None:
        """Move a corrupted database aside and start fresh instead of crashing."""
        backup = self.path.with_name(f"{self.path.name}.corrupt-{now_iso().replace(':', '')}")
        try:
            if self.path.exists():
                shutil.move(str(self.path), str(backup))
                self.recovered_from = backup
            with self._conn() as c:
                c.executescript(SCHEMA)
        except (OSError, sqlite3.Error) as exc:
            raise DatabaseError(f"The scan history database could not be opened or repaired: {exc}") from None

    # ---- scans ------------------------------------------------------------------------------
    def save_scan(self, result) -> str:
        d = result.to_dict() if hasattr(result, "to_dict") else dict(result)
        d = redact_obj(d)
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                      (d["scan_id"], d["timestamp"], d["target"], d["hostname"], d["status"],
                       json.dumps(d["config"]), json.dumps(d["summary"]), d.get("requests_made", 0),
                       d.get("duration_s", 0), d.get("app_version", ""),
                       json.dumps(d.get("errors", [])), json.dumps(d.get("notes", []))))
            c.execute("DELETE FROM findings WHERE scan_id=?", (d["scan_id"],))
            for f in d["findings"]:
                c.execute("INSERT INTO findings (scan_id, finding_id, severity, validation_status, user_note, data_json)"
                          " VALUES (?,?,?,?,?,?)",
                          (d["scan_id"], f["finding_id"], f["severity"], f["validation_status"],
                           f.get("user_note", ""), json.dumps(f)))
        return d["scan_id"]

    def list_scans(self, limit: int | None = None) -> list[dict]:
        sql = "SELECT * FROM scans ORDER BY timestamp DESC, rowid DESC" + (f" LIMIT {int(limit)}" if limit else "")
        with self._conn() as c:
            return [self._scan_row(r) for r in c.execute(sql)]

    @staticmethod
    def _scan_row(r) -> dict:
        return {"scan_id": r["scan_id"], "timestamp": r["timestamp"], "target": r["target"],
                "hostname": r["hostname"], "status": r["status"], "config": json.loads(r["config_json"]),
                "summary": json.loads(r["summary_json"]), "requests_made": r["requests_made"],
                "duration_s": r["duration_s"], "app_version": r["app_version"],
                "errors": json.loads(r["errors_json"] or "[]"), "notes": json.loads(r["notes_json"] or "[]")}

    def get_scan(self, scan_id: str) -> dict | None:
        """Full scan record including findings (with current validation state and notes)."""
        with self._conn() as c:
            row = c.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
            if row is None:
                return None
            scan = self._scan_row(row)
            scan["findings"] = self._findings(c, scan_id)
            return scan

    @staticmethod
    def _findings(conn, scan_id: str) -> list[dict]:
        out = []
        for r in conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY row_id", (scan_id,)):
            f = json.loads(r["data_json"])
            f["validation_status"], f["user_note"] = r["validation_status"], r["user_note"]
            out.append(f)
        return out

    def get_findings(self, scan_id: str) -> list[dict]:
        with self._conn() as c:
            return self._findings(c, scan_id)

    def update_validation(self, scan_id: str, finding_id: str, status: str, note: str = "") -> None:
        if status not in VALIDATION_STATES:
            raise DatabaseError(f"'{status}' is not a valid validation state.")
        with self._conn() as c:
            c.execute("UPDATE findings SET validation_status=?, user_note=? WHERE scan_id=? AND finding_id=?",
                      (status, redact_text(note)[:2000], scan_id, finding_id))

    def delete_scan(self, scan_id: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
            c.execute("DELETE FROM scans WHERE scan_id=?", (scan_id,))

    def clear_history(self) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM findings")
            c.execute("DELETE FROM scans")

    def stats(self) -> dict:
        with self._conn() as c:
            scans = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            by = {s: 0 for s in SEVERITIES}
            for r in c.execute("SELECT severity, COUNT(*) n FROM findings GROUP BY severity"):
                by[r["severity"]] = r["n"]
        return {"total_scans": scans, "total_findings": sum(by.values()), "by_severity": by}

    # ---- allowlist --------------------------------------------------------------------------
    def list_allowlist(self) -> list[str]:
        with self._conn() as c:
            return [r["hostname"] for r in c.execute("SELECT hostname FROM authorized_targets ORDER BY hostname")]

    def add_allowlist(self, hostname: str) -> None:
        with self._conn() as c:
            c.execute("INSERT OR IGNORE INTO authorized_targets VALUES (?,?)", (hostname, now_iso()))

    def remove_allowlist(self, hostname: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM authorized_targets WHERE hostname=?", (hostname,))
