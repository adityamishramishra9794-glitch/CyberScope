"""Runs a scan on a background thread so the GUI never freezes."""
from __future__ import annotations

import logging
import threading

from PySide6.QtCore import QObject, Signal, Slot

from core.scan_engine import ScanEngine, ScanRefused
from database.database_manager import DatabaseError

log = logging.getLogger("cyberscope.gui")


class ScanWorker(QObject):
    progress = Signal(int, str, str)   # percent (-1 = unchanged), check name, message
    done = Signal(str)                 # scan_id
    failed = Signal(str)               # user-friendly message

    def __init__(self, target, config, settings, scope, db):
        super().__init__()
        self._args = (target, config, settings, scope)
        self._db = db
        self.cancel_event = threading.Event()

    def cancel(self) -> None:
        self.cancel_event.set()

    @Slot()
    def run(self) -> None:
        target, config, settings, scope = self._args
        try:
            engine = ScanEngine(target, config, settings, scope,
                                progress=lambda p, n, m: self.progress.emit(p, n, m),
                                cancel_event=self.cancel_event)
            result = engine.run()
            self.done.emit(self._db.save_scan(result))
        except ScanRefused as exc:
            self.failed.emit(str(exc))
        except DatabaseError as exc:
            self.failed.emit(f"The scan finished but could not be saved: {exc}")
        except Exception:
            log.exception("Unexpected scan failure")
            self.failed.emit("The scan stopped because of an unexpected problem. "
                             "Technical details were saved to the log file.")
