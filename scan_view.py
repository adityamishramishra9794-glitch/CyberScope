"""New Scan page: target, authorization, allowlist, check selection, progress."""
from __future__ import annotations

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (QCheckBox, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QMessageBox,
                               QPlainTextEdit, QProgressBar, QPushButton, QVBoxLayout, QWidget)

from core.models import CHECKS, ScanConfig
from core.scope_manager import ScopeManager
from core.target_validation import TargetValidationError, normalize_target
from database.database_manager import DatabaseError
from gui.scan_worker import ScanWorker


class ScanView(QWidget):
    scan_finished = Signal(str)
    running_changed = Signal(bool)

    def __init__(self, db, scope: ScopeManager, get_settings):
        super().__init__()
        self.db, self.scope, self.get_settings = db, scope, get_settings
        self.thread: QThread | None = None
        self.worker: ScanWorker | None = None

        root = QVBoxLayout(self)
        title = QLabel("New scan")
        title.setObjectName("title")
        root.addWidget(title)
        warn = QLabel("<b>Authorization required.</b> Only scan websites you own or have explicit written permission to test. "
                      "CyberScope runs safe, non-destructive checks, only against hosts on your authorized list.")
        warn.setObjectName("warning")
        warn.setWordWrap(True)
        root.addWidget(warn)

        box = QGroupBox("1. Target")
        lay = QVBoxLayout(box)
        self.target = QLineEdit()
        self.target.setPlaceholderText("example.com  or  https://example.com")
        self.target.setToolTip("A domain name or an http(s) URL. Paths and query strings are ignored; "
                               "the scan inspects the site's home page and three public metadata files.")
        self.target.textChanged.connect(self._update_normalized)
        self.normalized = QLabel("")
        self.normalized.setWordWrap(True)
        self.btn_allow_add = QPushButton("Add this target to authorized list")
        self.btn_allow_add.setObjectName("secondary")
        self.btn_allow_add.setToolTip("Only add targets you are permitted to test.")
        self.btn_allow_add.clicked.connect(self._add_allowlist)
        self.auth = QCheckBox("I own this target or have explicit permission to test it.")
        self.auth.setToolTip("Required. The scan engine refuses to run without it.")
        lay.addWidget(self.target)
        lay.addWidget(self.normalized)
        lay.addWidget(self.btn_allow_add)
        lay.addWidget(self.auth)
        root.addWidget(box)

        box2 = QGroupBox("Authorized targets (allowlist)")
        lay2 = QHBoxLayout(box2)
        self.allow_list = QListWidget()
        self.allow_list.setMaximumHeight(90)
        self.allow_list.setToolTip("Exact hostname matching: 'example.com' does not authorize 'www.example.com'.")
        self.btn_allow_remove = QPushButton("Remove selected")
        self.btn_allow_remove.setObjectName("secondary")
        self.btn_allow_remove.clicked.connect(self._remove_allowlist)
        lay2.addWidget(self.allow_list, 1)
        lay2.addWidget(self.btn_allow_remove)
        root.addWidget(box2)

        box3 = QGroupBox("2. Checks")
        lay3 = QVBoxLayout(box3)
        self.checks: dict[str, QCheckBox] = {}
        for key, label, tip in CHECKS:
            cb = QCheckBox(label)
            cb.setChecked(True)
            cb.setToolTip(tip)
            self.checks[key] = cb
            lay3.addWidget(cb)
        btn_default = QPushButton("Reset to safe default profile")
        btn_default.setObjectName("secondary")
        btn_default.setToolTip("Enables all checks. Every check is passive and non-destructive.")
        btn_default.clicked.connect(lambda: [c.setChecked(True) for c in self.checks.values()])
        lay3.addWidget(btn_default)
        root.addWidget(box3)

        row = QHBoxLayout()
        self.btn_start = QPushButton("Start scan")
        self.btn_cancel = QPushButton("Cancel scan")
        self.btn_cancel.setObjectName("danger")
        self.btn_cancel.setEnabled(False)
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_cancel.clicked.connect(self.cancel_scan)
        row.addWidget(self.btn_start)
        row.addWidget(self.btn_cancel)
        row.addStretch()
        root.addLayout(row)

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.current = QLabel("Idle")
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(110)
        self.log.setPlaceholderText("Scan messages will appear here.")
        root.addWidget(self.bar)
        root.addWidget(self.current)
        root.addWidget(self.log)
        self.reload_allowlist()
        self._update_normalized()

    # ---- allowlist --------------------------------------------------------------------------
    def reload_allowlist(self) -> None:
        self.allow_list.clear()
        self.allow_list.addItems(self.scope.allowed_hosts())

    def _add_allowlist(self) -> None:
        try:
            host = normalize_target(self.target.text()).hostname
        except TargetValidationError as exc:
            QMessageBox.warning(self, "Invalid target", str(exc))
            return
        if QMessageBox.question(self, "Authorize target",
                                f"Confirm that you own '{host}' or have explicit permission to test it.\n\n"
                                "Add it to the authorized list?") != QMessageBox.Yes:
            return
        self.scope.add(host)
        try:
            self.db.add_allowlist(host)
        except DatabaseError as exc:
            QMessageBox.warning(self, "Database problem", str(exc))
        self.reload_allowlist()
        self._update_normalized()

    def _remove_allowlist(self) -> None:
        item = self.allow_list.currentItem()
        if not item:
            QMessageBox.information(self, "Select a target", "Select a host in the list first.")
            return
        self.scope.remove(item.text())
        try:
            self.db.remove_allowlist(item.text())
        except DatabaseError as exc:
            QMessageBox.warning(self, "Database problem", str(exc))
        self.reload_allowlist()
        self._update_normalized()

    def _update_normalized(self) -> None:
        text = self.target.text().strip()
        if not text:
            self.normalized.setText("<span style='color:gray'>Enter a target to see how it will be scanned.</span>")
            self.btn_allow_add.setEnabled(False)
            return
        try:
            t = normalize_target(text)
        except TargetValidationError as exc:
            self.normalized.setText(f"<span style='color:#C0392B'>Not valid: {exc}</span>")
            self.btn_allow_add.setEnabled(False)
            return
        listed = self.scope.is_allowed(t.hostname)
        state = ("<span style='color:#2E7D32'>on the authorized list</span>" if listed else
                 "<span style='color:#D68910'>NOT on the authorized list yet</span>")
        self.normalized.setText(f"Final target: <b>{t.url}</b> (host <b>{t.hostname}</b>) - {state}")
        self.btn_allow_add.setEnabled(not listed)

    # ---- scanning ---------------------------------------------------------------------------
    def is_running(self) -> bool:
        return self.thread is not None and self.thread.isRunning()

    def start_scan(self) -> None:
        if self.is_running():
            return
        try:
            t = normalize_target(self.target.text())
        except TargetValidationError as exc:
            QMessageBox.warning(self, "Invalid target", str(exc))
            return
        if not self.scope.is_allowed(t.hostname):
            QMessageBox.warning(self, "Target not authorized",
                                f"'{t.hostname}' is not on your authorized list.\nAdd it first (button above).")
            return
        if not self.auth.isChecked():
            QMessageBox.warning(self, "Authorization required",
                                "Tick the authorization checkbox to confirm you may test this target.")
            return
        config = ScanConfig(checks={k: cb.isChecked() for k, cb in self.checks.items()},
                            authorization_confirmed=True)
        if not any(config.checks.values()):
            QMessageBox.warning(self, "No checks selected", "Select at least one check.")
            return
        self.log.clear()
        self.bar.setValue(0)
        self.thread = QThread(self)
        self.worker = ScanWorker(self.target.text(), config, self.get_settings(), self.scope, self.db)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.done.connect(self._on_done)
        self.worker.failed.connect(self._on_failed)
        self.worker.done.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self._cleanup)
        self._set_running(True)
        self.thread.start()

    def cancel_scan(self) -> None:
        if self.worker:
            self.worker.cancel()
            self.current.setText("Cancelling ... waiting for the current request to finish.")
            self.btn_cancel.setEnabled(False)

    def shutdown(self, wait_ms: int = 15000) -> None:
        """Called when the application closes during a scan."""
        if self.is_running():
            self.worker.cancel()
            self.thread.quit()
            self.thread.wait(wait_ms)

    def _set_running(self, running: bool) -> None:
        self.btn_start.setEnabled(not running)
        self.btn_cancel.setEnabled(running)
        for w in (self.target, self.auth, self.btn_allow_add, self.btn_allow_remove, *self.checks.values()):
            w.setEnabled(not running)
        self.running_changed.emit(running)

    def _on_progress(self, pct: int, name: str, message: str) -> None:
        if pct >= 0:
            self.bar.setValue(pct)
        self.current.setText(f"Current check: {name}")
        self.log.appendPlainText(message)

    def _on_done(self, scan_id: str) -> None:
        self.bar.setValue(100)
        self.current.setText("Finished.")
        self.log.appendPlainText("Scan saved to local history.")
        self.scan_finished.emit(scan_id)

    def _on_failed(self, message: str) -> None:
        self.current.setText("Scan did not run.")
        self.log.appendPlainText(message)
        QMessageBox.warning(self, "Scan problem", message)

    def _cleanup(self) -> None:
        self._set_running(False)
        self._update_normalized()
        if self.worker:
            self.worker.deleteLater()
        if self.thread:
            self.thread.deleteLater()
        self.worker, self.thread = None, None
