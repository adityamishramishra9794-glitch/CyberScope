"""Main application window."""
from __future__ import annotations

import logging

from PySide6.QtWidgets import (QApplication, QHBoxLayout, QListWidget, QMainWindow, QMessageBox, QStackedWidget,
                               QWidget)

from config.app_config import APP_VERSION, app_data_dir
from config.settings import load_settings
from core.scope_manager import ScopeManager
from database.database_manager import DatabaseError, DatabaseManager
from gui.dashboard import DashboardView
from gui.findings_view import FindingsView
from gui.scan_view import ScanView
from gui.settings_view import SettingsView
from gui.styles import build_stylesheet

log = logging.getLogger("cyberscope.gui")
PAGES = ["Dashboard", "New Scan", "Findings", "Settings"]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"CyberScope V4 - Authorized Web Security Assessment (v{APP_VERSION})")
        self.resize(1150, 780)
        self.settings = load_settings()
        self.db = DatabaseManager(app_data_dir() / "cyberscope.db")
        self.scope = ScopeManager()
        try:
            for host in self.db.list_allowlist():
                self.scope.add(host)
        except (DatabaseError, ValueError) as exc:
            log.warning("Could not load allowlist: %s", exc)

        self.dashboard = DashboardView(self.db)
        self.scan_view = ScanView(self.db, self.scope, lambda: self.settings)
        self.findings = FindingsView(self.db, lambda: self.settings)
        self.settings_view = SettingsView(self.settings)

        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(170)
        self.nav.addItems(PAGES)
        self.stack = QStackedWidget()
        for w in (self.dashboard, self.scan_view, self.findings, self.settings_view):
            self.stack.addWidget(w)
        self.nav.currentRowChanged.connect(self._on_nav)
        central = QWidget()
        lay = QHBoxLayout(central)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.nav)
        lay.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        self.dashboard.open_scan.connect(self._open_scan)
        self.dashboard.history_changed.connect(lambda: self.findings.refresh_scans())
        self.scan_view.scan_finished.connect(self._scan_finished)
        self.scan_view.running_changed.connect(lambda r: self.statusBar().showMessage("Scan running ..." if r else "Ready"))
        self.settings_view.settings_saved.connect(self._settings_saved)
        self.nav.setCurrentRow(0)
        self.statusBar().showMessage("Ready")
        self._apply_theme()
        if self.db.recovered_from:
            QMessageBox.information(self, "History database repaired",
                                    "The scan history database was damaged, so a fresh one was created.\n"
                                    f"The damaged file was kept as:\n{self.db.recovered_from}")

    def _apply_theme(self) -> None:
        app = QApplication.instance()
        if app:
            app.setStyleSheet(build_stylesheet(self.settings.theme))

    def _on_nav(self, row: int) -> None:
        self.stack.setCurrentIndex(max(row, 0))
        if row == 0:
            self.dashboard.refresh()

    def _open_scan(self, scan_id: str) -> None:
        self.findings.refresh_scans(select=scan_id)
        self.nav.setCurrentRow(2)

    def _scan_finished(self, scan_id: str) -> None:
        self.dashboard.refresh()
        self._open_scan(scan_id)

    def _settings_saved(self, settings) -> None:
        self.settings = settings
        self._apply_theme()

    def closeEvent(self, event) -> None:
        if self.scan_view.is_running():
            answer = QMessageBox.question(self, "Scan in progress",
                                          "A scan is still running. Cancel it and exit?")
            if answer != QMessageBox.Yes:
                event.ignore()
                return
            self.statusBar().showMessage("Stopping scan ...")
            self.scan_view.shutdown()
        event.accept()
