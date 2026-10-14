"""Main dashboard: summary cards, recent scans, quick-start."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel,
                               QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from config.app_config import APP_VERSION
from database.database_manager import DatabaseError
from gui.styles import SEVERITY_COLORS


class Card(QFrame):
    def __init__(self, label: str, color: str | None = None, tip: str = ""):
        super().__init__()
        self.setObjectName("card")
        self.setToolTip(tip)
        lay = QVBoxLayout(self)
        self.number = QLabel("0")
        self.number.setObjectName("cardNumber")
        if color:
            self.number.setStyleSheet(f"color:{color};")
        caption = QLabel(label)
        caption.setObjectName("muted")
        lay.addWidget(self.number)
        lay.addWidget(caption)

    def set_value(self, value: int) -> None:
        self.number.setText(str(value))


class DashboardView(QWidget):
    open_scan = Signal(str)
    history_changed = Signal()

    def __init__(self, db):
        super().__init__()
        self.db = db
        self._scan_ids: list[str] = []
        root = QVBoxLayout(self)
        title = QLabel(f"CyberScope V4")
        title.setObjectName("title")
        sub = QLabel(f"Authorized web security assessment  -  v{APP_VERSION}")
        sub.setObjectName("subtitle")
        root.addWidget(title)
        root.addWidget(sub)

        grid = QGridLayout()
        self.c_scans = Card("Total scans", tip="Number of scans stored locally.")
        self.c_find = Card("Total findings", tip="All findings across stored scans, including informational ones.")
        self.c_high = Card("High severity", SEVERITY_COLORS["High"], "High and Critical findings combined.")
        self.c_med = Card("Medium severity", SEVERITY_COLORS["Medium"])
        self.c_low = Card("Low severity", SEVERITY_COLORS["Low"])
        for i, c in enumerate((self.c_scans, self.c_find, self.c_high, self.c_med, self.c_low)):
            grid.addWidget(c, 0, i)
        root.addLayout(grid)

        quick = QLabel("<b>Quick start</b><br>1. Open <b>New Scan</b> and enter a site you own or have written permission to test."
                       "<br>2. Add it to the authorized-target list and tick the authorization box."
                       "<br>3. Press <b>Start scan</b>, then review results under <b>Findings</b>."
                       "<br>4. Export a JSON or Markdown report from the Findings page.")
        quick.setWordWrap(True)
        quick.setObjectName("card")
        quick.setStyleSheet("padding:12px;")
        root.addWidget(quick)

        root.addWidget(QLabel("<b>Recent scans</b>"))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Date (UTC)", "Target", "Status", "Findings", "High+/Med/Low"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.doubleClicked.connect(lambda _: self._open_selected())
        root.addWidget(self.table, 1)
        self.empty = QLabel("No scans yet. Start one from the New Scan page.")
        self.empty.setObjectName("muted")
        self.empty.setAlignment(Qt.AlignCenter)
        root.addWidget(self.empty)

        row = QHBoxLayout()
        self.btn_open = QPushButton("Open selected scan")
        self.btn_del = QPushButton("Delete selected")
        self.btn_del.setObjectName("secondary")
        self.btn_clear = QPushButton("Clear all history")
        self.btn_clear.setObjectName("danger")
        self.btn_open.clicked.connect(self._open_selected)
        self.btn_del.clicked.connect(self._delete_selected)
        self.btn_clear.clicked.connect(self._clear_all)
        for b in (self.btn_open, self.btn_del, self.btn_clear):
            row.addWidget(b)
        row.addStretch()
        root.addLayout(row)
        self.refresh()

    def refresh(self) -> None:
        try:
            stats = self.db.stats()
            scans = self.db.list_scans(limit=50)
        except DatabaseError as exc:
            QMessageBox.warning(self, "Database problem", str(exc))
            return
        by = stats["by_severity"]
        self.c_scans.set_value(stats["total_scans"])
        self.c_find.set_value(stats["total_findings"])
        self.c_high.set_value(by.get("High", 0) + by.get("Critical", 0))
        self.c_med.set_value(by.get("Medium", 0))
        self.c_low.set_value(by.get("Low", 0))
        self._scan_ids = [s["scan_id"] for s in scans]
        self.table.setRowCount(len(scans))
        for r, s in enumerate(scans):
            b = s["summary"].get("by_severity", {})
            vals = [s["timestamp"].replace("T", " ").replace("Z", ""), s["hostname"], s["status"],
                    str(s["summary"].get("total", 0)),
                    f"{b.get('High', 0) + b.get('Critical', 0)} / {b.get('Medium', 0)} / {b.get('Low', 0)}"]
            for c, v in enumerate(vals):
                self.table.setItem(r, c, QTableWidgetItem(v))
        self.empty.setVisible(not scans)
        self.table.setVisible(bool(scans))
        for b in (self.btn_open, self.btn_del, self.btn_clear):
            b.setEnabled(bool(scans))

    def _selected_id(self) -> str | None:
        row = self.table.currentRow()
        return self._scan_ids[row] if 0 <= row < len(self._scan_ids) else None

    def _open_selected(self) -> None:
        sid = self._selected_id()
        if sid:
            self.open_scan.emit(sid)
        else:
            QMessageBox.information(self, "Select a scan", "Click a scan in the list first.")

    def _delete_selected(self) -> None:
        sid = self._selected_id()
        if not sid:
            QMessageBox.information(self, "Select a scan", "Click a scan in the list first.")
            return
        if QMessageBox.question(self, "Delete scan", "Delete this scan and its findings from local history?\n"
                                "This cannot be undone.") == QMessageBox.Yes:
            self._safe(lambda: self.db.delete_scan(sid))

    def _clear_all(self) -> None:
        if QMessageBox.question(self, "Clear history", "Delete ALL stored scans and findings?\n"
                                "Your authorized-target list is kept. This cannot be undone.") == QMessageBox.Yes:
            self._safe(self.db.clear_history)

    def _safe(self, fn) -> None:
        try:
            fn()
        except DatabaseError as exc:
            QMessageBox.warning(self, "Database problem", str(exc))
        self.refresh()
        self.history_changed.emit()
