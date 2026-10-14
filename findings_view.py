"""Findings dashboard: sortable/filterable table, full details, validation notes, exports."""
from __future__ import annotations

import html
import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QTableWidget,
                               QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget)

from core.models import SEVERITIES, VALIDATION_STATES, severity_rank
from database.database_manager import DatabaseError
from gui.styles import CONFIDENCE_COLORS, SEVERITY_COLORS, badge_html
from reports.json_exporter import ExportError, export_json
from reports.markdown_exporter import export_markdown

COLUMNS = ["ID", "Title", "Severity", "Confidence", "Category", "Target", "Validation", "Type"]
CONF_ORDER = {"High": 3, "Medium": 2, "Low": 1}


class SortItem(QTableWidgetItem):
    """Table item that sorts by a numeric/text key instead of its display text."""

    def __init__(self, text: str, key):
        super().__init__(text)
        self._key = key
        self.setFlags(self.flags() & ~Qt.ItemIsEditable)

    def __lt__(self, other):
        if isinstance(other, SortItem):
            return self._key < other._key
        return super().__lt__(other)


def _e(v) -> str:
    return html.escape(str(v if v is not None else ""))


def finding_to_html(f: dict) -> str:
    cwe = _e(f["cwe"]) if f.get("cwe") else f"<i>None - {_e(f.get('cwe_note', 'needs review'))}</i>"
    kind_color = {"Observation": "#607D8B", "Confirmed misconfiguration": "#2E7D32",
                  "Potential concern": "#D68910"}.get(f["classification"], "#607D8B")
    evidence = "\n".join(f"{k}: {v}" for k, v in f["evidence"].items())

    def sec(title, body):
        return f"<h4 style='margin-bottom:2px'>{title}</h4><div>{body}</div>"

    return (f"<h3>{_e(f['finding_id'])} - {_e(f['title'])}</h3>"
            f"<p>{badge_html(_e(f['severity']), SEVERITY_COLORS.get(f['severity'], '#607D8B'))} "
            f"{badge_html('Confidence: ' + _e(f['confidence']), CONFIDENCE_COLORS.get(f['confidence'], '#888'))} "
            f"{badge_html(_e(f['classification']), kind_color)}</p>"
            f"<p><b>Validation:</b> {_e(f['validation_status'])} &nbsp; <b>CWE:</b> {cwe}<br>"
            f"<b>Target:</b> {_e(f['target'])} &nbsp; <b>Check:</b> {_e(f['check_type'])} ({_e(f['category'])})<br>"
            f"<b>Observed at:</b> {_e(f['timestamp'])}</p>"
            + sec("Why it was identified", _e(f["description"]))
            + sec("Observed evidence", f"<pre>{_e(f['observation'])}\n\n{_e(evidence)}</pre>")
            + sec("Expected behavior", _e(f["expected"]))
            + sec("What the evidence proves", _e(f["proves"]))
            + sec("What the evidence does NOT prove", _e(f["not_proves"]))
            + sec("Security impact", _e(f["impact"]))
            + sec("Why this confidence", _e(f["confidence_reason"]))
            + sec("False-positive considerations", _e(f["false_positive_notes"]))
            + sec("Remediation", _e(f["remediation"]))
            + sec("Suggested manual verification", _e(f["manual_verification"])))


class FindingsView(QWidget):
    def __init__(self, db, get_settings):
        super().__init__()
        self.db, self.get_settings = db, get_settings
        self.scan: dict | None = None
        self.rows: list[dict] = []
        root = QVBoxLayout(self)
        title = QLabel("Findings")
        title.setObjectName("title")
        root.addWidget(title)

        top = QHBoxLayout()
        self.scan_combo = QComboBox()
        self.scan_combo.setToolTip("Choose a stored scan.")
        self.scan_combo.setMinimumWidth(280)
        self.scan_combo.activated.connect(self._combo_changed)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search findings ...")
        self.search.textChanged.connect(self._apply_filters)
        self.sev_filter = QComboBox()
        self.sev_filter.addItems(["All severities"] + list(reversed(SEVERITIES)))
        self.sev_filter.currentIndexChanged.connect(self._apply_filters)
        self.val_filter = QComboBox()
        self.val_filter.addItems(["All validation states"] + VALIDATION_STATES)
        self.val_filter.currentIndexChanged.connect(self._apply_filters)
        for w in (self.scan_combo, self.search, self.sev_filter, self.val_filter):
            top.addWidget(w, 1 if w is self.search else 0)
        root.addLayout(top)

        split = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._show_details)
        split.addWidget(self.table)

        bottom = QWidget()
        bl = QVBoxLayout(bottom)
        bl.setContentsMargins(0, 0, 0, 0)
        self.details = QTextBrowser()
        self.details.setPlaceholderText("Select a finding to see its full details.")
        bl.addWidget(self.details, 1)
        vrow = QHBoxLayout()
        vrow.addWidget(QLabel("Validation:"))
        self.val_combo = QComboBox()
        self.val_combo.addItems(VALIDATION_STATES)
        self.val_combo.setToolTip("Observed = seen directly. Needs Review = requires human judgment. "
                                  "Not Reproduced / False Positive / Accepted Risk = your own triage decisions.")
        self.note = QLineEdit()
        self.note.setPlaceholderText("Local note (never exported with secrets) ...")
        self.btn_save = QPushButton("Save validation")
        self.btn_save.clicked.connect(self._save_validation)
        vrow.addWidget(self.val_combo)
        vrow.addWidget(self.note, 1)
        vrow.addWidget(self.btn_save)
        bl.addLayout(vrow)
        split.addWidget(bottom)
        split.setSizes([260, 380])
        root.addWidget(split, 1)

        erow = QHBoxLayout()
        self.btn_json = QPushButton("Export JSON ...")
        self.btn_md = QPushButton("Export Markdown ...")
        self.btn_json.clicked.connect(lambda: self._export("json"))
        self.btn_md.clicked.connect(lambda: self._export("md"))
        erow.addWidget(self.btn_json)
        erow.addWidget(self.btn_md)
        self.status = QLabel("")
        self.status.setObjectName("muted")
        erow.addWidget(self.status, 1)
        root.addLayout(erow)
        self.refresh_scans()

    # ---- loading ----------------------------------------------------------------------------
    def refresh_scans(self, select: str | None = None) -> None:
        try:
            scans = self.db.list_scans()
        except DatabaseError as exc:
            QMessageBox.warning(self, "Database problem", str(exc))
            return
        current = select or (self.scan["scan_id"] if self.scan else None)
        self.scan_combo.blockSignals(True)
        self.scan_combo.clear()
        for s in scans:
            self.scan_combo.addItem(f"{s['timestamp'].replace('T', ' ').replace('Z', '')}  -  {s['hostname']}  "
                                    f"({s['summary'].get('total', 0)} findings, {s['status']})", s["scan_id"])
        self.scan_combo.blockSignals(False)
        ids = [s["scan_id"] for s in scans]
        if not ids:
            self.scan, self.rows = None, []
            self._populate()
            return
        self.load_scan(current if current in ids else ids[0])

    def _combo_changed(self, index: int) -> None:
        sid = self.scan_combo.itemData(index)
        if sid:
            self.load_scan(sid)

    def load_scan(self, scan_id: str) -> None:
        try:
            self.scan = self.db.get_scan(scan_id)
        except DatabaseError as exc:
            QMessageBox.warning(self, "Database problem", str(exc))
            return
        idx = self.scan_combo.findData(scan_id)
        if idx >= 0:
            self.scan_combo.setCurrentIndex(idx)
        self.rows = self.scan["findings"] if self.scan else []
        self._populate()

    def _populate(self) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.rows))
        for r, f in enumerate(self.rows):
            sev = SortItem(f["severity"], severity_rank(f["severity"]))
            sev.setBackground(QBrush(QColor(SEVERITY_COLORS.get(f["severity"], "#607D8B"))))
            sev.setForeground(QBrush(QColor("#FFFFFF")))
            cells = [SortItem(f["finding_id"], f["finding_id"]), SortItem(f["title"], f["title"].lower()), sev,
                     SortItem(f["confidence"], CONF_ORDER.get(f["confidence"], 0)),
                     SortItem(f["category"], f["category"]), SortItem(f["target"], f["target"]),
                     SortItem(f["validation_status"], f["validation_status"]),
                     SortItem(f["classification"], f["classification"])]
            cells[0].setData(Qt.UserRole, f["finding_id"])
            for c, item in enumerate(cells):
                self.table.setItem(r, c, item)
        self.table.setSortingEnabled(True)
        self.table.sortItems(2, Qt.DescendingOrder)
        self.details.clear()
        if self.scan:
            by = self.scan["summary"].get("by_severity", {})
            self.status.setText(f"{len(self.rows)} findings  |  status: {self.scan['status']}  |  "
                                f"requests: {self.scan.get('requests_made', 0)}")
            if self.scan.get("errors"):
                self.details.setPlainText("Scan notes:\n- " + "\n- ".join(self.scan["errors"]))
        else:
            self.status.setText("No scan loaded. Run a scan or open one from the dashboard.")
            self.details.setPlainText("No findings to show yet.")
        self._apply_filters()

    # ---- filtering / details ------------------------------------------------------------------
    def _apply_filters(self) -> None:
        text = self.search.text().strip().lower()
        sev = self.sev_filter.currentText()
        val = self.val_filter.currentText()
        for r in range(self.table.rowCount()):
            f = self._finding_at(r)
            if f is None:
                continue
            blob = " ".join(str(f.get(k, "")) for k in ("finding_id", "title", "category", "description", "observation"))
            hide = ((text and text not in blob.lower()) or
                    (sev != "All severities" and f["severity"] != sev) or
                    (val != "All validation states" and f["validation_status"] != val))
            self.table.setRowHidden(r, bool(hide))

    def _finding_at(self, row: int) -> dict | None:
        item = self.table.item(row, 0)
        if item is None:
            return None
        fid = item.data(Qt.UserRole)
        return next((f for f in self.rows if f["finding_id"] == fid), None)

    def _current_finding(self) -> dict | None:
        row = self.table.currentRow()
        return self._finding_at(row) if row >= 0 else None

    def _show_details(self) -> None:
        f = self._current_finding()
        if f is None:
            return
        self.details.setHtml(finding_to_html(f))
        self.val_combo.setCurrentText(f["validation_status"])
        self.note.setText(f.get("user_note", ""))

    def _save_validation(self) -> None:
        f = self._current_finding()
        if f is None or not self.scan:
            QMessageBox.information(self, "Select a finding", "Click a finding in the table first.")
            return
        try:
            self.db.update_validation(self.scan["scan_id"], f["finding_id"], self.val_combo.currentText(),
                                      self.note.text())
        except DatabaseError as exc:
            QMessageBox.warning(self, "Database problem", str(exc))
            return
        self.load_scan(self.scan["scan_id"])
        for r in range(self.table.rowCount()):
            if self.table.item(r, 0).data(Qt.UserRole) == f["finding_id"]:
                self.table.selectRow(r)
                break
        self.status.setText("Validation saved.")

    # ---- export -------------------------------------------------------------------------------
    def _export(self, kind: str) -> None:
        if not self.scan:
            QMessageBox.information(self, "Nothing to export", "Load a scan first.")
            return
        ext, label = ("json", "JSON (*.json)") if kind == "json" else ("md", "Markdown (*.md)")
        start = os.path.join(self.get_settings().export_dir or os.path.expanduser("~"),
                             f"cyberscope_{self.scan['hostname']}_{self.scan['scan_id']}.{ext}")
        path, _ = QFileDialog.getSaveFileName(self, "Export report", start, label)
        if not path:
            return
        try:
            fresh = self.db.get_scan(self.scan["scan_id"])   # include latest validation states and notes
            (export_json if kind == "json" else export_markdown)(fresh, path)
        except (ExportError, DatabaseError) as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Report saved", f"Report saved to:\n{path}\n\nSecrets and cookie values are never included.")
