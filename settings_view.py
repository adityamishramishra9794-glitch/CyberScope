"""Settings page with validation and safe upper limits."""
from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QComboBox, QDoubleSpinBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QSpinBox, QVBoxLayout, QWidget)

from config.app_config import LIMITS
from config.settings import THEMES, Settings, save_settings, validate_settings


class SettingsView(QWidget):
    settings_saved = Signal(object)

    def __init__(self, settings: Settings):
        super().__init__()
        root = QVBoxLayout(self)
        title = QLabel("Settings")
        title.setObjectName("title")
        root.addWidget(title)
        note = QLabel("Limits keep scans gentle on the target. Scope enforcement cannot be disabled.")
        note.setObjectName("muted")
        root.addWidget(note)
        form = QFormLayout()
        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(*LIMITS["timeout"])
        self.timeout.setSuffix(" s")
        self.timeout.setToolTip("How long to wait for a server before giving up.")
        self.body = QSpinBox()
        self.body.setRange(*LIMITS["max_body_kb"])
        self.body.setSuffix(" KB")
        self.body.setToolTip("Maximum amount of each response that is read.")
        self.requests = QSpinBox()
        self.requests.setRange(*LIMITS["max_requests"])
        self.requests.setToolTip("Hard cap on network operations per scan.")
        self.delay = QDoubleSpinBox()
        self.delay.setRange(*LIMITS["request_delay"])
        self.delay.setSingleStep(0.25)
        self.delay.setSuffix(" s")
        self.delay.setToolTip("Pause between requests to avoid load on the target.")
        self.export_dir = QLineEdit()
        self.export_dir.setPlaceholderText("(your home folder)")
        browse = QPushButton("Browse ...")
        browse.setObjectName("secondary")
        browse.clicked.connect(self._browse)
        dir_row = QHBoxLayout()
        dir_row.addWidget(self.export_dir, 1)
        dir_row.addWidget(browse)
        self.theme = QComboBox()
        self.theme.addItems(THEMES)
        self.ua = QLineEdit()
        self.ua.setToolTip("Sent with every request so site owners can recognise the scanner.")
        form.addRow("Connection timeout", self.timeout)
        form.addRow("Max response size", self.body)
        form.addRow("Request limit per scan", self.requests)
        form.addRow("Delay between requests", self.delay)
        form.addRow("Default export folder", dir_row)
        form.addRow("Theme", self.theme)
        form.addRow("User-agent", self.ua)
        root.addLayout(form)
        row = QHBoxLayout()
        save = QPushButton("Save settings")
        reset = QPushButton("Restore defaults")
        reset.setObjectName("secondary")
        save.clicked.connect(self._save)
        reset.clicked.connect(lambda: self.load(Settings()))
        row.addWidget(save)
        row.addWidget(reset)
        row.addStretch()
        root.addLayout(row)
        root.addStretch()
        self.load(settings)

    def load(self, s: Settings) -> None:
        self.timeout.setValue(s.timeout)
        self.body.setValue(s.max_body_kb)
        self.requests.setValue(s.max_requests)
        self.delay.setValue(s.request_delay)
        self.export_dir.setText(s.export_dir)
        self.theme.setCurrentText(s.theme)
        self.ua.setText(s.user_agent)

    def _browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose default export folder")
        if path:
            self.export_dir.setText(path)

    def _save(self) -> None:
        data = {"timeout": self.timeout.value(), "max_body_kb": self.body.value(),
                "max_requests": self.requests.value(), "request_delay": self.delay.value(),
                "export_dir": self.export_dir.text(), "theme": self.theme.currentText(),
                "user_agent": self.ua.text()}
        settings, errors = validate_settings(data)
        if errors:
            QMessageBox.warning(self, "Please fix these settings", "\n".join(f"- {e}" for e in errors))
            return
        try:
            save_settings(settings)
        except OSError as exc:
            QMessageBox.warning(self, "Could not save settings", f"The settings file could not be written: {exc.strerror}")
            return
        self.settings_saved.emit(settings)
        QMessageBox.information(self, "Settings", "Settings saved.")
