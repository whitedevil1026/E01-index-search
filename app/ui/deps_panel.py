"""Dependency status panel — what's installed, with one-click installer."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QMessageBox, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from app.core.deps import probe_all, missing
from app.ui.install_dialog import InstallDialog


class DepsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        title = QLabel("Dependency Status")
        title.setObjectName("h1")
        root.addWidget(title)

        sub = QLabel(
            "Versions verified May 2026 per the project's review document. "
            "Forensic libs are optional — missing ones degrade their feature gracefully."
        )
        sub.setObjectName("muted")
        sub.setWordWrap(True)
        root.addWidget(sub)

        self.summary_lbl = QLabel("")
        self.summary_lbl.setObjectName("h2")
        root.addWidget(self.summary_lbl)

        self.tbl = QTableWidget(0, 6)
        self.tbl.setHorizontalHeaderLabels(
            ["Package", "Installed", "Version", "Purpose", "Install command", "Notes"]
        )
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.tbl.horizontalHeader().setStretchLastSection(True)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.setWordWrap(True)
        root.addWidget(self.tbl, 1)

        bar = QHBoxLayout()
        self.btn_install = QPushButton("Install Missing…")
        self.btn_install.clicked.connect(self._open_installer)
        self.btn_refresh = QPushButton("Re-probe")
        self.btn_refresh.setObjectName("secondary")
        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_copy = QPushButton("Copy pip commands for missing")
        self.btn_copy.setObjectName("secondary")
        self.btn_copy.clicked.connect(self._copy_missing)
        bar.addWidget(self.btn_install)
        bar.addWidget(self.btn_refresh)
        bar.addWidget(self.btn_copy)
        bar.addStretch(1)
        root.addLayout(bar)

        self.refresh()

    def set_case(self, _case):
        # Deps panel is global — ignore case.
        pass

    def refresh(self):
        deps = probe_all()
        good = sum(1 for d in deps if d.installed)
        self.summary_lbl.setText(f"{good} / {len(deps)} packages installed")
        self.btn_install.setEnabled(good < len(deps))
        self.tbl.setRowCount(len(deps))
        for i, d in enumerate(deps):
            self.tbl.setItem(i, 0, QTableWidgetItem(d.name))
            ok_item = QTableWidgetItem("yes" if d.installed else "no")
            ok_item.setForeground(QColor("#22c55e") if d.installed else QColor("#ef4444"))
            self.tbl.setItem(i, 1, ok_item)
            ver_text = d.version if d.installed else ""
            self.tbl.setItem(i, 2, QTableWidgetItem(ver_text))
            self.tbl.setItem(i, 3, QTableWidgetItem(d.purpose))
            self.tbl.setItem(i, 4, QTableWidgetItem(d.install_hint))
            self.tbl.setItem(i, 5, QTableWidgetItem(d.notes or ""))
        self.tbl.resizeRowsToContents()
        # Bubble status-bar refresh (defensive — toolbar may not be built yet)
        mw = self.window()
        if hasattr(mw, "_refresh_deps_label") and hasattr(mw, "lbl_deps"):
            mw._refresh_deps_label()

    def _copy_missing(self):
        m = missing()
        if not m:
            QMessageBox.information(self, "Nothing missing", "All deps already installed.")
            return
        QGuiApplication.clipboard().setText("\n".join(d.install_hint for d in m))
        QMessageBox.information(
            self, "Copied",
            f"Copied {len(m)} pip command(s) to clipboard. "
            "Paste into a terminal to install.",
        )

    def _open_installer(self):
        m = missing()
        if not m:
            QMessageBox.information(self, "Nothing missing", "All deps already installed.")
            return
        ret = QMessageBox.question(
            self, "Install missing dependencies",
            f"{len(m)} package(s) will be installed via pip using:\n"
            f"  {__import__('sys').executable}\n\n"
            "No admin rights are needed — packages install to user site-packages. "
            "You'll see the live pip output and you can cancel at any time.\n\n"
            "Proceed?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes,
        )
        if ret != QMessageBox.Yes:
            return
        dlg = InstallDialog(m, self)
        dlg.closed_after_install.connect(self.refresh)
        dlg.exec()
        self.refresh()
