"""Case overview panel — case meta, evidence list, basic counts."""
from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from app.core.hash_policy import HashPolicy, SUPPORTED_ALGOS
from app.ui.centered_msg import msg_info
from app.ui.help_dialog import info_button


def _fmt_time(t: float | None) -> str:
    if not t:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def _fmt_size(n: int | None) -> str:
    if not n:
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


class CasePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None

        # Wrap content in a scroll area so the panel works on small
        # displays without bubbling huge minimum sizes up to the window.
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setMinimumSize(600, 360)
        outer.addWidget(scroll)
        inner = QWidget()
        scroll.setWidget(inner)
        root = QVBoxLayout(inner)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        title = QLabel("Case Overview")
        title.setObjectName("h1")
        root.addWidget(title)

        # ---- meta box -------------------------------------------------
        self.meta_box = QGroupBox("Case Metadata")
        form = QFormLayout(self.meta_box)
        self.lbl_id = QLabel("—")
        self.lbl_name = QLabel("—")
        self.lbl_examiner = QLabel("—")
        self.lbl_created = QLabel("—")
        self.lbl_root = QLabel("—")
        self.lbl_root.setWordWrap(True)
        for w in (self.lbl_id, self.lbl_name, self.lbl_examiner,
                  self.lbl_created, self.lbl_root):
            w.setTextInteractionFlags(Qt.TextSelectableByMouse)
        form.addRow("Case ID:", self.lbl_id)
        form.addRow("Name:", self.lbl_name)
        form.addRow("Examiner:", self.lbl_examiner)
        form.addRow("Created:", self.lbl_created)
        form.addRow("Root:", self.lbl_root)
        root.addWidget(self.meta_box)

        # ---- hash policy box ----------------------------------------
        hp_box = QGroupBox("Hash policy (applies to every file in this case)")
        hpl = QFormLayout(hp_box)
        title_row = QWidget()
        tr = QHBoxLayout(title_row); tr.setContentsMargins(0,0,0,0)
        self.lbl_policy = QLabel("—")
        self.lbl_policy.setTextInteractionFlags(Qt.TextSelectableByMouse)
        tr.addWidget(self.lbl_policy, 1)
        tr.addWidget(info_button("hash_policy", self))
        hpl.addRow("Current policy:", title_row)

        edit_row = QWidget()
        er = QHBoxLayout(edit_row); er.setContentsMargins(0,0,0,0)
        self.cmb_primary = QComboBox()
        for a in SUPPORTED_ALGOS:
            self.cmb_primary.addItem(a.upper(), a)
        er.addWidget(QLabel("Primary:"))
        er.addWidget(self.cmb_primary)
        er.addSpacing(12)
        er.addWidget(QLabel("Extras:"))
        self._extra_checks: dict[str, QCheckBox] = {}
        for a in SUPPORTED_ALGOS:
            cb = QCheckBox(a.upper())
            self._extra_checks[a] = cb
            er.addWidget(cb)
        er.addStretch(1)
        btn_apply = QPushButton("Apply")
        btn_apply.setToolTip(
            "Save the selected primary + extra hash algorithms as this "
            "case's policy. Applied to every later ingest, integrity check, "
            "and Compute Now run."
        )
        btn_apply.clicked.connect(self._apply_policy)
        er.addWidget(btn_apply)
        hpl.addRow("Change:", edit_row)
        self.cmb_primary.currentIndexChanged.connect(self._sync_extras)
        root.addWidget(hp_box)

        # ---- evidence table ------------------------------------------
        ev_box = QGroupBox("Evidence Items")
        ev_layout = QVBoxLayout(ev_box)
        self.tbl = QTableWidget(0, 6)
        self.tbl.setHorizontalHeaderLabels(
            ["ID", "Path", "Format", "Size", "SHA-256 (acquired)", "Added"]
        )
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.tbl.horizontalHeader().setStretchLastSection(True)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        ev_layout.addWidget(self.tbl)

        btn_row = QHBoxLayout()
        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.setObjectName("secondary")
        self.btn_refresh.clicked.connect(self.refresh)
        btn_row.addWidget(self.btn_refresh)
        btn_row.addStretch(1)
        ev_layout.addLayout(btn_row)
        root.addWidget(ev_box, 1)

        # ---- notes ----------------------------------------------------
        notes_box = QGroupBox("Examiner Notes (saved to audit log on save)")
        nl = QVBoxLayout(notes_box)
        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText("Free-form notes about this case…")
        self.notes.setFixedHeight(110)
        nl.addWidget(self.notes)
        btn = QPushButton("Save Note to Audit Log")
        btn.clicked.connect(self._save_note)
        nl.addWidget(btn, alignment=Qt.AlignRight)
        root.addWidget(notes_box)

    # ---- state -------------------------------------------------------

    def set_case(self, case):
        self.case = case
        self.setEnabled(case is not None)
        self.refresh()

    def refresh(self):
        if not self.case:
            self.lbl_id.setText("—"); self.lbl_name.setText("—")
            self.lbl_examiner.setText("—"); self.lbl_created.setText("—")
            self.lbl_root.setText("—")
            self.lbl_policy.setText("—")
            self.tbl.setRowCount(0)
            return
        # populate policy controls
        pol = self.case.hash_policy()
        self.lbl_policy.setText(pol.describe())
        self.cmb_primary.blockSignals(True)
        self.cmb_primary.setCurrentText(pol.primary.upper())
        self.cmb_primary.blockSignals(False)
        for a, cb in self._extra_checks.items():
            cb.blockSignals(True)
            cb.setChecked(a in pol.extras)
            cb.blockSignals(False)
        self._sync_extras()
        m = self.case.meta()
        self.lbl_id.setText(m.id)
        self.lbl_name.setText(m.name)
        self.lbl_examiner.setText(m.examiner)
        self.lbl_created.setText(_fmt_time(m.created_at))
        self.lbl_root.setText(str(self.case.root))

        rows = self.case.list_evidence()
        self.tbl.setRowCount(len(rows))
        for i, r in enumerate(rows):
            self.tbl.setItem(i, 0, QTableWidgetItem(str(r["id"])))
            self.tbl.setItem(i, 1, QTableWidgetItem(r["path"]))
            self.tbl.setItem(i, 2, QTableWidgetItem(r["format"]))
            self.tbl.setItem(i, 3, QTableWidgetItem(_fmt_size(r["size_bytes"])))
            self.tbl.setItem(i, 4, QTableWidgetItem(r["acquired_sha256"] or ""))
            self.tbl.setItem(i, 5, QTableWidgetItem(_fmt_time(r["added_at"])))

    def _sync_extras(self):
        primary = self.cmb_primary.currentData()
        for a, cb in self._extra_checks.items():
            if a == primary:
                cb.setChecked(False)
                cb.setEnabled(False)
                cb.setToolTip("Already the primary hash")
            else:
                cb.setEnabled(True)
                cb.setToolTip("")

    def _apply_policy(self):
        if not self.case:
            return
        primary = self.cmb_primary.currentData()
        extras = [a for a, cb in self._extra_checks.items()
                  if cb.isChecked() and cb.isEnabled() and a != primary]
        pol = HashPolicy(primary=primary, extras=extras).normalized()
        self.case.set_config("hash_policy", pol.to_json())
        msg_info(self, "Hash policy updated",
                 f"Active policy is now: {pol.describe()}")
        self.refresh()
        mw = self.window()
        if hasattr(mw, "audit_panel"):
            mw.audit_panel.refresh()

    def _save_note(self):
        if not self.case:
            return
        text = self.notes.toPlainText().strip()
        if not text:
            return
        self.case.log("examiner.note", {"text": text[:4000]})
        self.notes.clear()
        # Bubble refresh up if audit panel exists
        mw = self.window()
        if hasattr(mw, "audit_panel"):
            mw.audit_panel.refresh()
