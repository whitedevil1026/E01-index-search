"""Audit log panel — append-only, hash-chained, with verify button."""
from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QPushButton, QSpinBox,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)


def _fmt_time(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


class AuditPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        title = QLabel("Audit Log")
        title.setObjectName("h1")
        root.addWidget(title)

        sub = QLabel("Append-only. Each row is hash-chained to the previous via SHA-256.")
        sub.setObjectName("muted")
        root.addWidget(sub)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("Show last:"))
        self.spin = QSpinBox()
        self.spin.setRange(50, 50_000)
        self.spin.setValue(500)
        bar.addWidget(self.spin)
        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.setObjectName("secondary")
        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_verify = QPushButton("Verify Chain")
        self.btn_verify.clicked.connect(self._verify)
        bar.addWidget(self.btn_refresh)
        bar.addWidget(self.btn_verify)
        bar.addStretch(1)
        self.lbl_status = QLabel("")
        self.lbl_status.setObjectName("muted")
        bar.addWidget(self.lbl_status)
        root.addLayout(bar)

        self.tbl = QTableWidget(0, 6)
        self.tbl.setHorizontalHeaderLabels(
            ["ID", "Time", "Actor", "Action", "Payload", "Row Hash"]
        )
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.tbl.horizontalHeader().setStretchLastSection(True)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        root.addWidget(self.tbl, 1)

    def set_case(self, case):
        self.case = case
        self.setEnabled(case is not None)
        self.refresh()

    def refresh(self):
        if not self.case:
            self.tbl.setRowCount(0)
            self.lbl_status.setText("")
            return
        rows = self.case.audit_rows(limit=self.spin.value())
        self.tbl.setRowCount(len(rows))
        for i, r in enumerate(rows):
            self.tbl.setItem(i, 0, QTableWidgetItem(str(r["id"])))
            self.tbl.setItem(i, 1, QTableWidgetItem(_fmt_time(r["ts"])))
            self.tbl.setItem(i, 2, QTableWidgetItem(r["actor"]))
            self.tbl.setItem(i, 3, QTableWidgetItem(r["action"]))
            payload = r["payload_json"]
            if len(payload) > 200:
                payload = payload[:200] + "…"
            self.tbl.setItem(i, 4, QTableWidgetItem(payload))
            self.tbl.setItem(i, 5, QTableWidgetItem(r["row_hash"][:16]))
        self.lbl_status.setText(f"{len(rows)} rows shown")

    def _verify(self):
        if not self.case:
            return
        ok, msg = self.case.verify_audit_chain()
        self.lbl_status.setText(("OK — " if ok else "BROKEN — ") + msg)
