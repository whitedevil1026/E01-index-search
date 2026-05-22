"""Findings tab — browse raw-scan output.

The raw-scan pass produces three kinds of result that the filesystem
walk never surfaces:

  * IoC indicators   emails, URLs, IPs, cards, crypto addresses, …
  * YARA matches     carved files matching the rule pack
  * Carved files     files recovered from unallocated space by signature

They are all stored in the case database; this tab lets the examiner
browse, filter, search and export them.
"""
from __future__ import annotations

import csv
import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QPushButton, QScrollArea, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget,
)

from app.ui.exported_dialog import ExportedDialog


def _fmt_size(n) -> str:
    if not n:
        return ""
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class FindingsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        self._rows: list[dict] = []
        self._mode = "ioc"

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setMinimumSize(600, 360)
        outer.addWidget(scroll)
        inner = QWidget()
        scroll.setWidget(inner)
        root = QVBoxLayout(inner)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)

        title = QLabel("Raw-Scan Findings")
        title.setObjectName("h1")
        root.addWidget(title)

        sub = QLabel(
            "IoC indicators, YARA matches and carved files recovered by the "
            "raw scan. Run an ingest with the <b>Raw scan</b> options enabled "
            "to populate this view."
        )
        sub.setObjectName("muted")
        sub.setWordWrap(True)
        sub.setTextFormat(Qt.RichText)
        root.addWidget(sub)

        # ---- controls -------------------------------------------------
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Show:"))
        self.cmb_mode = QComboBox()
        self.cmb_mode.addItem("IoC indicators", "ioc")
        self.cmb_mode.addItem("YARA matches", "yara")
        self.cmb_mode.addItem("Carved files", "carved")
        self.cmb_mode.addItem("Flagged artifacts", "artifact")
        self.cmb_mode.currentIndexChanged.connect(self._on_mode_change)
        bar.addWidget(self.cmb_mode)

        bar.addWidget(QLabel("Type:"))
        self.cmb_subtype = QComboBox()
        self.cmb_subtype.addItem("(all)", None)
        self.cmb_subtype.currentIndexChanged.connect(self.refresh)
        bar.addWidget(self.cmb_subtype)

        self.ed_search = QLineEdit()
        self.ed_search.setPlaceholderText("filter by value / hash …")
        self.ed_search.returnPressed.connect(self.refresh)
        bar.addWidget(self.ed_search, 1)

        btn_refresh = QPushButton("Refresh")
        btn_refresh.setObjectName("secondary")
        btn_refresh.clicked.connect(self.refresh)
        bar.addWidget(btn_refresh)

        self.btn_export = QPushButton("Export CSV…")
        self.btn_export.clicked.connect(self._export)
        bar.addWidget(self.btn_export)
        root.addLayout(bar)

        # ---- summary line ---------------------------------------------
        self.lbl_summary = QLabel("")
        self.lbl_summary.setObjectName("h2")
        root.addWidget(self.lbl_summary)

        # ---- table ----------------------------------------------------
        self.tbl = QTableWidget(0, 4)
        hdr = self.tbl.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(True)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.verticalHeader().setDefaultSectionSize(26)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl.setMinimumHeight(360)
        self.tbl.cellDoubleClicked.connect(self._copy_cell)
        self.tbl.setStyleSheet(
            "QTableWidget { font-size: 10pt; }"
            "QHeaderView::section { font-weight: 600; padding: 6px; }"
        )
        root.addWidget(self.tbl, 1)

        foot = QLabel("Double-click any cell to copy its value.")
        foot.setObjectName("muted")
        root.addWidget(foot)

    # ---- state -------------------------------------------------------

    def set_case(self, case):
        self.case = case
        self.setEnabled(case is not None)
        if case is None:
            self.tbl.setRowCount(0)
            self.lbl_summary.setText("")
            return
        self._reload_subtypes()
        self.refresh()

    def showEvent(self, ev):
        super().showEvent(ev)
        if self.case is not None:
            self._reload_subtypes()
            self.refresh()

    def _on_mode_change(self):
        self._mode = self.cmb_mode.currentData()
        self._reload_subtypes()
        self.refresh()

    def _reload_subtypes(self):
        """Repopulate the Type dropdown for the current mode."""
        self.cmb_subtype.blockSignals(True)
        self.cmb_subtype.clear()
        self.cmb_subtype.addItem("(all)", None)
        if self.case is not None and self._mode in ("ioc", "yara", "artifact"):
            summ = self.case.findings_summary().get(self._mode, {})
            for sub in sorted(summ.keys()):
                self.cmb_subtype.addItem(f"{sub} ({summ[sub]:,})", sub)
            self.cmb_subtype.setEnabled(True)
        else:
            self.cmb_subtype.setEnabled(False)
        self.cmb_subtype.blockSignals(False)

    # ---- data --------------------------------------------------------

    def refresh(self):
        if not self.case:
            return
        search = self.ed_search.text().strip() or None
        if self._mode == "carved":
            self._rows = self.case.carved_files(search=search, limit=5000)
            self._render_carved()
        else:
            subtype = self.cmb_subtype.currentData()
            self._rows = self.case.list_findings(
                kind=self._mode, subtype=subtype, search=search, limit=5000)
            self._render_findings()

    def _render_findings(self):
        self.tbl.setColumnCount(4)
        self.tbl.setHorizontalHeaderLabels(
            ["Type", "Value", "Occurrences", "First offset"])
        self.tbl.setRowCount(len(self._rows))
        for i, r in enumerate(self._rows):
            self.tbl.setItem(i, 0, QTableWidgetItem(r["subtype"]))
            self.tbl.setItem(i, 1, QTableWidgetItem(r["value"]))
            it_c = QTableWidgetItem(f"{r['count']:,}")
            self.tbl.setItem(i, 2, it_c)
            off = r.get("first_offset")
            self.tbl.setItem(i, 3, QTableWidgetItem(
                f"{off:#x}" if isinstance(off, int) else ""))
        self.tbl.setColumnWidth(0, 110)
        self.tbl.setColumnWidth(1, 520)
        self.tbl.setColumnWidth(2, 110)
        kind_name = {"ioc": "IoC indicators", "yara": "YARA matches",
                     "artifact": "flagged artifacts"}.get(
                         self._mode, self._mode)
        total_occ = sum(r["count"] for r in self._rows)
        self.lbl_summary.setText(
            f"{len(self._rows):,} distinct {kind_name}  "
            f"({total_occ:,} total occurrences)")

    def _render_carved(self):
        self.tbl.setColumnCount(5)
        self.tbl.setHorizontalHeaderLabels(
            ["Name", "Size", "MD5", "SHA-256", "Path"])
        self.tbl.setRowCount(len(self._rows))
        for i, r in enumerate(self._rows):
            self.tbl.setItem(i, 0, QTableWidgetItem(r["name"]))
            self.tbl.setItem(i, 1, QTableWidgetItem(_fmt_size(r["size_bytes"])))
            self.tbl.setItem(i, 2, QTableWidgetItem(r.get("md5") or ""))
            self.tbl.setItem(i, 3, QTableWidgetItem(r.get("sha256") or ""))
            self.tbl.setItem(i, 4, QTableWidgetItem(r["path"]))
        self.tbl.setColumnWidth(0, 200)
        self.tbl.setColumnWidth(1, 90)
        self.tbl.setColumnWidth(2, 240)
        self.tbl.setColumnWidth(3, 300)
        self.lbl_summary.setText(f"{len(self._rows):,} carved files")

    # ---- helpers -----------------------------------------------------

    def _copy_cell(self, row: int, col: int):
        item = self.tbl.item(row, col)
        if item:
            QGuiApplication.clipboard().setText(item.text())

    def _export(self):
        if not self._rows:
            return
        p, _ = QFileDialog.getSaveFileName(
            self, "Export findings",
            f"findings_{self._mode}_{time.strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV (*.csv)")
        if not p:
            return
        try:
            with open(p, "w", newline="", encoding="utf-8") as fh:
                wr = csv.writer(fh)
                if self._mode == "carved":
                    wr.writerow(["Name", "SizeBytes", "MD5", "SHA256",
                                 "TLSH", "Path"])
                    for r in self._rows:
                        wr.writerow([r["name"], r["size_bytes"],
                                     r.get("md5", ""), r.get("sha256", ""),
                                     r.get("tlsh", ""), r["path"]])
                else:
                    wr.writerow(["Kind", "Type", "Value", "Occurrences",
                                 "FirstOffset"])
                    for r in self._rows:
                        off = r.get("first_offset")
                        wr.writerow([r["kind"], r["subtype"], r["value"],
                                     r["count"],
                                     f"{off:#x}" if isinstance(off, int) else ""])
        except Exception as exc:  # noqa: BLE001
            from app.ui.centered_msg import msg_error
            msg_error(self, "Export failed", str(exc))
            return
        if self.case:
            self.case.log("findings.export",
                          {"mode": self._mode, "rows": len(self._rows),
                           "path": p})
        ExportedDialog(self, title="Findings exported",
                       intro=f"Wrote {len(self._rows):,} rows:",
                       paths=[p]).exec()
