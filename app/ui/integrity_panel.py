"""E01 Integrity Checker tab.

Pick a folder containing one or more E01 image sets (or a single E01
file). Runs the segment-level checks from `app.core.ewf_integrity`,
shows per-segment results, missing chunks, and extracted case metadata,
and lets the examiner export the report as CSV + an FTK-style TXT.
"""
from __future__ import annotations

import csv
import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
    QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSplitter,
    QTableWidget, QTableWidgetItem, QTabWidget, QTextEdit, QVBoxLayout,
    QWidget,
)

from app.core.ewf_integrity import (
    SegmentInfo, SetReport, check_set, find_image_sets,
    format_report_txt, segment_index_from_ext,
)
from app.core.worker import Worker
from app.ui.centered_msg import msg_error, msg_info, msg_warn
from app.ui.exported_dialog import ExportedDialog


# ---- helpers --------------------------------------------------------------

_STATUS_COLOR = {
    "OK":      "#22c55e",
    "BAD":     "#ef4444",
    "MISSING": "#f97316",
    "?":       "#9ca0ad",
}


class _NotesDialog(QMessageBox):
    """Tiny prompt for free-form investigator notes before TXT export."""
    pass


class IntegrityPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        self._worker: Worker | None = None
        self._reports: list[SetReport] = []

        # Wrap the entire panel in a QScrollArea so the user can scroll
        # the whole tab vertically when content doesn't fit on screen.
        # IMPORTANT: cap the scroll area's minimumSize so it doesn't
        # propagate the inner widget's tall content minimum up to the
        # window. Without this, the QMainWindow's minimum height grows
        # past the screen height and Qt emits a setGeometry warning.
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
        root.setSpacing(12)

        title = QLabel("E01 Integrity Checker")
        title.setObjectName("h1")
        root.addWidget(title)

        sub = QLabel(
            "Verifies EWF / EnCase segment sets — detects missing chunks, "
            "bad signatures, wrong segment numbers, broken Adler-32 descriptors, "
            "and 'next' vs 'done' trailer markers. Also extracts case metadata "
            "(case #, examiner, OS, GUID, stored hashes). Reads only ~89 bytes "
            "per segment + the header sections — fast on network shares."
        )
        sub.setObjectName("muted")
        sub.setWordWrap(True)
        root.addWidget(sub)

        # ---- input ----------------------------------------------------
        pick = QGroupBox("1. Select a folder or a single .E01 file")
        pl = QHBoxLayout(pick)
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(
            "Folder containing E01 segments, or a single .E01 / .Ex01 / .L01 file…"
        )
        btn_folder = QPushButton("Folder…")
        btn_folder.setObjectName("secondary")
        btn_folder.clicked.connect(self._browse_folder)
        btn_file = QPushButton("Single file…")
        btn_file.setObjectName("secondary")
        btn_file.clicked.connect(self._browse_file)
        pl.addWidget(self.path_edit, 1)
        pl.addWidget(btn_folder)
        pl.addWidget(btn_file)
        root.addWidget(pick)

        # ---- options + run --------------------------------------------
        opt = QGroupBox("2. Options")
        ol = QHBoxLayout(opt)
        self.chk_recurse = QCheckBox("Include sub-folders")
        self.chk_meta = QCheckBox("Extract case metadata (recommended)")
        self.chk_meta.setChecked(True)
        self.chk_audit = QCheckBox("Log every check to case audit log")
        self.chk_audit.setChecked(True)
        self.chk_hash_segments = QCheckBox(
            "Hash each .E01 segment file (slow — full read)"
        )
        ol.addWidget(self.chk_recurse)
        ol.addWidget(self.chk_meta)
        ol.addWidget(self.chk_audit)
        ol.addWidget(self.chk_hash_segments)
        ol.addStretch(1)
        root.addWidget(opt)

        run_row = QHBoxLayout()
        self.btn_run = QPushButton("Run Integrity Check")
        self.btn_run.setToolTip(
            "Walk every EWF segment in the chosen path: verify the EVF/LVF "
            "signature, check the trailing Adler-32 descriptor, detect "
            "missing E01/E02/… chunks, and (optionally) extract the case "
            "metadata stored in the EWF header. Reads ~89 bytes per segment "
            "so it's fast even over a network share."
        )
        self.btn_run.clicked.connect(self._run)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setObjectName("danger")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel)
        self.btn_export = QPushButton("Export Report…")
        self.btn_export.setObjectName("secondary")
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self._export_report)
        run_row.addWidget(self.btn_run)
        run_row.addWidget(self.btn_cancel)
        run_row.addWidget(self.btn_export)
        run_row.addStretch(1)
        self.lbl_summary = QLabel("")
        self.lbl_summary.setObjectName("h2")
        run_row.addWidget(self.lbl_summary)
        root.addLayout(run_row)

        self.progress = QProgressBar()
        self.progress.setFormat("%v / %m   %p%")
        root.addWidget(self.progress)

        # ---- results: splitter ---------------------------------------
        split = QSplitter(Qt.Vertical)

        # Per-segment table
        seg_box = QGroupBox("Per-segment results  (double-click any cell to copy)")
        sl = QVBoxLayout(seg_box)

        self.tbl = QTableWidget(0, 9)
        self.tbl.setHorizontalHeaderLabels([
            "Status", "Image set", "Segment file", "Size (bytes)",
            "Header", "Family", "Trailer", "Adler-32", "Notes",
        ])
        # Better visibility: bigger fonts on cells, taller rows, smart widths
        hdr = self.tbl.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(True)
        hdr.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.verticalHeader().setVisible(False)
        # Default row size used until refresh sets explicit per-row heights.
        self.tbl.verticalHeader().setDefaultSectionSize(34)
        self.tbl.verticalHeader().setMinimumSectionSize(28)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl.setShowGrid(True)
        # min height kept modest so the panel still fits on a 1024x768
        # display; the scroll area absorbs anything taller.
        self.tbl.setMinimumHeight(140)
        self.tbl.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.tbl.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.tbl.cellDoubleClicked.connect(self._copy_cell)
        self.tbl.setStyleSheet(
            "QTableWidget { font-size: 10pt; gridline-color:#2a2d35; }"
            "QTableWidget::item { padding: 4px 6px; }"
            "QHeaderView::section { font-weight: 600; padding: 8px; }"
        )
        # Preferred minimums so columns don't get cropped
        self._col_min_widths = {
            0: 80,    # Status
            1: 200,   # Set
            2: 240,   # Segment file
            3: 110,   # Size
            4: 80,    # Header
            5: 120,   # Family
            6: 80,    # Trailer
            7: 80,    # Adler-32
            8: 360,   # Notes
        }
        sl.addWidget(self.tbl)
        split.addWidget(seg_box)

        # Metadata + console
        bot_tabs = QTabWidget()
        bot_tabs.setDocumentMode(True)

        # Metadata view (selectable values)
        meta_widget = QWidget()
        ml = QVBoxLayout(meta_widget)
        ml.setContentsMargins(8, 8, 8, 8)
        self.meta_box = QFormLayout()
        self.meta_box.setLabelAlignment(Qt.AlignLeft)
        meta_inner = QWidget()
        meta_inner.setLayout(self.meta_box)
        ml.addWidget(meta_inner)
        ml.addStretch(1)
        bot_tabs.addTab(meta_widget, "Case Metadata")

        # Console
        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumBlockCount(20_000)
        self.log_box.setFont(QFont("Consolas", 9))
        self.log_box.setStyleSheet(
            "QPlainTextEdit { background:#0a0c10; color:#d4d4d4; }"
        )
        bot_tabs.addTab(self.log_box, "Console")

        split.addWidget(bot_tabs)
        split.setSizes([240, 200])
        split.setMinimumHeight(280)
        root.addWidget(split, 1)

    # ---- state -------------------------------------------------------

    def set_case(self, case):
        self.case = case
        self.chk_audit.setEnabled(case is not None)
        if case is None:
            self.chk_audit.setChecked(False)

    # ---- browse ------------------------------------------------------

    def _browse_folder(self):
        d = QFileDialog.getExistingDirectory(
            self, "Select folder containing E01 segments", str(Path.home())
        )
        if d:
            self.path_edit.setText(d)

    def _browse_file(self):
        p, _ = QFileDialog.getOpenFileName(
            self, "Select first E01 segment", str(Path.home()),
            "EWF images (*.E01 *.Ex01 *.L01 *.Lx01);;All files (*.*)",
        )
        if p:
            self.path_edit.setText(p)

    # ---- run ---------------------------------------------------------

    def _run(self):
        path_text = self.path_edit.text().strip()
        if not path_text:
            msg_warn(self, "Missing path", "Pick a folder or .E01 file first.")
            return
        target = Path(path_text)
        if not target.exists():
            msg_warn(self, "Not found", f"{target} does not exist.")
            return

        # Build list of image sets
        if target.is_dir():
            sets = find_image_sets(str(target), recurse=self.chk_recurse.isChecked())
        else:
            sets = find_image_sets(str(target.parent), recurse=False)
            sets = [s for s in sets if target in s or target.stem == s[0].stem]
            if not sets and segment_index_from_ext(target.suffix) > 0:
                sets = [[target]]

        if not sets:
            msg_info(self, "Nothing found",
                     "No E01 / L01 / Ex01 segments in that path.")
            return

        # Reset UI
        self.tbl.setRowCount(0)
        self._clear_meta()
        self.log_box.clear()
        self._reports = []
        self.btn_export.setEnabled(False)
        self.progress.setRange(0, sum(len(s) for s in sets))
        self.progress.setValue(0)
        self.btn_run.setEnabled(False)
        self.btn_cancel.setEnabled(True)

        case = self.case
        do_audit = self.chk_audit.isChecked() and case is not None
        do_meta = self.chk_meta.isChecked()
        do_hash_segments = self.chk_hash_segments.isChecked()
        progress_n = [0]
        self._segment_hashes: dict[str, dict[str, dict[str, str]]] = {}
        policy = case.hash_policy() if case else None

        def task(w: Worker) -> tuple[bool, str]:
            from app.core.hash_policy import hash_path_with_policy, HashPolicy
            pol = policy or HashPolicy()
            for st in sets:
                if w.cancelled:
                    break
                w.log.emit(f"=== Image set: {st[0].stem}  ({len(st)} segments) ===")
                report = check_set(
                    st,
                    extract_meta=do_meta,
                    on_log=lambda m: w.log.emit(m),
                    on_segment=lambda seg, cur, tot: (
                        progress_n.__setitem__(0, progress_n[0] + 1),
                        w.progress.emit(progress_n[0], 0, ""),
                    ),
                )
                self._reports.append(report)
                if do_hash_segments:
                    seg_hashes: dict[str, dict[str, str]] = {}
                    for seg_path in st:
                        if w.cancelled:
                            break
                        w.log.emit(f"  hashing {seg_path.name} with {pol.describe()}…")
                        try:
                            result = hash_path_with_policy(str(seg_path), pol)
                            digs = {k.upper(): str(v) for k, v in result.items()
                                    if k != "size_bytes"}
                            seg_hashes[seg_path.name] = digs
                            for algo, d in digs.items():
                                w.log.emit(f"    {algo:<8s}= {d}")
                        except Exception as exc:  # noqa: BLE001
                            w.log.emit(f"    [error] {exc}")
                    self._segment_hashes[report.image_set] = seg_hashes
                if do_audit and case:
                    case.log("integrity.check", {
                        "set": report.image_set,
                        "ok": report.summary["ok"],
                        "bad": report.summary["bad"],
                        "missing": report.summary["missing"],
                        "complete": report.summary["complete"],
                        "missing_segments": report.missing,
                        "segments_hashed": do_hash_segments,
                    })
            n = sum(len(r.segments) for r in self._reports)
            mset = sum(1 for r in self._reports if not r.summary["complete"])
            return (
                True,
                f"checked {len(self._reports)} set(s), {n} segment records, "
                f"{mset} incomplete",
            )

        w = Worker(task, self)
        w.log.connect(self._append_log)
        w.done.connect(self._on_done)
        w.error.connect(lambda m: self._append_log(f"[error] {m}"))
        self._worker = w
        w.start()

    def _cancel(self):
        if self._worker:
            self._worker.request_cancel()
            self._append_log("[cancel] cancellation requested")

    def _on_done(self, ok: bool, msg: str):
        self.btn_run.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_export.setEnabled(bool(self._reports))
        self._append_log(("[ok] " if ok else "[fail] ") + msg)
        self._refresh_results()
        mw = self.window()
        if hasattr(mw, "audit_panel"):
            mw.audit_panel.refresh()

    # ---- result rendering -------------------------------------------

    def _refresh_results(self):
        rows: list[tuple[str, SegmentInfo]] = []
        for rep in self._reports:
            for seg in rep.segments:
                rows.append((rep.image_set, seg))
        self.tbl.setRowCount(len(rows))
        for i, (set_name, seg) in enumerate(rows):
            color = QColor(_STATUS_COLOR.get(seg.status, "#9ca0ad"))
            it_status = QTableWidgetItem(seg.status)
            it_status.setForeground(color)
            it_status.setFont(QFont("Segoe UI", 10, QFont.Bold))
            self.tbl.setItem(i, 0, it_status)
            self.tbl.setItem(i, 1, QTableWidgetItem(set_name))
            self.tbl.setItem(i, 2, QTableWidgetItem(seg.file_name))
            self.tbl.setItem(i, 3, QTableWidgetItem(
                f"{seg.size_bytes:,}" if seg.size_bytes else ""))
            self.tbl.setItem(i, 4, QTableWidgetItem(
                "OK" if seg.header_valid else (
                    "MISSING" if seg.status == "MISSING" else "BAD")))
            self.tbl.setItem(i, 5, QTableWidgetItem(seg.family))
            self.tbl.setItem(i, 6, QTableWidgetItem(seg.last_section_type or ""))
            adler = ""
            if seg.descriptor_checksum_ok is True:
                adler = "OK"
            elif seg.descriptor_checksum_ok is False:
                adler = "BAD"
            self.tbl.setItem(i, 7, QTableWidgetItem(adler))
            self.tbl.setItem(i, 8, QTableWidgetItem("  ".join(seg.notes)))
            # Explicit row height — never rely on resizeRowsToContents which
            # can collapse rows to a few pixels when content is short.
            self.tbl.setRowHeight(i, 34)
        # Resize columns: first by contents, then enforce minimums
        self.tbl.resizeColumnsToContents()
        for col, mw in self._col_min_widths.items():
            if self.tbl.columnWidth(col) < mw:
                self.tbl.setColumnWidth(col, mw)

        # populate metadata pane (first complete report wins)
        self._clear_meta()
        meta_report = next(
            (r for r in self._reports if r.summary["complete"]),
            self._reports[0] if self._reports else None,
        )
        if meta_report and meta_report.metadata:
            for k, v in meta_report.metadata.as_ordered():
                if v:
                    self._add_meta(k, v)
            if meta_report.metadata.metadata_error:
                self._add_meta("MetadataError", meta_report.metadata.metadata_error)

        # summary label
        total = sum(len(r.segments) for r in self._reports)
        ok = sum(r.summary["ok"] for r in self._reports)
        bad = sum(r.summary["bad"] for r in self._reports)
        miss = sum(r.summary["missing"] for r in self._reports)
        incomplete = sum(1 for r in self._reports if not r.summary["complete"])
        col = "#22c55e" if incomplete == 0 else "#ef4444"
        self.lbl_summary.setText(
            f"<span style='color:{col};'>Sets: {len(self._reports)} "
            f"({incomplete} incomplete)  |  OK={ok}  BAD={bad}  MISSING={miss}</span>"
        )
        self.lbl_summary.setTextFormat(Qt.RichText)

    def _clear_meta(self):
        while self.meta_box.rowCount() > 0:
            self.meta_box.removeRow(0)

    def _add_meta(self, k: str, v: str):
        # value as selectable read-only line so the examiner can copy it
        lbl_v = QLineEdit(str(v))
        lbl_v.setReadOnly(True)
        lbl_v.setFrame(False)
        lbl_v.setStyleSheet(
            "QLineEdit { background: transparent; color:#e8e8ea; "
            "padding-left:0; }"
        )
        # Provide a per-row Copy button
        row = QWidget()
        rl = QHBoxLayout(row)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)
        rl.addWidget(lbl_v, 1)
        btn = QPushButton("Copy")
        btn.setObjectName("secondary")
        btn.setFixedWidth(56)
        btn.clicked.connect(lambda _, t=str(v): self._copy_text(t, btn))
        rl.addWidget(btn)
        self.meta_box.addRow(QLabel(f"<b>{k}</b>"), row)

    def _copy_cell(self, row: int, col: int):
        item = self.tbl.item(row, col)
        if not item:
            return
        from PySide6.QtGui import QGuiApplication
        QGuiApplication.clipboard().setText(item.text())
        self._append_log(f"[copy] {item.text()[:120]}")

    def _copy_text(self, text: str, btn: QPushButton):
        from PySide6.QtGui import QGuiApplication
        from PySide6.QtCore import QTimer
        QGuiApplication.clipboard().setText(text)
        btn.setText("Copied")
        btn.setEnabled(False)
        QTimer.singleShot(700, lambda: (btn.setText("Copy"), btn.setEnabled(True)))

    # ---- export ------------------------------------------------------

    def _export_report(self):
        if not self._reports:
            return
        opts = _ExportOptionsDialog(self,
                                    suggest_extras=bool(self.case),
                                    case_name=(self.case.meta().name if self.case else ""),
                                    examiner=(self.case.meta().examiner if self.case else ""))
        if opts.exec() != QDialog.Accepted:
            return
        choice = opts.choice()

        d = QFileDialog.getExistingDirectory(self, "Export to folder…",
                                             str(Path.home()))
        if not d:
            return
        ts = time.strftime("%Y%m%d_%H%M%S")
        outdir = Path(d)
        written: list[str] = []

        try:
            if choice["csv_segments"]:
                p = outdir / f"E01_IntegrityReport_{ts}.csv"
                self._write_csv(p)
                written.append(str(p))
            if choice["csv_case"]:
                p = outdir / f"E01_CaseInfo_{ts}.csv"
                self._write_case_csv(p)
                written.append(str(p))
            if choice["txt"]:
                p = outdir / f"E01_CaseReport_{ts}.txt"
                txt = format_report_txt(
                    self._reports,
                    case_name=choice["case_name"],
                    examiner=choice["examiner"],
                    case_id=choice["case_id"],
                    investigator_notes=choice["notes"],
                    extras=self._segment_hashes,
                )
                p.write_text(txt, encoding="utf-8")
                written.append(str(p))
        except Exception as exc:  # noqa: BLE001
            msg_error(self, "Export failed", f"{type(exc).__name__}: {exc}")
            return

        if self.case:
            self.case.log("integrity.export", {"files": written, **choice})

        # show custom dialog with copyable paths
        ExportedDialog(self, title="Reports exported",
                       intro=f"Wrote {len(written)} file(s):",
                       paths=written).exec()

    def _write_csv(self, p: Path):
        with open(p, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow([
                "ImageSet", "SegmentFile", "FullPath", "SizeBytes",
                "HeaderValid", "HeaderHex32",
                "FormatFamily",
                "SegmentIndex_FromFilename", "SegmentIndex_InsideHeader",
                "SegmentIndex_Matches",
                "TrailingSectionType", "Adler32_TrailerValid",
                "OverallStatus", "Notes",
            ])
            for rep in self._reports:
                for s in rep.segments:
                    w.writerow([
                        rep.image_set, s.file_name, s.full_path, s.size_bytes,
                        s.header_valid, s.header_hex, s.family,
                        s.segment_from_name, s.segment_in_header or "",
                        "" if s.segment_number_match is None else s.segment_number_match,
                        s.last_section_type,
                        "" if s.descriptor_checksum_ok is None else s.descriptor_checksum_ok,
                        s.status, " | ".join(s.notes),
                    ])

    def _write_case_csv(self, p: Path):
        with open(p, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["ImageSet", "FirstSegment", "LastSegment",
                        "MetadataField", "Value"])
            for rep in self._reports:
                for k, v in rep.metadata.as_ordered():
                    if v:
                        w.writerow([rep.image_set, rep.first_segment,
                                    rep.last_segment, k, v])

    # ---- logging -----------------------------------------------------

    def _append_log(self, line: str):
        ts = time.strftime("%H:%M:%S")
        self.log_box.appendPlainText(f"{ts}  {line}")


# ---- Export Options dialog ------------------------------------------------

class _ExportOptionsDialog(QDialog):
    """Asks the examiner what to include in the export bundle and lets
    them fill in optional case metadata for the TXT report.
    """

    def __init__(self, parent, *, suggest_extras: bool,
                 case_name: str = "", examiner: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Export integrity report")
        self.setMinimumWidth(560)
        self.setStyleSheet(parent.styleSheet() if parent else "")

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 12)
        root.setSpacing(10)

        h = QLabel("Choose what to export")
        h.setObjectName("h1")
        root.addWidget(h)

        intro = QLabel(
            "The TXT report is FTK-Imager-style: examiner / case info, "
            "acquisition metadata from the EWF header, per-segment "
            "verification table, plus any full-segment hashes you "
            "computed during the run."
        )
        intro.setObjectName("muted")
        intro.setWordWrap(True)
        root.addWidget(intro)

        # Output choices
        box = QGroupBox("Output files")
        bl = QVBoxLayout(box)
        self.chk_txt = QCheckBox("Professional .txt case report (FTK-style)")
        self.chk_txt.setChecked(True)
        self.chk_csv_segments = QCheckBox(
            "CSV — per-segment verification (one row per segment)")
        self.chk_csv_segments.setChecked(True)
        self.chk_csv_case = QCheckBox(
            "CSV — case metadata (one row per metadata field)")
        self.chk_csv_case.setChecked(True)
        bl.addWidget(self.chk_txt)
        bl.addWidget(self.chk_csv_segments)
        bl.addWidget(self.chk_csv_case)
        root.addWidget(box)

        # TXT-only fields
        form_box = QGroupBox("Case details for the .txt report (optional — leave blank to skip)")
        fl = QFormLayout(form_box)
        self.ed_case = QLineEdit(case_name)
        self.ed_case_id = QLineEdit()
        self.ed_examiner = QLineEdit(examiner)
        self.ed_notes = QTextEdit()
        self.ed_notes.setPlaceholderText(
            "Free-form notes — methodology, chain-of-custody comments, "
            "scope, environmental conditions, etc."
        )
        self.ed_notes.setFixedHeight(96)
        fl.addRow("Case name:", self.ed_case)
        fl.addRow("Case identifier:", self.ed_case_id)
        fl.addRow("Examiner:", self.ed_examiner)
        fl.addRow("Notes:", self.ed_notes)
        root.addWidget(form_box)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    def choice(self) -> dict:
        return {
            "txt": self.chk_txt.isChecked(),
            "csv_segments": self.chk_csv_segments.isChecked(),
            "csv_case": self.chk_csv_case.isChecked(),
            "case_name": self.ed_case.text().strip(),
            "case_id": self.ed_case_id.text().strip(),
            "examiner": self.ed_examiner.text().strip(),
            "notes": self.ed_notes.toPlainText().strip(),
        }


# Expose for ingest panel pre-flight
def quick_pre_flight(first_segment: str) -> SetReport:
    p = Path(first_segment)
    sets = find_image_sets(str(p.parent), recurse=False)
    paths = next((s for s in sets if p in s or p.stem == s[0].stem), [p])
    return check_set(paths, extract_meta=True)
