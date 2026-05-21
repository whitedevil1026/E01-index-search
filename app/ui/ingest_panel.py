"""Ingest panel — pick an E01, inspect, then walk + hash + index."""
from __future__ import annotations

import io
import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
    QProgressBar, QPushButton, QScrollArea, QSpinBox, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from app.core.ewf_reader import inspect, glob_segments, EwfHandle, HAS_PYEWF
from app.core.filesystem import walk_image, HAS_PYTSK3
from app.core.hashing import hash_stream
from app.core.hash_policy import HashPolicy
from app.core.indexer import HAS_TANTIVY, Indexer
from app.core.text_extract import extract_text, MAX_TEXT_CHARS
from app.core.worker import Worker
from app.ui.centered_msg import msg_error, msg_info, msg_question, msg_warn
from app.ui.integrity_panel import quick_pre_flight


class IngestPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        self._worker: Worker | None = None

        # Whole panel is scrollable so the user can always reach the
        # bottom log even on a small window. Cap the scroll-area's own
        # minimumSize so the inner content's tall min-height doesn't
        # bubble up to the QMainWindow.
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

        title = QLabel("Ingest E01 Image")
        title.setObjectName("h1")
        root.addWidget(title)

        self.lbl_policy = QLabel("")
        self.lbl_policy.setObjectName("muted")
        self.lbl_policy.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl_policy.setWordWrap(True)
        root.addWidget(self.lbl_policy)

        # ---- pick image -----------------------------------------------
        pick = QGroupBox("1. Select first segment (.E01 / .Ex01 / .L01)")
        pl = QHBoxLayout(pick)
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Path to image.E01 …")
        btn_browse = QPushButton("Browse…")
        btn_browse.setObjectName("secondary")
        btn_browse.clicked.connect(self._browse)
        btn_inspect = QPushButton("Inspect")
        btn_inspect.setToolTip(
            "Read the E01 header without scanning the whole file. Shows "
            "format, segment count, size, and any MD5/SHA-1 written into "
            "the header by the original acquisition tool. Enables the "
            "Compute Now button."
        )
        btn_inspect.clicked.connect(self._inspect)
        btn_integrity = QPushButton("Integrity Check")
        btn_integrity.setObjectName("secondary")
        btn_integrity.clicked.connect(self._preflight_integrity)
        btn_integrity.setToolTip(
            "Verify the segment set is complete and not corrupted before ingest."
        )
        pl.addWidget(self.path_edit, 1)
        pl.addWidget(btn_browse)
        pl.addWidget(btn_inspect)
        pl.addWidget(btn_integrity)
        root.addWidget(pick)

        # ---- 2a: image info (header-only, no I/O over the whole file) -
        insp = QGroupBox("2a. Image metadata (read from the E01 header — fast)")
        form = QFormLayout(insp)
        self.lbl_format = QLabel("—")
        self.lbl_segments = QLabel("—")
        self.lbl_size = QLabel("—")
        self.lbl_encrypted = QLabel("—")
        self.lbl_acq_md5 = QLabel("—")
        self.lbl_acq_sha1 = QLabel("—")
        for w in (self.lbl_format, self.lbl_segments, self.lbl_size,
                  self.lbl_encrypted, self.lbl_acq_md5, self.lbl_acq_sha1):
            w.setTextInteractionFlags(Qt.TextSelectableByMouse)
        form.addRow("Format:", self.lbl_format)
        form.addRow("Segments:", self.lbl_segments)
        form.addRow("Total size:", self.lbl_size)
        form.addRow("Encrypted (Ex01 guess):", self.lbl_encrypted)
        # Hard separation: these are not policy hashes. They are values
        # the *original* acquisition tool wrote inside the E01 file
        # itself. We surface them so you can independently verify your
        # computed policy hashes against the recorded acquisition values.
        note_acq = QLabel(
            "<b>The two hash fields below are NOT computed by this tool.</b>  "
            "They are the values the original acquisition software "
            "(EnCase / FTK Imager / dd-style) wrote into the E01 header at "
            "the time the image was created. They will always be MD5 / "
            "SHA-1 because that's what EnCase records — they do not "
            "change with your case hash policy."
        )
        note_acq.setWordWrap(True)
        note_acq.setObjectName("muted")
        note_acq.setStyleSheet(
            "color:#f59e0b; background:#1a1d24; padding:8px; "
            "border-radius:4px; border-left: 3px solid #f59e0b;"
        )
        note_acq.setTextFormat(Qt.RichText)
        form.addRow(note_acq)
        form.addRow("MD5 written by acquisition tool:", self.lbl_acq_md5)
        form.addRow("SHA-1 written by acquisition tool:", self.lbl_acq_sha1)
        root.addWidget(insp)

        # ---- 2b: case-policy hashes (computed by THIS tool, on demand) -
        comp_box = QGroupBox("2b. Hashes computed by THIS tool per the case hash policy")
        comp_layout = QVBoxLayout(comp_box)
        comp_intro = QLabel(
            "Click <b>Compute Now</b> to read the entire E01 file (every segment) "
            "and compute the hashes selected by the case's hash policy. This is "
            "the fingerprint that goes into the audit log and the manifest."
        )
        comp_intro.setObjectName("muted")
        comp_intro.setWordWrap(True)
        comp_intro.setTextFormat(Qt.RichText)
        comp_layout.addWidget(comp_intro)

        ch_row = QHBoxLayout()
        self.lbl_comp_policy = QLabel("—")
        self.lbl_comp_policy.setTextInteractionFlags(Qt.TextSelectableByMouse)
        ch_row.addWidget(QLabel("Will compute:"))
        ch_row.addWidget(self.lbl_comp_policy, 1)
        self.btn_compute = QPushButton("Compute Now")
        self.btn_compute.clicked.connect(self._compute_policy_hashes)
        self.btn_compute.setEnabled(False)
        self.btn_compute.setToolTip(
            "Hash the entire E01 segment(s) with the case's hash policy."
        )
        ch_row.addWidget(self.btn_compute)
        comp_layout.addLayout(ch_row)

        # Results form populated dynamically per algorithm
        self.comp_form = QFormLayout()
        comp_layout.addLayout(self.comp_form)
        self._comp_value_widgets: dict[str, QLineEdit] = {}

        self.lbl_comp_status = QLabel("")
        self.lbl_comp_status.setObjectName("muted")
        self.lbl_comp_status.setWordWrap(True)
        comp_layout.addWidget(self.lbl_comp_status)
        root.addWidget(comp_box)

        # ---- case hash policy box -------------------------------------
        policy_box = QGroupBox("Case hash policy — what THIS tool will compute on every file")
        ppl = QFormLayout(policy_box)
        self.lbl_policy_primary = QLabel("—")
        self.lbl_policy_extras = QLabel("—")
        for w in (self.lbl_policy_primary, self.lbl_policy_extras):
            w.setTextInteractionFlags(Qt.TextSelectableByMouse)
            w.setWordWrap(True)
        ppl.addRow("Primary hash:", self.lbl_policy_primary)
        ppl.addRow("Extra hashes:", self.lbl_policy_extras)
        change_hint = QLabel(
            "<i>To change the policy for this case, go to the <b>Case</b> tab → "
            "<b>Hash policy</b> section.</i>"
        )
        change_hint.setObjectName("muted")
        change_hint.setTextFormat(Qt.RichText)
        ppl.addRow(change_hint)
        root.addWidget(policy_box)

        # ---- options + run --------------------------------------------
        opt = QGroupBox("3. Walk filesystem + hash files + index into Tantivy")
        ol = QVBoxLayout(opt)
        opt_row = QHBoxLayout()
        opt_row.addWidget(QLabel("File-count cap:"))
        self.spin_max = QSpinBox()
        self.spin_max.setRange(0, 10_000_000)
        self.spin_max.setValue(5000)
        self.spin_max.setSuffix("  (0 = walk the entire image)")
        self.spin_max.setToolTip(
            "Stop after enumerating this many files. Useful for quick "
            "previews on huge images. 0 disables the cap."
        )
        opt_row.addWidget(self.spin_max)
        opt_row.addSpacing(20)
        self.chk_hash = QCheckBox("Hash file contents per case policy (slow)")
        self.chk_hash.setChecked(True)
        self.chk_index = QCheckBox("Index file names + paths")
        self.chk_index.setChecked(True)
        opt_row.addWidget(self.chk_hash)
        opt_row.addWidget(self.chk_index)
        opt_row.addStretch(1)
        ol.addLayout(opt_row)

        # content-extraction row
        content_row = QHBoxLayout()
        self.chk_content = QCheckBox(
            "Extract & index file CONTENTS (text inside PDFs, Office docs, "
            "emails, text files)"
        )
        self.chk_content.setToolTip(
            "Reads each regular file's bytes from the image and extracts its "
            "text so search can match words inside documents — not just file "
            "names. Significantly slower because it reads the actual file "
            "data, not just metadata."
        )
        self.chk_content.toggled.connect(self._on_content_toggled)
        content_row.addWidget(self.chk_content)
        content_row.addSpacing(16)
        content_row.addWidget(QLabel("Max file size to extract:"))
        self.spin_content_mb = QSpinBox()
        self.spin_content_mb.setRange(1, 1024)
        self.spin_content_mb.setValue(32)
        self.spin_content_mb.setSuffix(" MB")
        self.spin_content_mb.setEnabled(False)
        self.spin_content_mb.setToolTip(
            "Files larger than this are skipped for content extraction "
            "(their names are still indexed). Big media files rarely hold "
            "searchable text and slow the walk down."
        )
        content_row.addWidget(self.spin_content_mb)
        content_row.addStretch(1)
        ol.addLayout(content_row)

        content_note = QLabel(
            "Supported: PDF · DOCX/XLSX/PPTX · MSG · EML · HTML · RTF · "
            "plain-text & source files. Legacy DOC/XLS/PPT are detected but "
            "not yet extracted (a future release). Pure-Python — no Java / Tika."
        )
        content_note.setObjectName("muted")
        content_note.setWordWrap(True)
        ol.addWidget(content_note)

        run_row = QHBoxLayout()
        self.btn_run = QPushButton("Ingest into Case")
        self.btn_run.setToolTip(
            "Register the evidence row, walk every filesystem inside the "
            "E01 with The Sleuth Kit, optionally hash each file with the "
            "case hash policy, and index file names + paths into Tantivy. "
            "All actions go into the audit log."
        )
        self.btn_run.clicked.connect(self._run)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setObjectName("danger")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel)
        run_row.addWidget(self.btn_run)
        run_row.addWidget(self.btn_cancel)
        run_row.addStretch(1)
        ol.addLayout(run_row)

        progress_label = QLabel(
            "Progress (files enumerated of the cap above &mdash; 0 / cap until ingest starts)"
        )
        progress_label.setObjectName("muted")
        progress_label.setTextFormat(Qt.RichText)
        ol.addWidget(progress_label)
        self.progress = QProgressBar()
        self.progress.setFormat("Files enumerated: %v / %m   (%p%)")
        self.progress.setMinimumHeight(20)
        ol.addWidget(self.progress)

        log_label = QLabel("Ingest log")
        log_label.setObjectName("h2")
        ol.addWidget(log_label)
        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumBlockCount(2000)
        # Sensible minimum so it doesn't collapse to one line, but small
        # enough that the whole panel fits on a 1024x768 display.
        self.log_box.setMinimumHeight(140)
        ol.addWidget(self.log_box, 1)
        root.addWidget(opt, 1)

        self._segs: list[str] = []
        self._info = None

    # ---- state -------------------------------------------------------

    def set_case(self, case):
        self.case = case
        self.setEnabled(case is not None)
        self._refresh_policy_views()

    def showEvent(self, ev):
        """Called every time the tab becomes visible. Re-read the policy
        in case the user changed it on the Case tab and came back.
        """
        super().showEvent(ev)
        self._refresh_policy_views()

    def _refresh_policy_views(self):
        if self.case is not None:
            policy = self.case.hash_policy()
            self.lbl_policy.setText(
                f"<b>Case:</b> {self.case.meta().name}  |  <b>Examiner:</b> "
                f"{self.case.meta().examiner}  |  <b>Hash policy:</b> {policy.describe()}"
            )
            self.lbl_policy.setTextFormat(Qt.RichText)
            self.lbl_policy_primary.setText(policy.primary.upper())
            self.lbl_policy_extras.setText(
                ", ".join(a.upper() for a in policy.extras) if policy.extras else "(none)"
            )
            self.lbl_comp_policy.setText(policy.describe())
            # Invalidate any previously-computed hashes if the policy
            # changed since they were computed.
            current_algos = set(policy.all_algos())
            shown_algos = set(self._comp_value_widgets.keys())
            if current_algos != shown_algos and self._comp_value_widgets:
                self._clear_comp_results()
                self.lbl_comp_status.setText(
                    "<i>Hash policy changed since last computation — "
                    "click Compute Now to re-hash with the new algorithms.</i>"
                )
                self.lbl_comp_status.setTextFormat(Qt.RichText)
                self.lbl_comp_status.setStyleSheet("color:#f59e0b;")
        else:
            self.lbl_policy.setText("")
            self.lbl_policy_primary.setText("—")
            self.lbl_policy_extras.setText("—")
            self.lbl_comp_policy.setText("—")
            self._clear_comp_results()
            self.lbl_comp_status.setText("")

    # ---- handlers ----------------------------------------------------

    def _browse(self):
        p, _ = QFileDialog.getOpenFileName(
            self, "Select first segment",
            str(Path.home()),
            "EWF Images (*.E01 *.Ex01 *.L01 *.Lx01);;All files (*.*)",
        )
        if p:
            self.path_edit.setText(p)

    def _on_content_toggled(self, checked: bool):
        self.spin_content_mb.setEnabled(checked)

    def _clear_comp_results(self):
        while self.comp_form.rowCount() > 0:
            self.comp_form.removeRow(0)
        self._comp_value_widgets.clear()

    def _set_comp_row(self, algo: str, value: str):
        edit = QLineEdit(value)
        edit.setReadOnly(True)
        edit.setCursorPosition(0)
        edit.setStyleSheet(
            "QLineEdit { font-family:'Consolas','Courier New',monospace; "
            "background:#1a1d24; padding:5px; }"
        )
        row = QWidget()
        rl = QHBoxLayout(row); rl.setContentsMargins(0,0,0,0); rl.setSpacing(6)
        rl.addWidget(edit, 1)
        copy_btn = QPushButton("Copy")
        copy_btn.setObjectName("secondary")
        copy_btn.setFixedWidth(60)
        copy_btn.clicked.connect(lambda _, t=value, b=copy_btn: self._copy(t, b))
        rl.addWidget(copy_btn)
        self.comp_form.addRow(QLabel(f"<b>{algo.upper()}</b>"), row)
        self._comp_value_widgets[algo] = edit

    def _copy(self, text: str, btn):
        from PySide6.QtGui import QGuiApplication
        from PySide6.QtCore import QTimer
        QGuiApplication.clipboard().setText(text)
        btn.setText("Copied")
        btn.setEnabled(False)
        QTimer.singleShot(700, lambda: (btn.setText("Copy"), btn.setEnabled(True)))

    def _compute_policy_hashes(self):
        if not self.case or not self._segs:
            msg_warn(self, "Inspect first",
                     "Pick an E01 file and click Inspect before computing.")
            return
        policy = self.case.hash_policy()
        from app.core.hash_policy import hash_path_with_policy
        # Reset UI
        self._clear_comp_results()
        for algo in policy.all_algos():
            self._set_comp_row(algo, "(computing…)")
        self.btn_compute.setEnabled(False)
        self.lbl_comp_status.setText(
            f"Computing {policy.describe()} over {len(self._segs)} segment(s) — "
            "this reads the full E01 file."
        )
        self.lbl_comp_status.setStyleSheet("color:#facc15;")

        segs = list(self._segs)
        total_bytes = sum(Path(p).stat().st_size for p in segs)

        def task(w: Worker) -> tuple[bool, str]:
            # Single pass per segment, accumulate across segments per algo
            from app.core.hash_policy import _new_hasher
            hashers = {a: _new_hasher(a) for a in policy.all_algos()}
            done = 0
            t0 = time.time()
            for seg in segs:
                w.log.emit(f"hashing segment: {Path(seg).name}")
                with open(seg, "rb") as fh:
                    while True:
                        if w.cancelled:
                            return False, "cancelled by user"
                        chunk = fh.read(1 << 20)
                        if not chunk:
                            break
                        done += len(chunk)
                        for h in hashers.values():
                            h.update(chunk)
                        w.progress.emit(done, total_bytes, "")
            elapsed = time.time() - t0
            mb_s = (total_bytes / 1024 / 1024) / max(elapsed, 0.001)
            for algo, h in hashers.items():
                hex_digest = h.hexdigest()
                # back to UI thread via signal — but Worker uses
                # a single 'log' signal so we encode the value
                w.log.emit(f"@HASH@{algo}={hex_digest}")
            return True, (
                f"computed {len(hashers)} hashes over "
                f"{total_bytes:,} bytes in {elapsed:.1f}s ({mb_s:.0f} MB/s)"
            )

        w = Worker(task, self)

        # Update the per-row widget when each hash is emitted
        def on_log(line: str):
            if line.startswith("@HASH@") and "=" in line:
                _, body = line.split("@HASH@", 1)
                algo, hex_digest = body.split("=", 1)
                if algo in self._comp_value_widgets:
                    self._comp_value_widgets[algo].setText(hex_digest)
                self._append_log(f"  {algo.upper():<10s}= {hex_digest}")
            else:
                self._append_log(line)

        def on_progress(cur, tot, _msg):
            if tot:
                pct = (cur * 100) // tot
                self.lbl_comp_status.setText(
                    f"Hashing… {cur:,} / {tot:,} bytes  ({pct}%)"
                )

        def on_done(ok, msg):
            self.btn_compute.setEnabled(True)
            if ok:
                self.lbl_comp_status.setText(msg)
                self.lbl_comp_status.setStyleSheet("color:#22c55e;")
                # Audit-log it
                if self.case:
                    self.case.log("ingest.hash_compute", {
                        "segments": [Path(p).name for p in segs],
                        "total_bytes": total_bytes,
                        "algos": list(policy.all_algos()),
                        "primary": policy.primary,
                    })
                mw = self.window()
                if hasattr(mw, "audit_panel"):
                    mw.audit_panel.refresh()
            else:
                self.lbl_comp_status.setText(f"[failed] {msg}")
                self.lbl_comp_status.setStyleSheet("color:#ef4444;")

        w.log.connect(on_log)
        w.progress.connect(on_progress)
        w.done.connect(on_done)
        w.error.connect(lambda m: self._append_log(f"[error] {m}"))
        w.start()
        self._compute_worker = w

    def _preflight_integrity(self):
        p = self.path_edit.text().strip()
        if not p or not Path(p).exists():
            msg_warn(self, "Missing", "Pick an existing E01 file first.")
            return
        self._append_log("Running integrity pre-flight…")
        try:
            report = quick_pre_flight(p)
        except Exception as exc:  # noqa: BLE001
            msg_error(self, "Integrity error", f"{type(exc).__name__}: {exc}")
            return
        summary = report.summary
        msg_lines = [
            f"Image set: {report.image_set}",
            f"Segments present: {report.segments_present} / max-index {report.max_index}",
            f"Missing segments: {len(report.missing)}",
            f"OK={summary['ok']}  BAD={summary['bad']}  MISSING={summary['missing']}",
            f"done-marker present: {'yes' if summary['has_done'] else 'NO'}",
            f"Overall: {'COMPLETE' if summary['complete'] else 'INCOMPLETE'}",
        ]
        if report.missing:
            msg_lines.append("")
            msg_lines.append("Missing files:")
            msg_lines.extend(f"  {m}" for m in report.missing[:20])
            if len(report.missing) > 20:
                msg_lines.append(f"  …and {len(report.missing) - 20} more")
        for line in msg_lines:
            self._append_log("  " + line)
        if self.case:
            self.case.log("integrity.preflight", {
                "set": report.image_set,
                **summary, "missing_segments": report.missing,
            })
        body = "\n".join(msg_lines)
        if summary["complete"]:
            msg_info(self, "Integrity pre-flight", body)
        else:
            msg_error(self, "Integrity pre-flight — INCOMPLETE", body)

    def _inspect(self):
        p = self.path_edit.text().strip()
        if not p or not Path(p).exists():
            msg_warn(self, "Missing", "Pick an existing E01 file.")
            return
        info = inspect(p)
        self._info = info
        self._segs = info.segment_files
        self.lbl_format.setText(info.format)
        self.lbl_segments.setText(f"{len(info.segment_files)} files")
        self.lbl_size.setText(f"{info.media_size:,} bytes")
        self.lbl_encrypted.setText("yes" if info.is_encrypted else "no")
        self.lbl_acq_md5.setText(info.md5 or "—")
        self.lbl_acq_sha1.setText(info.sha1 or "—")
        if not HAS_PYEWF:
            self._append_log("[warn] libewf-python (pyewf) not installed — "
                             "inspection shows segment list only. Install: "
                             "pip install libewf-python==20240506")
        else:
            self._append_log(f"[ok] inspected {len(info.segment_files)} segments "
                             f"({info.media_size:,} bytes)")
        # Enable the policy-hash Compute Now button now that we have a
        # valid segment list.
        self.btn_compute.setEnabled(bool(self._segs))
        self.lbl_comp_status.setText(
            f"Ready to compute. Click <b>Compute Now</b> to hash {len(self._segs)} "
            f"segment(s) totalling {info.media_size:,} bytes."
        )
        self.lbl_comp_status.setTextFormat(Qt.RichText)
        self.lbl_comp_status.setStyleSheet("color:#9ca0ad;")
        # Wipe any previous compute results — they were for a different image.
        self._clear_comp_results()

    def _run(self):
        if not self.case:
            return
        if not self._info or not self._segs:
            msg_warn(self, "Inspect first",
                     "Inspect an image before ingesting.")
            return
        if self._info.is_encrypted:
            ret = msg_question(
                self, "Encrypted image",
                "This looks like Ex01 (likely encrypted). libewf cannot "
                "decrypt Ex01. Proceed and tag as 'encrypted, no usable text'?",
            )
            if ret != QMessageBox.Yes:
                return
        if not HAS_PYEWF or not HAS_PYTSK3:
            ret = msg_question(
                self, "Missing forensic libs",
                f"libewf-python installed: {HAS_PYEWF}\n"
                f"pytsk3 installed: {HAS_PYTSK3}\n\n"
                "Without these the ingest will only register the evidence row "
                "and skip filesystem walking. Continue?",
            )
            if ret != QMessageBox.Yes:
                return

        case = self.case
        segs = list(self._segs)
        info = self._info
        max_files = self.spin_max.value() or None
        do_hash = self.chk_hash.isChecked()
        do_index = self.chk_index.isChecked() and HAS_TANTIVY
        do_content = self.chk_content.isChecked() and HAS_TANTIVY
        max_content_bytes = self.spin_content_mb.value() * 1024 * 1024
        # Content mode buffers up to ~1 MB of text per doc in the Tantivy
        # writer, so commit more often and give the writer a bigger heap.
        commit_every = 2000 if do_content else 5000
        heap_mb = 256 if do_content else 128

        first = segs[0] if segs else self.path_edit.text().strip()

        def task(w: Worker) -> tuple[bool, str]:
            w.log.emit(f"Registering evidence: {first}")
            if do_content:
                w.log.emit(f"Content extraction ON (max {max_content_bytes // (1024*1024)} MB/file)")
            ev_id = case.add_evidence(
                path=first, fmt=info.format, size=info.media_size,
                md5=info.md5, sha256=None,
                notes=f"segments={len(segs)}",
            )
            evidence_uuid = next(
                (r["evidence_uuid"] for r in case.list_evidence() if r["id"] == ev_id),
                "",
            )

            if not HAS_PYEWF or not HAS_PYTSK3:
                case.log("ingest.skipped", {"reason": "missing-libs",
                                            "pyewf": HAS_PYEWF,
                                            "pytsk3": HAS_PYTSK3})
                return True, "registered evidence; FS walk skipped (missing libs)"

            indexer: Indexer | None = None
            writer = None
            if do_index or do_content:
                try:
                    indexer = Indexer(case.index_dir / f"ev_{ev_id}")
                    writer = indexer.writer(heap_mb=heap_mb)
                except Exception as exc:  # noqa: BLE001
                    w.log.emit(f"[warn] indexer init failed: {exc}")
                    indexer = None
                    writer = None

            n_files = 0
            n_since_commit = 0
            n_extracted = 0           # files with searchable text extracted
            extract_stats: dict[str, int] = {}
            with EwfHandle(segs) as h:
                files_iter = walk_image(
                    h, max_files=max_files,
                    read_content=do_content,
                    max_content_bytes=max_content_bytes,
                )
                buf: list[dict] = []   # SQLite metadata batch (no file text)
                t0 = time.time()
                for rec in files_iter:
                    if w.cancelled:
                        break

                    # --- content extraction (text never buffered) -------
                    body_text = rec.name
                    if do_content and rec.content:
                        result = extract_text(rec.name, rec.content)
                        rec.content = None   # free the raw bytes immediately
                        if result.ok():
                            body_text = rec.name + "\n" + result.text
                            n_extracted += 1
                            extract_stats[result.extractor] = \
                                extract_stats.get(result.extractor, 0) + 1

                    row = {
                        "inode": rec.inode, "path": rec.path, "name": rec.name,
                        "size_bytes": rec.size_bytes,
                        "mtime": rec.mtime, "atime": rec.atime,
                        "ctime": rec.ctime, "crtime": rec.crtime,
                        "is_allocated": rec.is_allocated,
                        "ads_name": rec.ads_name,
                        "md5": None, "sha256": None, "tlsh": None,
                    }
                    buf.append(row)

                    # --- index this doc right away ----------------------
                    if writer is not None:
                        indexer.add_doc(
                            writer,
                            case_doc_id=hash((ev_id, rec.path)) & 0x7FFFFFFFFFFFFFFF,
                            path=rec.path, name=rec.name,
                            body=body_text,
                            encoding="utf-8",
                            size_bytes=rec.size_bytes or 0,
                            sha256="", tlsh="",
                            evidence_uuid=evidence_uuid,
                        )
                    n_files += 1
                    n_since_commit += 1

                    # --- flush the SQLite metadata batch ----------------
                    if len(buf) >= 250:
                        case.add_files(ev_id, buf)
                        buf.clear()

                    # --- incremental Tantivy commit ---------------------
                    if writer is not None and n_since_commit >= commit_every:
                        w.log.emit(f"  …intermediate commit at {n_files:,} files")
                        writer.commit()
                        n_since_commit = 0

                    # --- progress / log every 250 files -----------------
                    if n_files % 250 == 0:
                        w.progress.emit(n_files, max_files or 0, "")
                        rate = n_files / max(time.time() - t0, 0.01)
                        extra = f", {n_extracted} with text" if do_content else ""
                        w.log.emit(f"  …{n_files} files enumerated "
                                   f"({rate:.0f}/s{extra})")

                # final SQLite flush
                if buf:
                    case.add_files(ev_id, buf)

            if writer is not None:
                w.log.emit("Committing index…")
                writer.commit()

            if do_content and extract_stats:
                breakdown = ", ".join(f"{k}={v}" for k, v in
                                      sorted(extract_stats.items(),
                                             key=lambda kv: -kv[1]))
                w.log.emit(f"  text extracted by type: {breakdown}")

            case.log("ingest.complete", {
                "evidence_id": ev_id, "files": n_files,
                "content_extracted": n_extracted,
                "extract_stats": extract_stats,
                "cancelled": w.cancelled,
            })
            summary = f"ingested {n_files} files"
            if do_content:
                summary += f", extracted searchable text from {n_extracted}"
            if w.cancelled:
                summary += " (cancelled)"
            return True, summary

        self._start_worker(task, total_hint=max_files or 0)

    def _start_worker(self, fn, total_hint: int):
        self.progress.setRange(0, total_hint if total_hint > 0 else 0)
        self.progress.setValue(0)
        self.btn_run.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        w = Worker(fn, self)
        w.progress.connect(self._on_progress)
        w.log.connect(self._append_log)
        w.done.connect(self._on_done)
        w.error.connect(lambda m: self._append_log(f"[error] {m}"))
        self._worker = w
        w.start()

    def _on_progress(self, cur: int, total: int, msg: str):
        if total and self.progress.maximum() != total:
            self.progress.setRange(0, total)
        self.progress.setValue(cur)
        if msg:
            self._append_log(msg)

    def _on_done(self, ok: bool, msg: str):
        self.btn_run.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self._append_log(("[ok] " if ok else "[fail] ") + msg)
        mw = self.window()
        if hasattr(mw, "case_panel"):
            mw.case_panel.refresh()
        if hasattr(mw, "audit_panel"):
            mw.audit_panel.refresh()

    def _cancel(self):
        if self._worker:
            self._worker.request_cancel()
            self._append_log("[cancel] cancellation requested")

    def _append_log(self, line: str):
        ts = time.strftime("%H:%M:%S")
        self.log_box.appendPlainText(f"{ts}  {line}")
