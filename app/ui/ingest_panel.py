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

from app.core.ewf_reader import (
    inspect, glob_segments, EwfHandle, RawHandle, open_handle,
    parallel_hash, raw_media_hash, HAS_PYEWF,
)
from app.core.filesystem import walk_image, scan_volumes, HAS_PYTSK3
from app.core.hashing import hash_stream
from app.core.hash_policy import HashPolicy
from app.core.indexer import HAS_TANTIVY, Indexer
from app.core.text_extract import extract_text, MAX_TEXT_CHARS
from app.core.worker import Worker
from app.core import encryption as enc_mod
from app.core.raw_scan import raw_string_sweep
from app.core import patterns as pat_mod
from app.core.carver import carve_stream
from app.core.hashing import hash_bytes
from app.core import artifacts as art_mod
try:
    from app.core.yara_scan import YaraScanner, HAS_YARA_X
except Exception:  # noqa: BLE001
    YaraScanner = None
    HAS_YARA_X = False
from app.ui.centered_msg import msg_error, msg_info, msg_question, msg_warn, show_centered
from app.ui.encryption_dialog import EncryptionKeyDialog
from app.ui.integrity_panel import quick_pre_flight


class IngestPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        self._worker: Worker | None = None
        # Credentials collected by Scan Volumes for any encrypted volume.
        self._credentials = None
        self._scanned_volumes: list = []
        # Examiner-supplied YARA rule files (compiled alongside built-ins).
        self._yara_rule_files: list = []

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
        btn_scan = QPushButton("Scan Volumes")
        btn_scan.setObjectName("secondary")
        btn_scan.clicked.connect(self._scan_volumes)
        btn_scan.setToolTip(
            "Enumerate the partitions inside the image and probe each for "
            "BitLocker / FileVault / LUKS encryption and Volume Shadow "
            "Copies. If an encrypted volume is found you'll be prompted "
            "for the key."
        )
        pl.addWidget(self.path_edit, 1)
        pl.addWidget(btn_browse)
        pl.addWidget(btn_inspect)
        pl.addWidget(btn_integrity)
        pl.addWidget(btn_scan)
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

        # Specialized artifacts row
        self.chk_artifacts = QCheckBox(
            "Parse specialized artifacts — Outlook PST/OST, Windows "
            "Registry hives, ESE databases, SQLite DBs, Defender quarantine"
        )
        self.chk_artifacts.setChecked(True)
        self.chk_artifacts.setToolTip(
            "Look INSIDE container files: index every Outlook message, "
            "registry key/value, ESE/SQLite row. Decrypts Microsoft "
            "Defender quarantine files. Encrypted chat DBs, memory images "
            "and packet captures are detected and flagged in Findings."
        )
        ol.addWidget(self.chk_artifacts)

        # VSS (Volume Shadow Copy) row
        vss_row = QHBoxLayout()
        self.chk_vss = QCheckBox("Include Volume Shadow Copies (VSS snapshots)")
        self.chk_vss.setToolTip(
            "Also walk every Volume Shadow Copy on each volume. Shadow "
            "copies are point-in-time snapshots that often still contain "
            "files the user later deleted — a major evidence source."
        )
        self.chk_vss.toggled.connect(self._on_vss_toggled)
        self.chk_vss_dedup = QCheckBox(
            "Deduplicate files identical across snapshots"
        )
        self.chk_vss_dedup.setChecked(True)
        self.chk_vss_dedup.setEnabled(False)
        self.chk_vss_dedup.setToolTip(
            "Most files are byte-identical across snapshots. With dedup on, "
            "a file already seen (same path + size + mtime) in another "
            "snapshot is skipped, keeping the index 10-30x smaller."
        )
        vss_row.addWidget(self.chk_vss)
        vss_row.addSpacing(16)
        vss_row.addWidget(self.chk_vss_dedup)
        vss_row.addStretch(1)
        ol.addLayout(vss_row)

        # Raw-scan options — operate on raw image bytes, after the FS walk
        raw_box = QGroupBox("Raw scan — unallocated space, carving & IoCs "
                            "(slow; reads the whole image)")
        rl = QVBoxLayout(raw_box)
        self.chk_raw_strings = QCheckBox(
            "Raw strings sweep — index text from unallocated space & slack "
            "in all encodings (ASCII / UTF-8 / UTF-16 / CJK)"
        )
        self.chk_raw_strings.setToolTip(
            "Reads the entire image in 16 MiB pages and extracts printable "
            "strings under every encoding. Surfaces deleted documents, chat "
            "fragments and registry remnants the filesystem walk never sees."
        )
        self.chk_raw_patterns = QCheckBox(
            "IoC pattern extraction — emails, URLs, IPs, credit cards, "
            "crypto addresses, phone numbers"
        )
        self.chk_raw_patterns.setToolTip(
            "Regex-scan raw bytes for high-value indicators. Credit-card "
            "numbers are Luhn-validated to cut false positives."
        )
        self.chk_carve = QCheckBox(
            "File carving — recover deleted / embedded files by signature "
            "(JPEG, PNG, PDF, ZIP, Office, …)"
        )
        self.chk_carve.setToolTip(
            "Scans for file magic signatures and carves out files that the "
            "filesystem no longer references — deleted files, embedded "
            "attachments, data in unallocated space."
        )
        self.chk_yara = QCheckBox(
            "YARA-X scan — flag files matching the IoC rule pack"
        )
        self.chk_yara.setToolTip(
            "Runs the built-in YARA-X rules (private keys, AWS keys, "
            "executables, wallet artefacts, saved browser passwords) over "
            "carved files. Load your own .yar rules with the button on "
            "the right to scan against them too."
        )
        for cb in (self.chk_raw_strings, self.chk_raw_patterns,
                   self.chk_carve):
            rl.addWidget(cb)
        # YARA row — checkbox + custom-rule loader
        yara_row = QHBoxLayout()
        yara_row.addWidget(self.chk_yara)
        yara_row.addSpacing(16)
        btn_yara_rules = QPushButton("Load custom .yar rules…")
        btn_yara_rules.setObjectName("secondary")
        btn_yara_rules.clicked.connect(self._load_yara_rules)
        btn_yara_rules.setToolTip(
            "Add your own YARA rule files. They are compiled alongside the "
            "built-in pack for this case."
        )
        yara_row.addWidget(btn_yara_rules)
        self.lbl_yara_rules = QLabel("built-in pack only")
        self.lbl_yara_rules.setObjectName("muted")
        yara_row.addWidget(self.lbl_yara_rules)
        yara_row.addStretch(1)
        rl.addLayout(yara_row)
        ol.addWidget(raw_box)

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

    def _on_vss_toggled(self, checked: bool):
        self.chk_vss_dedup.setEnabled(checked)

    def _load_yara_rules(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select YARA rule files", str(Path.home()),
            "YARA rules (*.yar *.yara);;All files (*.*)",
        )
        if not paths:
            return
        # validate they compile before accepting
        if YaraScanner is not None:
            try:
                YaraScanner.from_files(paths, include_builtin=True)
            except Exception as exc:  # noqa: BLE001
                msg_error(self, "Rule compile error",
                          f"The selected rules did not compile:\n\n{exc}")
                return
        self._yara_rule_files = list(paths)
        self.lbl_yara_rules.setText(
            f"built-in pack + {len(paths)} custom file(s)")
        self.chk_yara.setChecked(True)
        self._append_log(f"loaded {len(paths)} custom YARA rule file(s)")

    def _scan_volumes(self):
        """Enumerate volumes, probe encryption + VSS, and collect keys
        for any encrypted volume found. Runs synchronously — it only
        reads partition + signature headers, so it is fast.
        """
        if not self._segs:
            msg_warn(self, "Inspect first",
                     "Pick an E01 file and click Inspect before scanning volumes.")
            return
        self._append_log("Scanning volumes…")
        try:
            with open_handle(self._info) as h:
                vols = scan_volumes(h)
        except Exception as exc:  # noqa: BLE001
            msg_error(self, "Scan failed", f"{type(exc).__name__}: {exc}")
            return
        self._scanned_volumes = vols
        self._credentials = None
        enc_found = []
        for v in vols:
            enc = enc_mod.human_name(v.encryption) if v.encryption else "none"
            vss = "yes" if v.has_vss else "no"
            self._append_log(
                f"  vol{v.index}: {v.length:,} bytes  encryption={enc}  "
                f"VSS={vss}  {v.description}"
            )
            if v.encryption:
                enc_found.append(v)

        if not enc_found:
            self._append_log("  no encrypted volumes — ingest can proceed directly")
            msg_info(self, "Volume scan complete",
                     f"{len(vols)} volume(s) found, none encrypted.\n"
                     "VSS snapshots, if any, are shown in the log.")
            return

        # collect credentials for the encrypted volume(s)
        for v in enc_found:
            dlg = EncryptionKeyDialog(self, kind=v.encryption,
                                      volume_label=f"vol{v.index}")
            show_centered(dlg, self)
            if dlg.result_skip():
                self._append_log(f"  vol{v.index}: examiner chose to skip")
                continue
            creds = dlg.credentials()
            if not creds.is_empty():
                self._credentials = creds
                self._append_log(
                    f"  vol{v.index}: key material captured for "
                    f"{enc_mod.human_name(v.encryption)}"
                )
                # Note: a single credential set is applied to every
                # encrypted volume during the ingest walk.
                break
        if self._credentials is None:
            msg_warn(self, "No keys captured",
                     "No key material was entered. Encrypted volumes will be "
                     "tagged 'encrypted, no usable text' during ingest.")

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
        n_workers = 4
        media_size_holder = {"size": 0}
        is_raw = (self._info is not None and self._info.format == "RAW")

        def task(w: Worker) -> tuple[bool, str]:
            # Hash the decompressed MEDIA CONTENT (the imaged disk). For
            # an E01, multiple libewf handles decompress in parallel; for
            # a raw/dd image there is nothing to decompress, so a single
            # streaming pass is used. Either way the result is directly
            # comparable to the acquisition hash.
            t0 = time.time()
            try:
                if is_raw:
                    w.log.emit("Media hash — raw image, single streaming pass")
                    result = raw_media_hash(
                        segs[0], list(policy.all_algos()),
                        progress_cb=lambda d, t: w.progress.emit(d, t, ""),
                        cancel_cb=lambda: w.cancelled,
                    )
                else:
                    w.log.emit(f"Parallel media hash — {n_workers} libewf handles")
                    result = parallel_hash(
                        segs, list(policy.all_algos()),
                        n_workers=n_workers, block_size=16 * 1024 * 1024,
                        progress_cb=lambda d, t: w.progress.emit(d, t, ""),
                        cancel_cb=lambda: w.cancelled,
                    )
            except Exception as exc:  # noqa: BLE001
                if w.cancelled:
                    return False, "cancelled by user"
                raise
            elapsed = time.time() - t0
            size = int(result.pop("size_bytes", 0))
            media_size_holder["size"] = size
            mb_s = (size / 1024 / 1024) / max(elapsed, 0.001)
            for algo, hex_digest in result.items():
                # Worker exposes a single 'log' signal, so encode the
                # per-algorithm result and decode it in on_log().
                w.log.emit(f"@HASH@{algo}={hex_digest}")
            return True, (
                f"computed {len(result)} media-content hash(es) over "
                f"{size:,} bytes in {elapsed:.1f}s ({mb_s:.0f} MB/s)"
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
                        "media_bytes": media_size_holder["size"],
                        "algos": list(policy.all_algos()),
                        "primary": policy.primary,
                        "method": f"parallel_hash x{n_workers}",
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
            msg_warn(self, "Missing",
                     "Pick an existing image file (.E01 / .Ex01 / .L01 or "
                     "a raw .dd / .img / .raw / .001).")
            return
        info = inspect(p)
        self._info = info
        self._segs = info.segment_files
        self.lbl_format.setText(info.format)
        unit = "files" if info.format not in ("RAW", "AFF4") else "file"
        self.lbl_segments.setText(f"{len(info.segment_files)} {unit}")
        self.lbl_size.setText(f"{info.media_size:,} bytes")
        self.lbl_encrypted.setText("yes" if info.is_encrypted else "no")
        self.lbl_acq_md5.setText(info.md5 or "—")
        self.lbl_acq_sha1.setText(info.sha1 or "—")

        if info.format == "AFF4":
            self._append_log("[warn] AFF4 image detected — not supported by "
                             "this build. Convert to E01 or raw/dd first.")
            msg_warn(self, "AFF4 not supported",
                     "This is an AFF4 image. AFF4 is not supported because "
                     "the only Python AFF4 library (pyaff4) has an "
                     "abandoned dependency chain that will not run on "
                     "current Python.\n\nConvert the image to E01 or raw "
                     "(dd) and re-open it.")
            self.btn_compute.setEnabled(False)
            return
        if info.format == "RAW":
            self._append_log(f"[ok] raw/dd image — {info.media_size:,} bytes "
                             "(flat disk dump, no EWF metadata)")
        elif not HAS_PYEWF:
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

    # ---- raw-scan pass (Phase 2 strings + Phase 3 carving/IoC/YARA) -----

    def _raw_scan_pass(self, w, case, ev_id, evidence_uuid, segs,
                       indexer, writer, do_raw_strings, do_raw_patterns,
                       do_carve, do_yara) -> dict:
        """Run the raw byte-level scans after the filesystem walk.
        Returns a summary dict. Runs inside the ingest Worker thread.
        """
        summary: dict = {}

        yara_scanner = None
        if do_yara and YaraScanner is not None:
            try:
                if self._yara_rule_files:
                    yara_scanner = YaraScanner.from_files(
                        self._yara_rule_files, include_builtin=True)
                    w.log.emit(f"  YARA-X: built-in pack + "
                               f"{len(self._yara_rule_files)} custom file(s)")
                else:
                    yara_scanner = YaraScanner()
                    w.log.emit("  YARA-X built-in rule pack loaded")
            except Exception as exc:  # noqa: BLE001
                w.log.emit(f"  [warn] YARA init failed: {exc}")

        # ---- raw strings + IoC patterns (paged sweep) -----------------
        # Distinct IoC indicators, deduplicated across the whole image:
        #   (kind, value) -> [occurrence_count, first_offset]
        # Capped so a pathological image cannot exhaust memory.
        IOC_DISTINCT_CAP = 500_000
        ioc_distinct: dict = {}

        if do_raw_strings or do_raw_patterns:
            counters = {"raw_docs": 0, "pat": 0}
            pat_totals: dict = {}

            def on_page(page, text, n_strings):
                if w.cancelled:
                    return
                body_parts = []
                if do_raw_strings and text:
                    body_parts.append(text)
                if do_raw_patterns and text:
                    # Patterns are scanned over the *extracted text*, not
                    # the raw bytes — ~10x less data and no regex
                    # backtracking on binary noise.
                    phits = pat_mod.scan_text(text)
                    if phits:
                        counters["pat"] += len(phits)
                        for ph in phits:
                            pat_totals[ph.kind] = pat_totals.get(ph.kind, 0) + 1
                            key = (ph.kind, ph.value)
                            slot = ioc_distinct.get(key)
                            if slot is not None:
                                slot[0] += 1
                            elif len(ioc_distinct) < IOC_DISTINCT_CAP:
                                ioc_distinct[key] = [1, page.offset]
                        body_parts.append("\n".join(
                            f"{p.kind}: {p.value}" for p in phits))
                if body_parts and writer is not None and indexer is not None:
                    indexer.add_doc(
                        writer,
                        case_doc_id=hash((ev_id, "raw", page.offset))
                        & 0x7FFFFFFFFFFFFFFF,
                        path=f"/(raw)/{page.offset:#x}",
                        name=f"raw@{page.offset:#x}",
                        body="\n".join(body_parts),
                        encoding="multi", size_bytes=page.length,
                        sha256="", tlsh="", evidence_uuid=evidence_uuid,
                    )
                    counters["raw_docs"] += 1

            try:
                with open_handle(self._info) as rh:
                    stats = raw_string_sweep(
                        rh, on_page=on_page,
                        progress_cb=lambda d, t: w.progress.emit(d, t, ""),
                        cancel_cb=lambda: w.cancelled,
                    )
                w.log.emit(
                    f"  raw sweep: {stats.pages} pages, "
                    f"{stats.bytes_scanned:,} bytes, {stats.strings:,} "
                    f"strings -> {counters['raw_docs']} indexed docs"
                )
                summary["raw_docs"] = counters["raw_docs"]
                if do_raw_patterns:
                    top = dict(sorted(pat_totals.items(),
                                      key=lambda kv: -kv[1]))
                    w.log.emit(f"  IoC patterns: {counters['pat']:,} hits  {top}")
                    summary["patterns"] = counters["pat"]
                    case.log("ingest.raw_patterns",
                             {"total": counters["pat"], "by_kind": pat_totals})
                    # persist distinct indicators to the findings table
                    if ioc_distinct:
                        finding_rows = [
                            {"kind": "ioc", "subtype": k[0], "value": k[1],
                             "count": v[0], "first_offset": v[1]}
                            for k, v in ioc_distinct.items()
                        ]
                        case.add_findings(ev_id, finding_rows)
                        w.log.emit(f"  stored {len(finding_rows):,} distinct "
                                   f"IoC indicators to findings")
                        summary["distinct_iocs"] = len(finding_rows)
            except Exception as exc:  # noqa: BLE001
                w.log.emit(f"  [error] raw sweep failed: {exc}")

        # ---- file carving (+ YARA on carved files) --------------------
        carve_active = do_carve or do_yara
        if carve_active and not w.cancelled:
            carved_rows: list = []
            counts = {"carved": 0, "yara": 0}
            yara_by_rule: dict = {}
            # distinct YARA matches: (rule, source) -> count
            yara_distinct: dict = {}

            def on_carved(cf):
                if w.cancelled:
                    return
                hashes = hash_bytes(cf.data)
                yara_tags = []
                if yara_scanner is not None:
                    matches = yara_scanner.scan_bytes(
                        cf.data, source=f"{cf.file_type}@{cf.offset:#x}")
                    for m in matches:
                        counts["yara"] += 1
                        yara_by_rule[m.rule] = yara_by_rule.get(m.rule, 0) + 1
                        yara_tags.append(m.rule)
                        yk = (m.rule, m.source)
                        yara_distinct[yk] = yara_distinct.get(yk, 0) + 1
                row = {
                    "inode": None,
                    "path": f"/(carved)/{cf.file_type}/{cf.offset:#x}",
                    "name": f"{cf.file_type}_{cf.offset:#x}.{cf.file_type}",
                    "size_bytes": cf.size, "is_allocated": False,
                    "md5": hashes["md5"], "sha256": hashes["sha256"],
                    "tlsh": hashes["tlsh"],
                }
                carved_rows.append(row)
                counts["carved"] += 1
                if writer is not None and indexer is not None:
                    body = row["name"]
                    if yara_tags:
                        body += "\nYARA: " + " ".join(yara_tags)
                    indexer.add_doc(
                        writer,
                        case_doc_id=hash((ev_id, "carved", cf.offset))
                        & 0x7FFFFFFFFFFFFFFF,
                        path=row["path"], name=row["name"], body=body,
                        encoding="binary", size_bytes=cf.size,
                        sha256=hashes["sha256"] or "",
                        tlsh=hashes["tlsh"] or "",
                        evidence_uuid=evidence_uuid,
                    )
                if len(carved_rows) >= 100:
                    case.add_files(ev_id, list(carved_rows))
                    carved_rows.clear()

            try:
                with open_handle(self._info) as ch:
                    cstats = carve_stream(
                        ch, max_files=100000, on_file=on_carved,
                        progress_cb=lambda d, t: w.progress.emit(d, t, ""),
                        cancel_cb=lambda: w.cancelled,
                    )
                if carved_rows:
                    case.add_files(ev_id, carved_rows)
                w.log.emit(f"  carved {cstats.carved} files  "
                           f"{dict(cstats.per_type)}")
                summary["carved"] = cstats.carved
                case.log("ingest.carve", {"carved": cstats.carved,
                                          "by_type": dict(cstats.per_type)})
                if counts["yara"]:
                    w.log.emit(f"  YARA matches on carved files: {yara_by_rule}")
                    summary["yara"] = counts["yara"]
                    case.log("ingest.yara", {"matches": counts["yara"],
                                             "by_rule": yara_by_rule})
                    # persist YARA matches to the findings table
                    if yara_distinct:
                        yrows = [
                            {"kind": "yara", "subtype": rule, "value": src,
                             "count": cnt, "first_offset": None}
                            for (rule, src), cnt in yara_distinct.items()
                        ]
                        case.add_findings(ev_id, yrows)
            except Exception as exc:  # noqa: BLE001
                w.log.emit(f"  [error] carving failed: {exc}")

        return summary

    def _run(self):
        if not self.case:
            return
        if not self._info or not self._segs:
            msg_warn(self, "Inspect first",
                     "Inspect an image before ingesting.")
            return
        if self._info.format == "AFF4":
            msg_warn(self, "AFF4 not supported",
                     "AFF4 images cannot be ingested by this build. "
                     "Convert the image to E01 or raw/dd first.")
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
        do_artifacts = self.chk_artifacts.isChecked() and HAS_TANTIVY
        max_content_bytes = self.spin_content_mb.value() * 1024 * 1024
        # When hashing files (or parsing artifact containers) we need the
        # COMPLETE file content, so the read cap is raised. Files larger
        # than this are not hashed (a partial hash would be forensically
        # wrong) — they are counted and reported instead.
        HASH_FILE_CAP = 256 * 1024 * 1024
        need_content = do_content or do_hash or do_artifacts
        walk_content_cap = (max(max_content_bytes, HASH_FILE_CAP)
                            if (do_hash or do_artifacts) else max_content_bytes)
        do_vss = self.chk_vss.isChecked()
        do_vss_dedup = self.chk_vss_dedup.isChecked()
        credentials = self._credentials
        do_raw_strings = self.chk_raw_strings.isChecked() and HAS_TANTIVY
        do_raw_patterns = self.chk_raw_patterns.isChecked()
        do_carve = self.chk_carve.isChecked()
        do_yara = self.chk_yara.isChecked() and HAS_YARA_X
        # Content mode buffers up to ~1 MB of text per doc in the Tantivy
        # writer, so commit more often and give the writer a bigger heap.
        commit_every = 2000 if do_content else 5000
        heap_mb = 256 if do_content else 128

        first = segs[0] if segs else self.path_edit.text().strip()

        def task(w: Worker) -> tuple[bool, str]:
            w.log.emit(f"Registering evidence: {first}")
            if do_content:
                w.log.emit(f"Content extraction ON (max {max_content_bytes // (1024*1024)} MB/file)")
            if do_vss:
                w.log.emit(f"VSS snapshots ON (dedup={'on' if do_vss_dedup else 'off'})")
            if credentials is not None:
                w.log.emit("Encryption keys loaded — encrypted volumes will be unlocked")
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
            if do_index or do_content or do_raw_strings or do_raw_patterns:
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
            n_hashed = 0              # files hashed
            n_hash_skipped = 0        # files too large to hash fully
            n_artifacts = 0           # specialized containers parsed
            n_artifact_items = 0      # sub-docs from those containers
            artifact_stats: dict[str, int] = {}
            flagged_artifacts: list[dict] = []   # memory/pcap/encrypted DBs
            extract_stats: dict[str, int] = {}
            # SQLite DBs + their -wal/-shm side files are deferred to a
            # post-walk pass so the write-ahead log can be replayed
            # (the -wal file is a separate filesystem entry that usually
            # appears AFTER its database in the walk order).
            sqlite_stash: dict[str, bytes] = {}
            sqlite_stash_bytes = 0
            SQLITE_STASH_CAP = 400 * 1024 * 1024
            with open_handle(info) as h:
                files_iter = walk_image(
                    h, max_files=max_files,
                    read_content=need_content,
                    max_content_bytes=walk_content_cap,
                    credentials=credentials,
                    include_vss=do_vss,
                    vss_dedup=do_vss_dedup,
                    log=lambda m: w.log.emit(m),
                )
                buf: list[dict] = []   # SQLite metadata batch (no file text)
                t0 = time.time()
                for rec in files_iter:
                    if w.cancelled:
                        break

                    content = rec.content
                    rec.content = None        # detach; freed at loop end

                    # --- per-file hashing -------------------------------
                    md5 = sha256 = tlsh = None
                    if do_hash and content and rec.is_regular:
                        full = (rec.size_bytes is None
                                or len(content) >= rec.size_bytes)
                        if full:
                            hh = hash_bytes(content)
                            md5, sha256, tlsh = (hh["md5"], hh["sha256"],
                                                 hh["tlsh"])
                            n_hashed += 1
                        else:
                            # file exceeded the read cap — a partial hash
                            # would be wrong, so skip it
                            n_hash_skipped += 1

                    # --- specialized artifact parsing -------------------
                    # PST / registry / ESE / SQLite / Defender quarantine
                    # are container formats — parse them and index every
                    # message / key / row as its own searchable doc.
                    body_text = rec.name
                    artifact_kind = ""
                    if (do_artifacts and content and rec.is_regular
                            and writer is not None):
                        artifact_kind = art_mod.detect_artifact(
                            rec.name, content[:64])
                        nlow = rec.name.lower()
                        if artifact_kind == art_mod.SQLITE or \
                                nlow.endswith(("-wal", "-shm")):
                            # Defer SQLite DBs and their WAL/SHM side
                            # files to a post-walk pass for WAL replay.
                            if sqlite_stash_bytes + len(content) <= SQLITE_STASH_CAP:
                                sqlite_stash[rec.path] = content
                                sqlite_stash_bytes += len(content)
                                if artifact_kind == art_mod.SQLITE:
                                    body_text = (f"{rec.name}\n[SQLite database "
                                                 "— queued for WAL-aware parsing]")
                            elif artifact_kind == art_mod.SQLITE:
                                # stash full — parse now, without WAL
                                items, summ = art_mod.parse_artifact(
                                    artifact_kind, content, rec.path)
                                for it in items:
                                    indexer.add_doc(
                                        writer,
                                        case_doc_id=hash((ev_id, rec.path,
                                                          it.subpath))
                                        & 0x7FFFFFFFFFFFFFFF,
                                        path=f"{rec.path}#{it.subpath}",
                                        name=it.name,
                                        body=f"{it.name}\n{it.text}",
                                        encoding="artifact",
                                        size_bytes=0, sha256="", tlsh="",
                                        evidence_uuid=evidence_uuid,
                                    )
                                n_artifacts += 1
                                n_artifact_items += len(items)
                                n_since_commit += len(items)
                                artifact_stats["sqlite"] = \
                                    artifact_stats.get("sqlite", 0) + 1
                        elif artifact_kind in art_mod.PARSEABLE:
                            items, summ = art_mod.parse_artifact(
                                artifact_kind, content, rec.path)
                            for it in items:
                                indexer.add_doc(
                                    writer,
                                    case_doc_id=hash((ev_id, rec.path,
                                                      it.subpath))
                                    & 0x7FFFFFFFFFFFFFFF,
                                    path=f"{rec.path}#{it.subpath}",
                                    name=it.name,
                                    body=f"{it.name}\n{it.text}",
                                    encoding="artifact",
                                    size_bytes=0, sha256="", tlsh="",
                                    evidence_uuid=evidence_uuid,
                                )
                            n_artifacts += 1
                            n_artifact_items += len(items)
                            n_since_commit += len(items)
                            artifact_stats[artifact_kind] = \
                                artifact_stats.get(artifact_kind, 0) + 1
                            body_text = (f"{rec.name}\n[{art_mod.HUMAN[artifact_kind]}"
                                         f" — {len(items)} items extracted]")
                        elif artifact_kind in art_mod.FLAG_ONLY:
                            flagged_artifacts.append({
                                "kind": "artifact",
                                "subtype": artifact_kind,
                                "value": rec.path, "count": 1,
                            })
                            body_text = (f"{rec.name}\n[{art_mod.HUMAN[artifact_kind]}"
                                         f" — detected, flagged in Findings]")

                    # --- generic content extraction ---------------------
                    # (only when the file was not a parsed artifact)
                    if (do_content and content
                            and artifact_kind not in art_mod.PARSEABLE):
                        result = extract_text(rec.name, content)
                        if result.ok():
                            body_text = rec.name + "\n" + result.text
                            n_extracted += 1
                            extract_stats[result.extractor] = \
                                extract_stats.get(result.extractor, 0) + 1
                    content = None            # free the raw bytes now

                    row = {
                        "inode": rec.inode, "path": rec.path, "name": rec.name,
                        "size_bytes": rec.size_bytes,
                        "mtime": rec.mtime, "atime": rec.atime,
                        "ctime": rec.ctime, "crtime": rec.crtime,
                        "is_allocated": rec.is_allocated,
                        "ads_name": rec.ads_name,
                        "vss_snapshot_id": rec.vss_snapshot_id,
                        "md5": md5, "sha256": sha256, "tlsh": tlsh,
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
                            sha256=sha256 or "", tlsh=tlsh or "",
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

            # ---- post-walk SQLite pass (WAL replay) -----------------------
            # Now that the whole directory tree has been walked, every
            # database has its -wal side file available. Parse each DB,
            # replaying its WAL so the most recent (un-checkpointed)
            # chat messages / history rows are recovered.
            if do_artifacts and sqlite_stash and writer is not None and not w.cancelled:
                db_paths = [p for p in sqlite_stash
                            if not p.lower().endswith(("-wal", "-shm"))]
                n_wal = 0
                w.log.emit(f"  parsing {len(db_paths)} SQLite database(s) "
                           "with WAL replay…")
                for db_path in db_paths:
                    if w.cancelled:
                        break
                    db_bytes = sqlite_stash.get(db_path)
                    wal_bytes = sqlite_stash.get(db_path + "-wal")
                    if wal_bytes:
                        n_wal += 1
                    items, summ = art_mod.parse_artifact(
                        art_mod.SQLITE, db_bytes, db_path,
                        wal_content=wal_bytes)
                    for it in items:
                        indexer.add_doc(
                            writer,
                            case_doc_id=hash((ev_id, db_path, it.subpath))
                            & 0x7FFFFFFFFFFFFFFF,
                            path=f"{db_path}#{it.subpath}",
                            name=it.name,
                            body=f"{it.name}\n{it.text}",
                            encoding="artifact",
                            size_bytes=0, sha256="", tlsh="",
                            evidence_uuid=evidence_uuid,
                        )
                    n_artifacts += 1
                    n_artifact_items += len(items)
                    artifact_stats["sqlite"] = \
                        artifact_stats.get("sqlite", 0) + 1
                w.log.emit(f"  SQLite: {len(db_paths)} database(s), "
                           f"{n_wal} with a WAL replayed")
                sqlite_stash.clear()

            if writer is not None:
                w.log.emit("Committing index…")
                writer.commit()

            if do_content and extract_stats:
                breakdown = ", ".join(f"{k}={v}" for k, v in
                                      sorted(extract_stats.items(),
                                             key=lambda kv: -kv[1]))
                w.log.emit(f"  text extracted by type: {breakdown}")

            if do_artifacts and (n_artifacts or flagged_artifacts):
                w.log.emit(
                    f"  artifacts parsed: {n_artifacts} container(s) -> "
                    f"{n_artifact_items:,} indexed items  {artifact_stats}")
                if flagged_artifacts:
                    by_kind: dict[str, int] = {}
                    for fa in flagged_artifacts:
                        by_kind[fa["subtype"]] = by_kind.get(fa["subtype"], 0) + 1
                    w.log.emit(f"  artifacts flagged (need separate tools): "
                               f"{by_kind}")
                    # record memory/pcap/encrypted-DB hits in Findings
                    try:
                        case.add_findings(ev_id, flagged_artifacts)
                    except Exception as exc:  # noqa: BLE001
                        w.log.emit(f"  [warn] could not store flagged "
                                   f"artifacts: {exc}")

            # ---- raw-scan pass (Phase 2 + 3) ------------------------------
            raw_summary = {}
            do_any_raw = (do_raw_strings or do_raw_patterns or do_carve
                          or do_yara)
            if do_any_raw and not w.cancelled:
                w.log.emit("=== raw scan pass (unallocated / carving / IoCs) ===")
                raw_summary = self._raw_scan_pass(
                    w, case, ev_id, evidence_uuid, segs, indexer, writer,
                    do_raw_strings, do_raw_patterns, do_carve, do_yara,
                )
                if writer is not None:
                    writer.commit()

            if do_hash:
                w.log.emit(f"  per-file hashing: {n_hashed} hashed, "
                           f"{n_hash_skipped} skipped (larger than "
                           f"{HASH_FILE_CAP // (1024*1024)} MB)")

            case.log("ingest.complete", {
                "evidence_id": ev_id, "files": n_files,
                "content_extracted": n_extracted,
                "files_hashed": n_hashed,
                "hash_skipped_oversize": n_hash_skipped,
                "artifacts_parsed": n_artifacts,
                "artifact_items": n_artifact_items,
                "artifact_stats": artifact_stats,
                "artifacts_flagged": len(flagged_artifacts),
                "extract_stats": extract_stats,
                "raw_scan": raw_summary,
                "cancelled": w.cancelled,
            })
            summary = f"ingested {n_files} files"
            if do_hash:
                summary += f", hashed {n_hashed}"
            if do_content:
                summary += f", extracted searchable text from {n_extracted}"
            if do_artifacts and n_artifacts:
                summary += (f", parsed {n_artifacts} artifact container(s) "
                            f"-> {n_artifact_items:,} items")
            if flagged_artifacts:
                summary += f", flagged {len(flagged_artifacts)} artifact(s)"
            if raw_summary:
                if raw_summary.get("raw_docs"):
                    summary += f", {raw_summary['raw_docs']} raw-string docs"
                if raw_summary.get("patterns"):
                    summary += f", {raw_summary['patterns']} IoC hits"
                if raw_summary.get("carved"):
                    summary += f", {raw_summary['carved']} carved files"
                if raw_summary.get("yara"):
                    summary += f", {raw_summary['yara']} YARA matches"
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
