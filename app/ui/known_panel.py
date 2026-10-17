"""Known Files tab — manage the hash sets used to label stock content.

Hash sets are reference data, not evidence: they live in one store
shared by every case, so NSRL is imported once and serves all later
work. See app/core/known_files.py for why a match only ever labels a
file and never removes it.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog, QGroupBox, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
    QPlainTextEdit, QPushButton, QScrollArea, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from app.core.known_files import KnownSetStore, default_store_path
from app.core.worker import Worker
from app.ui.centered_msg import msg_error, msg_info, msg_question


class KnownFilesPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        # A corrupt or unreachable store must not stop the application
        # from starting: this panel is built during MainWindow setup, so
        # an exception here left the examiner unable to open any case.
        self.store = None
        self._store_error = ""
        try:
            self.store = KnownSetStore(default_store_path())
            self.store.sweep_orphans()
        except Exception as exc:  # noqa: BLE001
            self._store_error = (
                f"{type(exc).__name__}: {exc}\n\nStore path: "
                f"{default_store_path()}\n\nIf the file is corrupt, "
                f"rename it and restart to begin a fresh store.")
        self._worker = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        outer.addWidget(scroll)
        inner = QWidget()
        scroll.setWidget(inner)
        root = QVBoxLayout(inner)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)

        title = QLabel("Known Files")
        title.setObjectName("h1")
        root.addWidget(title)

        sub = QLabel(
            "Hash sets of files already known to the world — operating "
            "system and application files shipped by vendors. Matching the "
            "evidence against them separates <i>came with the machine</i> "
            "from <i>was put there</i>.<br><br>"
            "<b>A match only labels a file.</b> Nothing is ever removed from "
            "the index or the case database: these sets contain plenty of "
            "signed binaries that attackers abuse, so <i>known</i> does not "
            "mean <i>harmless</i>. Hiding known files is a view option in "
            "Search, off by default, and it always says how many rows it is "
            "hiding."
        )
        sub.setObjectName("muted")
        sub.setWordWrap(True)
        sub.setTextFormat(Qt.RichText)
        root.addWidget(sub)

        self.lbl_store = QLabel("")
        self.lbl_store.setObjectName("muted")
        self.lbl_store.setTextInteractionFlags(Qt.TextSelectableByMouse)
        root.addWidget(self.lbl_store)

        # ---- imported sets --------------------------------------------
        self.lbl_summary = QLabel("")
        self.lbl_summary.setObjectName("h2")
        root.addWidget(self.lbl_summary)

        self.tbl = QTableWidget(0, 5)
        self.tbl.setHorizontalHeaderLabels(
            ["Set", "Kind", "Hashes", "Coverage", "Imported from"])
        hdr = self.tbl.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(True)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl.setMinimumHeight(180)
        root.addWidget(self.tbl)

        bar = QHBoxLayout()
        self.btn_nsrl = QPushButton("Import NSRL RDSv3 (SQLite)…")
        self.btn_nsrl.clicked.connect(self._import_nsrl)
        self.btn_nsrl.setToolTip(
            "Import from an NSRL RDSv3 SQLite publication.\n\n"
            "NIST retired the old RDS 2.xx text format; RDSv3 SQLite is "
            "what is published now. Prefer the MINIMAL publication — it "
            "carries the same FILE view (sha256, sha1, md5, file name, "
            "size) at a fraction of the size of the full set, which runs "
            "to hundreds of GB unzipped.\n\n"
            "The publication is opened read-only and is never modified. "
            "Only the hash columns are copied."
        )
        bar.addWidget(self.btn_nsrl)

        self.btn_list = QPushButton("Import hash list (.txt)…")
        self.btn_list.setObjectName("secondary")
        self.btn_list.clicked.connect(self._import_list)
        self.btn_list.setToolTip(
            "One hash per line — MD5, SHA-1 or SHA-256, mixed freely. "
            "'#' comments and trailing filenames (as md5sum writes) are "
            "tolerated.\n\n"
            "This is the universal path: it needs no network and every "
            "hash-set vendor can produce it."
        )
        bar.addWidget(self.btn_list)

        self.btn_csv = QPushButton("Import CSV…")
        self.btn_csv.setObjectName("secondary")
        self.btn_csv.clicked.connect(self._import_csv)
        self.btn_csv.setToolTip(
            "A delimited file whose header names at least one of md5, "
            "sha1 or sha256."
        )
        bar.addWidget(self.btn_csv)

        self.btn_del = QPushButton("Remove selected set")
        self.btn_del.setObjectName("secondary")
        self.btn_del.setEnabled(False)
        self.btn_del.clicked.connect(self._delete_selected)
        bar.addWidget(self.btn_del)
        self.btn_cancel = QPushButton("Cancel import")
        self.btn_cancel.setObjectName("secondary")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel_import)
        self.btn_cancel.setToolTip(
            "Stop the running import. A cancelled set is kept but marked "
            "PARTIAL, so incomplete coverage is never mistaken for full."
        )
        bar.addWidget(self.btn_cancel)
        bar.addStretch(1)
        root.addLayout(bar)
        self.tbl.itemSelectionChanged.connect(
            lambda: self.btn_del.setEnabled(
                bool(self.tbl.selectionModel()
                     and self.tbl.selectionModel().selectedRows())))

        # ---- single-hash lookup ---------------------------------------
        probe = QGroupBox("Check one hash")
        pl = QVBoxLayout(probe)
        prow = QHBoxLayout()
        self.btn_probe = QPushButton("Look up a hash…")
        self.btn_probe.setObjectName("secondary")
        self.btn_probe.clicked.connect(self._probe)
        prow.addWidget(self.btn_probe)
        self.lbl_probe = QLabel("")
        self.lbl_probe.setObjectName("muted")
        prow.addWidget(self.lbl_probe)
        prow.addStretch(1)
        pl.addLayout(prow)
        root.addWidget(probe)

        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(140)
        self.log_box.setPlaceholderText("Import progress appears here.")
        root.addWidget(self.log_box)

        self.refresh()

    # ---- state --------------------------------------------------------

    def set_case(self, case):
        # Hash sets are not case data; the tab works with no case open.
        self.refresh()

    def refresh(self):
        if self.store is None:
            self.lbl_store.setText(f"Store: {default_store_path()}")
            self.lbl_summary.setText("Hash store unavailable")
            self.log_box.setPlainText(
                "The known-file hash store could not be opened, so no hash "
                "sets can be imported or matched. Everything else in the "
                "tool is unaffected.\n\n" + self._store_error)
            for b_ in (self.btn_nsrl, self.btn_list, self.btn_csv,
                       self.btn_del, self.btn_probe):
                b_.setEnabled(False)
            self.tbl.setRowCount(0)
            return
        self.lbl_store.setText(f"Store: {self.store.db_path}")
        sets = self.store.list_sets()
        self.tbl.setRowCount(len(sets))
        for i, s in enumerate(sets):
            self.tbl.setItem(i, 0, QTableWidgetItem(s.name))
            self.tbl.setItem(i, 1, QTableWidgetItem(s.kind))
            self.tbl.setItem(i, 2, QTableWidgetItem(f"{s.n_hashes:,}"))
            self.tbl.setItem(i, 3, QTableWidgetItem(
                ("PARTIAL — " + s.notes) if not s.complete
                else (s.notes or "complete")))
            self.tbl.setItem(i, 4, QTableWidgetItem(s.source_path))
        self.tbl.resizeColumnsToContents()
        total = self.store.total_hashes()
        if sets:
            self.lbl_summary.setText(
                f"{len(sets)} hash set(s), {total:,} hashes")
        else:
            self.lbl_summary.setText(
                "No hash sets imported — every file will be treated as "
                "unknown during ingest.")

    def _log(self, line: str):
        self.log_box.appendPlainText(line)

    # ---- imports ------------------------------------------------------

    def _ask_name(self, default: str) -> str:
        name, ok = QInputDialog.getText(
            self, "Name this hash set",
            "A short name recorded against every file that matches it:",
            text=default)
        return name.strip() if ok else ""

    def _run_import(self, fn, label: str):
        """Imports can take a long time, so they run off the GUI thread."""
        if self._worker is not None and self._worker.isRunning():
            msg_info(self, "Import running",
                     "An import is already in progress.")
            return
        for b in (self.btn_nsrl, self.btn_list, self.btn_csv, self.btn_del):
            b.setEnabled(False)
        self.btn_cancel.setEnabled(True)

        def task(w):
            n = fn(lambda c: w.progress.emit(c, 0, ""),
                   lambda: w.cancelled)
            if w.cancelled:
                return True, (f"{label}: CANCELLED after {n:,} hashes — the "
                              f"set is marked PARTIAL")
            return True, f"{label}: {n:,} hashes imported"

        w = Worker(task, self)
        w.progress.connect(
            lambda cur, tot, msg: self._log(f"  {cur:,} hashes…"))
        w.log.connect(self._log)
        w.done.connect(self._on_import_done)
        w.error.connect(lambda m: self._log(f"[error] {m}"))
        self._worker = w
        self._log(f"{label} starting…")
        w.start()

    def _cancel_import(self):
        if self._worker is not None and self._worker.isRunning():
            self._worker.request_cancel()
            self._log("[cancel] cancellation requested — finishing the "
                      "current batch")

    def _on_import_done(self, ok: bool, msg: str):
        for b in (self.btn_nsrl, self.btn_list, self.btn_csv):
            b.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self._log(("[ok] " if ok else "[fail] ") + msg)
        self.refresh()

    def _import_nsrl(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select an NSRL RDSv3 SQLite publication", "",
            "SQLite database (*.db *.sqlite *.sqlite3);;All files (*)")
        if not path:
            return
        info = self.store.inspect_nsrl(path)
        if not info["ok"]:
            msg_error(self, "Not an RDSv3 publication", info["note"])
            return
        cols = ", ".join(info.get("hash_columns", []))
        ret = msg_question(
            self, "Import this publication?",
            f"{Path(path).name}\n\n"
            f"FILE rows: {info['n_files']:,}\n"
            f"Hash columns present: {cols}\n\n"
            f"SHA-256 and MD5 will be imported (the tool's default hash "
            f"policy). The publication is opened read-only.\n\n"
            f"A large publication can take a while and will grow the hash "
            f"store substantially. Continue?")
        from PySide6.QtWidgets import QMessageBox
        if ret != QMessageBox.Yes:
            return
        name = self._ask_name(Path(path).stem)
        if not name:
            return
        self._run_import(
            lambda cb, cancel: self.store.import_nsrl(
                path, name, algos=("sha256", "md5"), progress_cb=cb,
                cancel_cb=cancel),
            f"NSRL import '{name}'")

    def _import_list(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select a hash list", "",
            "Text files (*.txt *.hash *.md5 *.sha1 *.sha256);;All files (*)")
        if not path:
            return
        name = self._ask_name(Path(path).stem)
        if not name:
            return
        self._run_import(
            lambda cb, _cancel: self.store.import_hash_list(
                path, name, progress_cb=cb),
            f"Hash-list import '{name}'")

    def _import_csv(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select a CSV hash set", "",
            "Delimited files (*.csv *.tsv *.txt);;All files (*)")
        if not path:
            return
        name = self._ask_name(Path(path).stem)
        if not name:
            return

        def go(cb, _cancel):
            try:
                return self.store.import_csv(path, name, progress_cb=cb)
            except ValueError as exc:
                raise RuntimeError(str(exc)) from exc

        self._run_import(go, f"CSV import '{name}'")

    def _delete_selected(self):
        sel = self.tbl.selectionModel()
        rows = sel.selectedRows() if sel else []
        if not rows:
            return
        name = self.tbl.item(rows[0].row(), 0).text()
        from PySide6.QtWidgets import QMessageBox
        ret = msg_question(
            self, "Remove hash set",
            f"Remove '{name}' from the hash store?\n\n"
            f"Cases already ingested keep the labels they were given — "
            f"this only affects future ingests.")
        if ret != QMessageBox.Yes:
            return
        if self.store.delete_set(name):
            self._log(f"removed hash set '{name}'")
            self.refresh()

    def _probe(self):
        value, ok = QInputDialog.getText(
            self, "Look up a hash",
            "Paste an MD5, SHA-1 or SHA-256 hash:")
        if not ok or not value.strip():
            return
        from app.core.known_files import normalise_hash
        n = normalise_hash(value)
        if not n:
            self.lbl_probe.setText("not a recognisable MD5/SHA-1/SHA-256 hash")
            return
        algo, h = n
        found = self.store.lookup(**{algo: h})
        if found:
            self.lbl_probe.setText(
                f"{algo.upper()} found in '{found}' — a KNOWN file "
                f"(vendor-shipped), which is not the same as harmless")
        else:
            self.lbl_probe.setText(
                f"{algo.upper()} not in any imported set — treated as unknown")
