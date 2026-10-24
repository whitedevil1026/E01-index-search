"""Search panel — query the Tantivy indexes belonging to this case.

Features:
- Live status indicator: 'Working…' while running, exact hit count + ms
  on success, explicit 'No matches' (with hints) on zero results,
  'Error: …' on exception.
- Smart fallback: when an exact query returns nothing AND the query has
  whitespace, automatically try the spaceless concatenation (e.g.
  "system 32" → "system32") and surface it as a suggestion.
- Multi-mode search: keyword full-text, exact-name substring, SHA-256
  prefix, TLSH similarity (engine ready, distance search lands when
  full-corpus TLSH indexing does).
- Inline 'What is TLSH?' info button.
"""
from __future__ import annotations

import re
import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from app.core.csv_safe import csv_safe_dict
from app.core.indexer import HAS_TANTIVY, Indexer
from app.core import extract as extract_mod
from app.ui.centered_msg import msg_info
from app.ui.exported_dialog import ExportedDialog
from app.ui.help_dialog import info_button


class SearchPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        self._last_results: list = []   # rows from the last search, for export
        self._last_mode: str = ""
        self._sel_prov = None           # provenance of the selected row
        self._known_cache: dict = {}    # (evidence_uuid, path) -> is_known
        self._last_hidden = 0           # rows the known-file filter hid

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)

        title = QLabel("Search")
        title.setObjectName("h1")
        root.addWidget(title)

        # Scope banner: search covers file names + paths always, and file
        # *contents* too if the ingest was run with the "Extract & index
        # file contents" option. Files whose ingest didn't extract text
        # (or types not yet supported) match on name only.
        scope_banner = QLabel(
            "<b>Searchable:</b> file names, file paths, and &mdash; for "
            "evidence ingested with <i>Extract &amp; index file contents</i> "
            "enabled &mdash; the text inside PDFs, DOCX/XLSX/PPTX, MSG, EML, "
            "HTML, RTF and plain-text files.  "
            "If an ingest was run with content extraction OFF, only names "
            "and paths are searchable for that evidence item."
        )
        scope_banner.setWordWrap(True)
        scope_banner.setTextFormat(Qt.RichText)
        scope_banner.setStyleSheet(
            "color:#9ca0ad; background:#1a1d24; padding:8px; "
            "border-radius:4px; border-left:3px solid #2563eb;"
        )
        root.addWidget(scope_banner)

        sub = QLabel(
            "Queries are NFC-normalized + lowercased at parse time. "
            "Tokenisation is on word boundaries — <code>system32</code> stays as "
            "one token, while <code>system 32</code> becomes two tokens "
            "(<code>system</code> OR <code>32</code>). "
            "Fields: <b>name</b>, <b>path</b>, <b>sha256</b>, <b>tlsh</b>."
        )
        sub.setObjectName("muted")
        sub.setWordWrap(True)
        sub.setTextFormat(Qt.RichText)
        root.addWidget(sub)

        # ---- query row ------------------------------------------------
        bar = QHBoxLayout()
        self.mode = QComboBox()
        self.mode.addItem("Keyword / full-text", "fulltext")
        self.mode.addItem("Exact name (substring)", "name")
        self.mode.addItem("Regex (name / path)", "regex")
        self.mode.addItem("SHA-256 prefix", "sha256")
        self.mode.addItem("TLSH similar to…", "tlsh")
        self.mode.currentIndexChanged.connect(self._on_mode_change)
        bar.addWidget(QLabel("Mode:"))
        bar.addWidget(self.mode)

        self.q = QLineEdit()
        self.q.setPlaceholderText("e.g. invoice  |  system32  |  abcd*  |  paste TLSH hash")
        self.q.returnPressed.connect(self._run)
        bar.addWidget(self.q, 1)

        # TLSH distance threshold — only shown in TLSH mode
        self.lbl_dist = QLabel("Max distance:")
        self.spin_dist = QSpinBox()
        self.spin_dist.setRange(1, 1000)
        self.spin_dist.setValue(80)
        self.spin_dist.setToolTip(
            "TLSH distance: 0 identical, 1-30 very similar, "
            "30-100 somewhat similar, >200 unrelated."
        )
        self.lbl_dist.setVisible(False)
        self.spin_dist.setVisible(False)
        bar.addWidget(self.lbl_dist)
        bar.addWidget(self.spin_dist)

        self.chk_hide_known = QCheckBox("Hide known files")
        self.chk_hide_known.setChecked(False)
        self.chk_hide_known.setToolTip(
            "Leave out results whose hash matched an imported hash set "
            "(NSRL and friends) during ingest.\n\n"
            "Off by default, deliberately. A hash set says a file shipped "
            "with some product, not that it is innocent — attackers use "
            "signed vendor binaries, and those are in NSRL too.\n\n"
            "When on, the status line always states how many results were "
            "hidden, so a filtered list is never mistaken for the whole "
            "set. Nothing is deleted; this only affects the view."
        )
        bar.addWidget(self.chk_hide_known)

        bar.addWidget(QLabel("Limit:"))
        self.limit = QSpinBox()
        self.limit.setRange(1, 1000)
        self.limit.setValue(50)
        bar.addWidget(self.limit)

        self.btn = QPushButton("Search")
        self.btn.clicked.connect(self._run)
        bar.addWidget(self.btn)

        self.btn_export = QPushButton("Export results…")
        self.btn_export.setObjectName("secondary")
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self._export_results)
        bar.addWidget(self.btn_export)

        # info button for TLSH
        self.tlsh_help_btn = info_button("tlsh", self)
        self.tlsh_help_btn.setToolTip("What is TLSH?")
        bar.addWidget(self.tlsh_help_btn)
        root.addLayout(bar)

        if not HAS_TANTIVY:
            warn = QLabel(
                "<b>tantivy-py is not installed.</b> "
                "Install: <code>pip install 'tantivy&gt;=0.22,&lt;0.26'</code>"
            )
            warn.setStyleSheet("color:#f59e0b;")
            warn.setTextFormat(Qt.RichText)
            root.addWidget(warn)

        # ---- status ---------------------------------------------------
        self.status = QLabel("Idle.")
        self.status.setObjectName("muted")
        self.status.setStyleSheet("padding: 4px 0;")
        root.addWidget(self.status)

        # ---- results table -------------------------------------------
        self.tbl = QTableWidget(0, 8)
        self.tbl.setHorizontalHeaderLabels(
            ["Score", "Origin", "Evidence", "Found in", "Name", "Size",
             "Encoding", "SHA-256"]
        )
        hdr = self.tbl.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(True)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.verticalHeader().setDefaultSectionSize(26)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl.cellDoubleClicked.connect(self._copy_cell)
        self.tbl.setStyleSheet(
            "QTableWidget { font-size: 10pt; }"
            "QHeaderView::section { font-weight: 600; padding: 6px; }"
        )
        self.tbl.itemSelectionChanged.connect(self._on_row_selected)
        root.addWidget(self.tbl, 1)

        # ---- provenance of the selected hit ---------------------------
        prov_box = QGroupBox("Where this hit came from")
        pv = QVBoxLayout(prov_box)
        self.prov_view = QPlainTextEdit()
        self.prov_view.setReadOnly(True)
        self.prov_view.setMaximumHeight(150)
        self.prov_view.setPlaceholderText(
            "Select a result to see exactly where in the image it was "
            "found — filesystem path, volume, byte offset and hashes."
        )
        self.prov_view.setStyleSheet("font-family: Consolas, monospace;")
        pv.addWidget(self.prov_view)

        prov_bar = QHBoxLayout()
        self.btn_extract = QPushButton("Export this file from the image…")
        self.btn_extract.setEnabled(False)
        self.btn_extract.clicked.connect(self._extract_selected)
        self.btn_extract.setToolTip(
            "Read the original bytes back out of the evidence image and "
            "save them to disk.\n\n"
            "The exported copy is hashed and checked against the hash "
            "recorded at ingest, and the export is written to the "
            "case audit log."
        )
        prov_bar.addWidget(self.btn_extract)
        self.chk_receipt = QCheckBox("Write hash receipt (.verify.txt)")
        self.chk_receipt.setChecked(True)
        self.chk_receipt.setToolTip(
            "Save a plain-text receipt next to the exported file recording "
            "where in the image it came from, its hashes under the case's "
            "hash policy, and whether those match the hashes recorded at "
            "ingest.\n\n"
            "Lets anyone re-hash the file later and confirm it is authentic."
        )
        prov_bar.addWidget(self.chk_receipt)
        self.lbl_extract = QLabel("")
        self.lbl_extract.setObjectName("muted")
        prov_bar.addWidget(self.lbl_extract)
        prov_bar.addStretch(1)
        pv.addLayout(prov_bar)
        root.addWidget(prov_box)

        bottom = QLabel(
            "Double-click any cell to copy its value. "
            "Press <b>Ctrl+F</b> on this tab to jump straight to the query box."
        )
        bottom.setObjectName("muted")
        bottom.setTextFormat(Qt.RichText)
        root.addWidget(bottom)

        # Ctrl+F focuses the query field when this panel is visible.
        focus_q = QShortcut(QKeySequence("Ctrl+F"), self)
        focus_q.setContext(Qt.WidgetWithChildrenShortcut)
        focus_q.activated.connect(lambda: (self.q.setFocus(), self.q.selectAll()))

    # ---- state -------------------------------------------------------

    def set_case(self, case):
        self.case = case
        self.setEnabled(case is not None)
        if case is None:
            self.tbl.setRowCount(0)
            self._set_status(
                "No case loaded — use <b>File → New Case</b> (Ctrl+N) or "
                "<b>Open Case</b> (Ctrl+O) on the toolbar to begin.",
                "warn",
            )
        else:
            self.tbl.setRowCount(0)
            self._set_status(
                f"Ready. Case '{case.meta().name}' loaded — type a query and "
                f"press Enter (or Ctrl+F to focus this field).",
                "muted",
            )

    def _on_mode_change(self):
        mode = self.mode.currentData()
        placeholders = {
            "fulltext": "e.g. invoice  |  password  |  ntfs",
            "name":     "exact-name substring, e.g. system32 (case-insensitive)",
            "regex":    r"RE2 regex — matches anywhere, e.g.  invoice.*2026  |  \$MFT  |  ^C:/Users",
            "sha256":   "SHA-256 hex prefix, e.g. a1b2c3 — finds files whose hash starts with it",
            "tlsh":     "paste a TLSH hash, or a SHA-256 of an already-hashed file, to find similar files",
        }
        self.q.setPlaceholderText(placeholders.get(mode, ""))
        if mode == "regex":
            self.q.setToolTip(
                "Matches anywhere in a term (no need to wrap in .*).\n"
                "Anchor with ^ or $ for a whole-term match.\n\n"
                "Searches the file NAME and the full PATH. Paths keep "
                "their original case and punctuation, so patterns like "
                r"\$MFT or ^C:/Users work against the path." "\n\n"
                "Names are tokenised and lowercased for indexing, so "
                "punctuation such as $ . _ is not part of a name term — "
                "match those against the path instead."
            )
        else:
            self.q.setToolTip("")
        is_tlsh = (mode == "tlsh")
        self.lbl_dist.setVisible(is_tlsh)
        self.spin_dist.setVisible(is_tlsh)

    # ---- search ------------------------------------------------------

    def _set_status(self, msg: str, kind: str = "muted") -> None:
        color = {
            "muted":   "#9ca0ad",
            "working": "#facc15",
            "ok":      "#22c55e",
            "warn":    "#f59e0b",
            "error":   "#ef4444",
        }.get(kind, "#9ca0ad")
        self.status.setText(msg)
        self.status.setStyleSheet(f"color:{color}; padding: 4px 0;")
        self.status.setTextFormat(Qt.RichText)

    def _run(self):
        if not self.case:
            return
        q = self.q.text().strip()
        if not q:
            self._set_status("Type a query first.", "warn")
            return
        mode = self.mode.currentData()

        # TLSH similarity is a database scan, not a Tantivy query.
        if mode == "tlsh":
            self._run_tlsh(q)
            return

        if not HAS_TANTIVY:
            msg_info(self, "tantivy missing",
                     "Install tantivy-py to enable search.")
            return

        self._known_cache.clear()
        self._set_status(f"Working — searching '{q}'…", "working")
        self.btn.setEnabled(False)
        self.btn_export.setEnabled(False)
        self.tbl.setRowCount(0)
        QGuiApplication.processEvents()

        t0 = time.time()
        try:
            hits, segments_searched, query_used, fallback = \
                self._search_with_fallback(q, mode)
        except Exception as exc:  # noqa: BLE001
            self._set_status(f"<b>Error:</b> {type(exc).__name__}: {exc}", "error")
            self.btn.setEnabled(True)
            return

        dt_ms = (time.time() - t0) * 1000
        self.btn.setEnabled(True)

        # Optionally leave out vendor-shipped files. This filters the
        # VIEW only — the documents stay in the index and the rows stay
        # in the database — and the count hidden is always reported, so
        # a filtered list is never mistaken for the complete one.
        n_hidden = 0
        if self.chk_hide_known.isChecked() and hits:
            kept = []
            for h in hits:
                if self._is_known(h.path, h.evidence_uuid):
                    n_hidden += 1
                else:
                    kept.append(h)
            hits = kept
        self._last_hidden = n_hidden

        # ---- render (Score / Path / Name / Size / Encoding / SHA-256) --
        self.tbl.setHorizontalHeaderLabels(
            ["Score", "Origin", "Evidence", "Found in", "Name", "Size",
             "Encoding", "SHA-256"])
        self.tbl.setRowCount(len(hits))
        origins = [extract_mod.origin_of(h.path) for h in hits]
        for i, h in enumerate(hits):
            self.tbl.setItem(i, 0, QTableWidgetItem(f"{h.score:.3f}"))
            self.tbl.setItem(i, 1, QTableWidgetItem(origins[i]))
            self.tbl.setItem(i, 2, QTableWidgetItem(self._evidence_label(h.evidence_uuid)))
            self.tbl.setItem(i, 3, QTableWidgetItem(h.path))
            self.tbl.setItem(i, 4, QTableWidgetItem(h.name))
            self.tbl.setItem(i, 5, QTableWidgetItem(str(h.size_bytes or "")))
            self.tbl.setItem(i, 6, QTableWidgetItem(h.encoding or ""))
            self.tbl.setItem(i, 7, QTableWidgetItem((h.sha256 or "")[:16]))
        self.tbl.resizeColumnsToContents()
        if self.tbl.columnWidth(3) < 280:
            self.tbl.setColumnWidth(3, 280)

        # keep results for export
        self._last_results = [
            {"score": f"{h.score:.3f}", "origin": origins[i], "path": h.path,
             "name": h.name, "size_bytes": h.size_bytes,
             "encoding": h.encoding or "", "sha256": h.sha256 or "",
             "evidence_uuid": h.evidence_uuid}
            for i, h in enumerate(hits)
        ]
        self._last_mode = mode
        self.btn_export.setEnabled(bool(hits))

        # status
        if len(hits) == 0:
            # Count total indexed docs across the case so the user sees
            # whether the index is empty vs the query simply not matching.
            total_docs = self._total_indexed_docs()
            tips = []
            tips.append(f"Try a different mode (current: <b>{mode}</b>).")
            if " " in q:
                tips.append(
                    f"Multi-word queries are OR'd — try the spaceless form "
                    f"<code>{q.replace(' ', '')}</code>."
                )
            tips.append("Try a wildcard, e.g. <code>system*</code>.")
            if getattr(self, "_last_hidden", 0):
                # Everything that matched was a known file. Reporting
                # this as "the query didn't match anything" would tell
                # the examiner the file is not on the drive when it is —
                # the exact failure the known-file design forbids.
                n = self._last_hidden
                self._set_status(
                    f"<b>0 shown — but {n} known file(s) matched and were "
                    f"hidden.</b> <i>Hide known files</i> is ticked, so every "
                    f"match for <code>{q}</code> was a file present in an "
                    f"imported hash set. Untick it to see them: a hash set "
                    f"means vendor-shipped, not harmless.",
                    "warn",
                )
            elif total_docs == 0:
                self._set_status(
                    "<b>No documents indexed yet.</b> Run an ingest in the "
                    "<b>Ingest</b> tab first — searches need indexed file names "
                    "to match against.",
                    "warn",
                )
            else:
                self._set_status(
                    "<b>0 matches</b> for <code>{q}</code> in {n} index "
                    "segment(s) ({ms:.0f} ms). "
                    "The case has <b>{docs:,}</b> indexed docs so search ran "
                    "fine &mdash; the query just didn't match anything. "
                    "If you expected a hit inside a document, check the "
                    "evidence was ingested with content extraction enabled. "
                    "Hints: {tips}".format(
                        q=q, n=segments_searched, ms=dt_ms,
                        docs=total_docs, tips="  ".join(tips),
                    ),
                    "warn",
                )
        elif fallback:
            self._set_status(
                f"<b>{len(hits)} hit(s)</b> via fallback query "
                f"<code>{query_used}</code> across {segments_searched} segment(s) "
                f"({dt_ms:.0f} ms).{self._hidden_note()}",
                "ok",
            )
        else:
            self._set_status(
                f"<b>{len(hits)} hit(s)</b> across {segments_searched} index segment(s) "
                f"({dt_ms:.0f} ms).{self._hidden_note()}",
                "ok",
            )

        # Audit-log every query
        self.case.log("query.search", {
            "mode": mode, "q": q, "q_executed": query_used,
            "fallback_used": fallback, "limit": self.limit.value(),
            "hits": len(hits), "segments": segments_searched,
            "duration_ms": int(dt_ms),
        })
        mw = self.window()
        if hasattr(mw, "audit_panel"):
            mw.audit_panel.refresh()

    # ---- query execution --------------------------------------------

    def _index_dirs(self):
        for sub in sorted(self.case.index_dir.iterdir()):
            if sub.is_dir() and (sub / "meta.json").exists():
                yield sub

    def _search_with_fallback(self, q: str, mode: str):
        """Returns (hits, segments_searched, query_used, fallback_used)."""
        limit = self.limit.value()
        all_hits = []
        n_idx = 0

        # ---- SHA-256 prefix ------------------------------------------
        # Routed through a regex query on the sha256 field, NOT the text
        # query parser. The parser has no wildcard support, so the old
        # "sha256:<hex>*" form made Tantivy treat the trailing * as part
        # of the term: the mode returned 0 hits even for a full, exact
        # hash that was indexed. Measured dead at every prefix length.
        if mode == "sha256":
            prefix = q.strip().lower()
            for sub in self._index_dirs():
                idx = Indexer(sub)
                try:
                    all_hits.extend(idx.regex_search(
                        "^" + re.escape(prefix), field="sha256", limit=limit))
                except Exception:  # noqa: BLE001
                    pass
                n_idx += 1
            seen, deduped = set(), []
            for h in all_hits:
                k = (h.evidence_uuid, h.path, h.name)
                if k not in seen:
                    seen.add(k)
                    deduped.append(h)
            return deduped[:limit], n_idx, f"sha256 prefix {prefix}", False

        # ---- exact name (substring) ----------------------------------
        # Same fault: "name:*q*" is not a wildcard query in Tantivy, so
        # the mode only ever matched whole tokens. "voice" missed
        # invoice_2026.pdf and "32" missed system32.dll, despite the mode
        # being labelled a substring search.
        if mode == "name":
            for sub in self._index_dirs():
                idx = Indexer(sub)
                for field in ("name", "path"):
                    try:
                        all_hits.extend(idx.regex_search(
                            re.escape(q.strip()), field=field, limit=limit))
                    except Exception:  # noqa: BLE001
                        pass
                n_idx += 1
            seen, deduped = set(), []
            for h in all_hits:
                k = (h.evidence_uuid, h.path, h.name)
                if k not in seen:
                    seen.add(k)
                    deduped.append(h)
            return deduped[:limit], n_idx, f"name contains {q!r}", False

        # ---- regex mode — Tantivy RE2 query over name + path ----------
        if mode == "regex":
            for sub in self._index_dirs():
                idx = Indexer(sub)
                for field in ("name", "path"):
                    try:
                        all_hits.extend(
                            idx.regex_search(q, field=field, limit=limit))
                    except Exception:  # noqa: BLE001
                        pass
                n_idx += 1
            # Dedup the same document matching on both `name` and `path`.
            # The key MUST include the evidence item: a case can hold
            # several images and paths like /$RECYCLE.BIN, /Boot and
            # /System Volume Information exist in all of them. Keying on
            # (path, name) alone collapsed those into one row and hid the
            # fact that the file is present on the other drives too.
            seen = set()
            deduped = []
            for h in all_hits:
                k = (h.evidence_uuid, h.path, h.name)
                if k not in seen:
                    seen.add(k)
                    deduped.append(h)
            return deduped[:limit], n_idx, f"regex:/{q}/", False

        # ---- standard query modes -------------------------------------
        query_to_use = self._format_query(q, mode)
        for sub in self._index_dirs():
            idx = Indexer(sub)
            all_hits.extend(idx.search(query_to_use, limit=limit))
            n_idx += 1
        all_hits.sort(key=lambda h: h.score, reverse=True)
        all_hits = all_hits[:limit]

        # Smart fallback: if 0 hits and the query has spaces, try spaceless
        used_fallback = False
        if not all_hits and " " in q and mode in ("fulltext", "name"):
            alt_q = q.replace(" ", "")
            alt_formatted = self._format_query(alt_q, mode)
            alt_hits = []
            for sub in self._index_dirs():
                idx = Indexer(sub)
                alt_hits.extend(idx.search(alt_formatted, limit=limit))
            alt_hits.sort(key=lambda h: h.score, reverse=True)
            if alt_hits:
                all_hits = alt_hits[:limit]
                query_to_use = alt_formatted
                used_fallback = True

        return all_hits, n_idx, query_to_use, used_fallback

    def _total_indexed_docs(self) -> int:
        """Quick best-effort count of docs across every evidence index in
        the case. Used to distinguish 'empty index' from 'no match' in
        the 0-result UX.
        """
        if not self.case:
            return 0
        total = 0
        try:
            for sub in self.case.index_dir.iterdir():
                if not sub.is_dir() or not (sub / "meta.json").exists():
                    continue
                try:
                    idx = Indexer(sub)
                    idx.index.reload()
                    total += int(idx.index.searcher().num_docs)
                except Exception:
                    pass
        except Exception:
            pass
        return total

    def _format_query(self, q: str, mode: str) -> str:
        """Only the full-text mode reaches the Tantivy query parser now.

        `name` and `sha256` used wildcard syntax the parser does not
        implement, so both are handled by regex queries on their fields
        in _search_with_fallback.
        """
        return q

    # ---- TLSH similarity search --------------------------------------

    def _run_tlsh(self, q: str):
        """TLSH similarity is a database scan over per-file TLSH hashes,
        not a Tantivy query. The input is either a TLSH hash or the
        SHA-256 of an already-hashed file (whose TLSH we look up).
        """
        self._set_status("Working — TLSH similarity search…", "working")
        self.btn.setEnabled(False)
        self.btn_export.setEnabled(False)
        self.tbl.setRowCount(0)
        QGuiApplication.processEvents()

        seed = q.strip()
        seed_note = ""
        query_tlsh = seed
        # a 64-hex string is a SHA-256 — resolve it to the file's TLSH
        if len(seed) == 64 and all(c in "0123456789abcdefABCDEF" for c in seed):
            tl = self.case.tlsh_lookup(seed.lower())
            if not tl:
                self.btn.setEnabled(True)
                self._set_status(
                    "No hashed file with that SHA-256 in the case. TLSH "
                    "search needs evidence ingested with <b>Hash file "
                    "contents</b> enabled.", "warn")
                return
            query_tlsh = tl
            seed_note = f" (seed file SHA-256 {seed[:12]}…)"

        t0 = time.time()
        try:
            results = self.case.tlsh_similar(
                query_tlsh, max_distance=self.spin_dist.value(),
                limit=self.limit.value())
        except Exception as exc:  # noqa: BLE001
            self.btn.setEnabled(True)
            self._set_status(f"<b>Error:</b> {type(exc).__name__}: {exc}",
                             "error")
            return
        dt_ms = (time.time() - t0) * 1000
        self.btn.setEnabled(True)

        # render — Distance / Origin / Found in / Name / Size / _ / SHA-256
        self.tbl.setHorizontalHeaderLabels(
            ["Distance", "Origin", "Evidence", "Found in", "Name", "Size",
             "", "SHA-256"])
        self.tbl.setRowCount(len(results))
        origins = [extract_mod.origin_of(r["path"]) for r in results]
        for i, r in enumerate(results):
            self.tbl.setItem(i, 0, QTableWidgetItem(str(r["distance"])))
            self.tbl.setItem(i, 1, QTableWidgetItem(origins[i]))
            self.tbl.setItem(i, 2, QTableWidgetItem(
                self._evidence_label(evidence_id=r.get("evidence_id"))))
            self.tbl.setItem(i, 3, QTableWidgetItem(r["path"]))
            self.tbl.setItem(i, 4, QTableWidgetItem(r["name"]))
            self.tbl.setItem(i, 5, QTableWidgetItem(str(r["size_bytes"] or "")))
            self.tbl.setItem(i, 6, QTableWidgetItem(""))
            self.tbl.setItem(i, 7, QTableWidgetItem((r["sha256"] or "")[:16]))
        self.tbl.resizeColumnsToContents()
        if self.tbl.columnWidth(3) < 280:
            self.tbl.setColumnWidth(3, 280)

        self._last_results = [
            {"distance": r["distance"], "origin": origins[i],
             "path": r["path"], "name": r["name"],
             "size_bytes": r["size_bytes"], "sha256": r["sha256"],
             "tlsh": r["tlsh"], "evidence_id": r.get("evidence_id")}
            for i, r in enumerate(results)
        ]
        self._last_mode = "tlsh"
        self.btn_export.setEnabled(bool(results))

        if not results:
            self._set_status(
                f"<b>0 files</b> within TLSH distance "
                f"{self.spin_dist.value()}{seed_note} ({dt_ms:.0f} ms). "
                "TLSH search only sees files ingested with <b>Hash file "
                "contents</b> enabled — and carved files.", "warn")
        else:
            self._set_status(
                f"<b>{len(results)} similar file(s)</b> within TLSH distance "
                f"{self.spin_dist.value()}{seed_note} ({dt_ms:.0f} ms). "
                "Nearest first (0 = identical).", "ok")

        self.case.log("query.tlsh", {
            "seed": seed[:80], "max_distance": self.spin_dist.value(),
            "results": len(results), "duration_ms": int(dt_ms),
        })
        mw = self.window()
        if hasattr(mw, "audit_panel"):
            mw.audit_panel.refresh()

    # ---- export ------------------------------------------------------

    def _export_results(self):
        if not self._last_results:
            return
        import csv
        p, _ = QFileDialog.getSaveFileName(
            self, "Export search results",
            f"search_{self._last_mode}_{time.strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV (*.csv)")
        if not p:
            return
        try:
            # Union of keys, not just the first row's — a later row with
            # an extra field would otherwise raise mid-write and lose
            # the whole export.
            cols: list[str] = []
            for r in self._last_results:
                for k in r:
                    if k not in cols:
                        cols.append(k)
            with open(p, "w", newline="", encoding="utf-8") as fh:
                # Results are evidence-derived; neutralise spreadsheet
                # formula leaders. See app.core.csv_safe.
                wr = csv.DictWriter(fh, fieldnames=cols, restval="")
                wr.writeheader()
                wr.writerows(csv_safe_dict(r) for r in self._last_results)
        except Exception as exc:  # noqa: BLE001
            msg_info(self, "Export failed", str(exc))
            return
        if self.case:
            self.case.log("query.export",
                          {"mode": self._last_mode,
                           "rows": len(self._last_results), "path": p})
        msg_info(self, "Results exported",
                 f"Wrote {len(self._last_results)} rows to:\n{p}")

    # ---- provenance / extraction -------------------------------------

    def _hidden_note(self) -> str:
        """State what the known-file filter removed from this view.

        A filtered result list that does not say it is filtered is
        indistinguishable from a complete one, which is how evidence
        gets overlooked.
        """
        n = getattr(self, "_last_hidden", 0)
        if not n:
            return ""
        return (f" &nbsp;<b>{n} known file(s) hidden</b> — untick "
                f"<i>Hide known files</i> to see them.")

    def _is_known(self, path: str, evidence_uuid: str = "") -> bool:
        """Did this file match a known-file hash set at ingest time?"""
        if not self.case:
            return False
        key = (evidence_uuid, path)
        cached = self._known_cache.get(key)
        if cached is not None:
            return cached
        ev_id = None
        if evidence_uuid:
            row = self.case.evidence_by_uuid(evidence_uuid)
            if row:
                ev_id = row["id"]
        # Container sub-documents are indexed as "<file>#<subpath>" and
        # never match a files.path row, so resolve the container.
        lookup_path = path.split("#", 1)[0] if "#" in path else path
        if ev_id is None and len(self.case.list_evidence()) > 1:
            # Several images and no way to tell which: treating the row
            # as unknown shows it, rather than judging it by another
            # image's file of the same path.
            self._known_cache[key] = False
            return False
        frow = self.case.file_by_path(lookup_path, ev_id)
        val = bool(frow and (frow.get("known_set") or ""))
        self._known_cache[key] = val
        return val

    def _evidence_label(self, evidence_uuid: str = "",
                        evidence_id=None) -> str:
        """Short name of the image a hit came from. A case can hold
        several images, so the row has to say which one."""
        if not self.case:
            return ""
        row = None
        if evidence_uuid:
            row = self.case.evidence_by_uuid(evidence_uuid)
        if row is None and evidence_id is not None:
            row = self.case.evidence_by_id(evidence_id)
        if row is None:
            return ""
        from pathlib import Path as _P
        return _P(row["path"]).name

    def _selected_indexed_path(self) -> str:
        rows = self.tbl.selectionModel().selectedRows() \
            if self.tbl.selectionModel() else []
        if not rows:
            return ""
        r = rows[0].row()
        if 0 <= r < len(self._last_results):
            return self._last_results[r].get("path", "")
        return ""

    def _on_row_selected(self):
        self._sel_prov = None
        self.btn_extract.setEnabled(False)
        self.lbl_extract.setText("")
        path = self._selected_indexed_path()
        if not path or not self.case:
            self.prov_view.setPlainText("")
            return
        # Pass the evidence UUID the hit carries: in a multi-image case
        # the same path can exist in several images, and resolving
        # without it would report — and export — the wrong one.
        ev_uuid = ""
        sel = self.tbl.selectionModel()
        rows = sel.selectedRows() if sel else []
        if rows and 0 <= rows[0].row() < len(self._last_results):
            ev_uuid = self._last_results[rows[0].row()].get("evidence_uuid", "")
        ev_id = None
        if rows and 0 <= rows[0].row() < len(self._last_results):
            ev_id = self._last_results[rows[0].row()].get("evidence_id")
        try:
            prov = extract_mod.describe(self.case, path,
                                        evidence_id=ev_id,
                                        evidence_uuid=ev_uuid)
        except Exception as exc:  # noqa: BLE001
            self.prov_view.setPlainText(f"Could not resolve origin: {exc}")
            return
        self._sel_prov = prov
        width = max(len(k) for k, _ in prov.summary_lines()) if \
            prov.summary_lines() else 10
        self.prov_view.setPlainText(
            "\n".join(f"{k:<{width}} :  {v}" for k, v in prov.summary_lines())
        )
        self.btn_extract.setEnabled(bool(prov.exportable))
        if not prov.exportable:
            self.lbl_extract.setText(prov.note or "not exportable")

    def _extract_selected(self):
        prov = getattr(self, "_sel_prov", None)
        if prov is None or not self.case:
            return
        dest, _ = QFileDialog.getSaveFileName(
            self, "Export file from image", prov.suggested_name)
        if not dest:
            return
        self.btn_extract.setEnabled(False)
        self.lbl_extract.setText("extracting…")
        QGuiApplication.processEvents()
        try:
            res = extract_mod.export(
                self.case, prov, dest,
                write_receipt=self.chk_receipt.isChecked())
        except Exception as exc:  # noqa: BLE001
            self.btn_extract.setEnabled(True)
            self.lbl_extract.setText("")
            msg_info(self, "Export failed", f"{type(exc).__name__}: {exc}")
            return
        self.btn_extract.setEnabled(True)
        if res["verified"] is True:
            verdict = ("Hash verified — the exported bytes match the "
                       "hash recorded at ingest.")
        elif res["verified"] is False:
            verdict = ("WARNING: the exported bytes do NOT match the "
                       "hash recorded at ingest.")
        else:
            verdict = "No ingest-time hash was stored, so nothing to verify."
        self.lbl_extract.setText(f"exported {res['bytes']:,} bytes")
        digest_lines = "\n".join(
            f"{a.upper():<8} {d}" for a, d in sorted(res["digests"].items()))
        paths = [res["path"]]
        if res.get("receipt"):
            paths.append(res["receipt"])
        ExportedDialog(
            self, title="Exported from image",
            intro=(f"Wrote {res['bytes']:,} bytes\n\n"
                   f"{digest_lines}\n\n{verdict}"),
            paths=paths,
        ).exec()

    def _copy_cell(self, row: int, col: int):
        item = self.tbl.item(row, col)
        if not item:
            return
        QGuiApplication.clipboard().setText(item.text())
        old = self.status.text()
        old_style = self.status.styleSheet()
        self._set_status(f"Copied: <code>{item.text()[:80]}</code>", "ok")
        QTimer.singleShot(1500, lambda: (
            self.status.setText(old), self.status.setStyleSheet(old_style)
        ))
