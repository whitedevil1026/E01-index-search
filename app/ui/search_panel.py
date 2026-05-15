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

import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMessageBox, QPushButton, QSpinBox, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from app.core.indexer import HAS_TANTIVY, Indexer
from app.ui.centered_msg import msg_info
from app.ui.help_dialog import info_button


class SearchPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)

        title = QLabel("Search")
        title.setObjectName("h1")
        root.addWidget(title)

        # IMPORTANT scope banner: this build indexes file names + paths.
        # File contents (text inside PDFs, Office docs, raw bytes) will
        # be indexed in a future release. Users searching for words that
        # only appear inside a file's body would otherwise get 0 results
        # with no explanation, so we warn up front.
        scope_banner = QLabel(
            "<b>Currently indexed:</b> file names and file paths from the "
            "filesystem walk.  "
            "<b>Not yet indexed:</b> file contents (text inside PDFs, Office "
            "documents, raw bytes, etc.) &mdash; that is on the roadmap. "
            "Searching for words that only appear inside a file's body will "
            "return zero hits until then."
        )
        scope_banner.setWordWrap(True)
        scope_banner.setTextFormat(Qt.RichText)
        scope_banner.setStyleSheet(
            "color:#f59e0b; background:#1a1d24; padding:8px; "
            "border-radius:4px; border-left:3px solid #f59e0b;"
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
        self.mode.addItem("SHA-256 prefix", "sha256")
        self.mode.addItem("TLSH similar to…", "tlsh")
        self.mode.currentIndexChanged.connect(self._on_mode_change)
        bar.addWidget(QLabel("Mode:"))
        bar.addWidget(self.mode)

        self.q = QLineEdit()
        self.q.setPlaceholderText("e.g. invoice  |  system32  |  abcd*  |  paste TLSH hash")
        self.q.returnPressed.connect(self._run)
        bar.addWidget(self.q, 1)

        bar.addWidget(QLabel("Limit:"))
        self.limit = QSpinBox()
        self.limit.setRange(1, 1000)
        self.limit.setValue(50)
        bar.addWidget(self.limit)

        self.btn = QPushButton("Search")
        self.btn.clicked.connect(self._run)
        bar.addWidget(self.btn)

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
        self.tbl = QTableWidget(0, 6)
        self.tbl.setHorizontalHeaderLabels(
            ["Score", "Path", "Name", "Size", "Encoding", "SHA-256"]
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
        root.addWidget(self.tbl, 1)

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
            "sha256":   "SHA-256 hex prefix, e.g. a1b2c3 — finds files whose hash starts with it",
            "tlsh":     "paste a TLSH hash to find files similar to it (requires hashed files in case)",
        }
        self.q.setPlaceholderText(placeholders.get(mode, ""))

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
        if not HAS_TANTIVY:
            msg_info(self, "tantivy missing",
                     "Install tantivy-py to enable search.")
            return
        q = self.q.text().strip()
        if not q:
            self._set_status("Type a query first.", "warn")
            return

        mode = self.mode.currentData()
        self._set_status(f"Working — searching '{q}'…", "working")
        self.btn.setEnabled(False)
        self.tbl.setRowCount(0)
        QGuiApplication.processEvents()

        t0 = time.time()
        try:
            hits, segments_searched, query_used, fallback = self._search_with_fallback(q, mode)
        except Exception as exc:  # noqa: BLE001
            self._set_status(f"<b>Error:</b> {type(exc).__name__}: {exc}", "error")
            self.btn.setEnabled(True)
            return

        dt_ms = (time.time() - t0) * 1000
        self.btn.setEnabled(True)

        # populate
        self.tbl.setRowCount(len(hits))
        for i, h in enumerate(hits):
            self.tbl.setItem(i, 0, QTableWidgetItem(f"{h.score:.3f}"))
            self.tbl.setItem(i, 1, QTableWidgetItem(h.path))
            self.tbl.setItem(i, 2, QTableWidgetItem(h.name))
            self.tbl.setItem(i, 3, QTableWidgetItem(str(h.size_bytes or "")))
            self.tbl.setItem(i, 4, QTableWidgetItem(h.encoding or ""))
            self.tbl.setItem(i, 5, QTableWidgetItem((h.sha256 or "")[:16]))
        self.tbl.resizeColumnsToContents()
        # avoid the Path column collapsing to a tiny width
        if self.tbl.columnWidth(1) < 280:
            self.tbl.setColumnWidth(1, 280)

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
            if total_docs == 0:
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
                    "Reminder: this build indexes file names only, not file "
                    "contents. Hints: {tips}".format(
                        q=q, n=segments_searched, ms=dt_ms,
                        docs=total_docs, tips="  ".join(tips),
                    ),
                    "warn",
                )
        elif fallback:
            self._set_status(
                f"<b>{len(hits)} hit(s)</b> via fallback query "
                f"<code>{query_used}</code> across {segments_searched} segment(s) "
                f"({dt_ms:.0f} ms).",
                "ok",
            )
        else:
            self._set_status(
                f"<b>{len(hits)} hit(s)</b> across {segments_searched} index segment(s) "
                f"({dt_ms:.0f} ms).",
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

    def _search_with_fallback(self, q: str, mode: str):
        """Returns (hits, segments_searched, query_used, fallback_used)."""
        index_root = self.case.index_dir
        # fan-out: one Tantivy index per evidence subdir
        all_hits = []
        n_idx = 0
        query_to_use = self._format_query(q, mode)
        for sub in sorted(index_root.iterdir()):
            if not sub.is_dir() or not (sub / "meta.json").exists():
                continue
            idx = Indexer(sub)
            hits = idx.search(query_to_use, limit=self.limit.value())
            all_hits.extend(hits)
            n_idx += 1
        all_hits.sort(key=lambda h: h.score, reverse=True)
        all_hits = all_hits[: self.limit.value()]

        # Smart fallback: if 0 hits and the query has spaces, try spaceless
        used_fallback = False
        if not all_hits and " " in q and mode in ("fulltext", "name"):
            alt_q = q.replace(" ", "")
            alt_formatted = self._format_query(alt_q, mode)
            alt_hits = []
            for sub in sorted(index_root.iterdir()):
                if not sub.is_dir() or not (sub / "meta.json").exists():
                    continue
                idx = Indexer(sub)
                alt_hits.extend(idx.search(alt_formatted, limit=self.limit.value()))
            alt_hits.sort(key=lambda h: h.score, reverse=True)
            if alt_hits:
                all_hits = alt_hits[: self.limit.value()]
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
        if mode == "name":
            # name field substring — try as-is + wildcards
            return f"name:*{q}*"
        if mode == "sha256":
            return f"sha256:{q.lower()}*"
        if mode == "tlsh":
            # try1 doesn't yet implement distance-search; fall back to exact prefix
            return f"tlsh:{q.upper()}*"
        return q

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
