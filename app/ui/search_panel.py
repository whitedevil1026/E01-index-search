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
    QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QMessageBox, QPushButton, QSpinBox, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from app.core.indexer import HAS_TANTIVY, Indexer
from app.ui.centered_msg import msg_info
from app.ui.help_dialog import info_button


class SearchPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        self._last_results: list = []   # rows from the last search, for export
        self._last_mode: str = ""

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
            "regex":    r"RE2 regex, e.g.  invoice.*2026   |   \d{4}-\d{4}",
            "sha256":   "SHA-256 hex prefix, e.g. a1b2c3 — finds files whose hash starts with it",
            "tlsh":     "paste a TLSH hash, or a SHA-256 of an already-hashed file, to find similar files",
        }
        self.q.setPlaceholderText(placeholders.get(mode, ""))
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

        # ---- render (Score / Path / Name / Size / Encoding / SHA-256) --
        self.tbl.setHorizontalHeaderLabels(
            ["Score", "Path", "Name", "Size", "Encoding", "SHA-256"])
        self.tbl.setRowCount(len(hits))
        for i, h in enumerate(hits):
            self.tbl.setItem(i, 0, QTableWidgetItem(f"{h.score:.3f}"))
            self.tbl.setItem(i, 1, QTableWidgetItem(h.path))
            self.tbl.setItem(i, 2, QTableWidgetItem(h.name))
            self.tbl.setItem(i, 3, QTableWidgetItem(str(h.size_bytes or "")))
            self.tbl.setItem(i, 4, QTableWidgetItem(h.encoding or ""))
            self.tbl.setItem(i, 5, QTableWidgetItem((h.sha256 or "")[:16]))
        self.tbl.resizeColumnsToContents()
        if self.tbl.columnWidth(1) < 280:
            self.tbl.setColumnWidth(1, 280)

        # keep results for export
        self._last_results = [
            {"score": f"{h.score:.3f}", "path": h.path, "name": h.name,
             "size_bytes": h.size_bytes, "encoding": h.encoding or "",
             "sha256": h.sha256 or ""}
            for h in hits
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

    def _index_dirs(self):
        for sub in sorted(self.case.index_dir.iterdir()):
            if sub.is_dir() and (sub / "meta.json").exists():
                yield sub

    def _search_with_fallback(self, q: str, mode: str):
        """Returns (hits, segments_searched, query_used, fallback_used)."""
        limit = self.limit.value()
        all_hits = []
        n_idx = 0

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
            # dedup (a doc can match on both name and path)
            seen = set()
            deduped = []
            for h in all_hits:
                k = (h.path, h.name)
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
        if mode == "name":
            # name field substring — try as-is + wildcards
            return f"name:*{q}*"
        if mode == "sha256":
            return f"sha256:{q.lower()}*"
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

        # render — Distance / Path / Name / Size / (blank) / SHA-256
        self.tbl.setHorizontalHeaderLabels(
            ["Distance", "Path", "Name", "Size", "", "SHA-256"])
        self.tbl.setRowCount(len(results))
        for i, r in enumerate(results):
            self.tbl.setItem(i, 0, QTableWidgetItem(str(r["distance"])))
            self.tbl.setItem(i, 1, QTableWidgetItem(r["path"]))
            self.tbl.setItem(i, 2, QTableWidgetItem(r["name"]))
            self.tbl.setItem(i, 3, QTableWidgetItem(str(r["size_bytes"] or "")))
            self.tbl.setItem(i, 4, QTableWidgetItem(""))
            self.tbl.setItem(i, 5, QTableWidgetItem((r["sha256"] or "")[:16]))
        self.tbl.resizeColumnsToContents()
        if self.tbl.columnWidth(1) < 280:
            self.tbl.setColumnWidth(1, 280)

        self._last_results = [
            {"distance": r["distance"], "path": r["path"], "name": r["name"],
             "size_bytes": r["size_bytes"], "sha256": r["sha256"],
             "tlsh": r["tlsh"]}
            for r in results
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
            cols = list(self._last_results[0].keys())
            with open(p, "w", newline="", encoding="utf-8") as fh:
                wr = csv.DictWriter(fh, fieldnames=cols)
                wr.writeheader()
                wr.writerows(self._last_results)
        except Exception as exc:  # noqa: BLE001
            msg_info(self, "Export failed", str(exc))
            return
        if self.case:
            self.case.log("query.export",
                          {"mode": self._last_mode,
                           "rows": len(self._last_results), "path": p})
        msg_info(self, "Results exported",
                 f"Wrote {len(self._last_results)} rows to:\n{p}")

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
