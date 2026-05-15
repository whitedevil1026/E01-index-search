"""Main window — tabbed layout with a status bar showing case + deps."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QKeySequence, QIcon
from PySide6.QtWidgets import (
    QDialog, QFileDialog, QInputDialog, QLabel, QMainWindow, QMessageBox,
    QStatusBar, QTabWidget, QToolBar, QWidget,
)

from app.core.case import Case
from app.core.deps import probe_all
from app.ui.case_panel import CasePanel
from app.ui.ingest_panel import IngestPanel
from app.ui.search_panel import SearchPanel
from app.ui.audit_panel import AuditPanel
from app.ui.deps_panel import DepsPanel
from app.ui.integrity_panel import IntegrityPanel
from app.ui.new_case_dialog import NewCaseDialog
from app.ui.help_dialog import HelpDialog
from app.ui.centered_msg import msg_info, msg_warn, msg_error, show_centered


STYLE = """
QMainWindow { background: #0f1115; }
QWidget { color: #e8e8ea; font-family: 'Segoe UI', 'Inter', sans-serif; font-size: 10pt; }
QTabWidget::pane { border: 1px solid #2a2d35; background: #14171d; }
QTabBar::tab {
    background: #1a1d24; color: #b8bcc8;
    padding: 8px 18px; border: 1px solid #2a2d35; border-bottom: none;
    margin-right: 2px;
}
QTabBar::tab:selected { background: #232733; color: #fff; }
QTabBar::tab:hover { background: #1f232b; }
QToolBar { background: #14171d; border-bottom: 1px solid #2a2d35; padding: 4px; spacing: 6px; }
QStatusBar { background: #0c0e12; color: #9ca0ad; border-top: 1px solid #2a2d35; }
QPushButton {
    background: #2563eb; color: white; border: none;
    padding: 7px 14px; border-radius: 4px; font-weight: 600;
}
QPushButton:hover { background: #1d4ed8; }
QPushButton:disabled { background: #2a2d35; color: #6b7280; }
QPushButton#secondary { background: #2a2d35; }
QPushButton#secondary:hover { background: #353944; }
QPushButton#danger { background: #b91c1c; }
QLineEdit, QTextEdit, QPlainTextEdit {
    background: #1a1d24; border: 1px solid #2a2d35; border-radius: 4px;
    padding: 6px; color: #e8e8ea; selection-background-color: #2563eb;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus { border-color: #2563eb; }
QTreeView, QTableView, QListView, QTableWidget, QTreeWidget {
    background: #14171d; alternate-background-color: #181b22;
    border: 1px solid #2a2d35; gridline-color: #2a2d35; color: #e8e8ea;
    selection-background-color: #2563eb;
}
QHeaderView::section {
    background: #1a1d24; color: #b8bcc8; border: none; border-right: 1px solid #2a2d35;
    border-bottom: 1px solid #2a2d35; padding: 6px;
}
QProgressBar {
    background: #1a1d24; border: 1px solid #2a2d35; border-radius: 3px;
    text-align: center; color: #e8e8ea;
}
QProgressBar::chunk { background: #2563eb; }
QLabel#h1 { font-size: 16pt; font-weight: 700; color: #fff; }
QLabel#h2 { font-size: 12pt; font-weight: 600; color: #e8e8ea; }
QLabel#muted { color: #9ca0ad; }
QGroupBox {
    border: 1px solid #2a2d35; border-radius: 5px; margin-top: 12px; padding-top: 10px;
    color: #b8bcc8; font-weight: 600;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
"""


class MainWindow(QMainWindow):
    case_changed = Signal(object)  # Case | None

    def __init__(self):
        super().__init__()
        self.setWindowTitle("E01 Index & Search")
        self.setStyleSheet(STYLE)
        self.case: Case | None = None

        self._build_toolbar()
        self._build_statusbar()
        self._build_tabs()

        self.case_changed.connect(self._on_case_changed)
        self._on_case_changed(None)

    # ---- chrome ----------------------------------------------------------

    def _build_toolbar(self):
        tb = QToolBar("Main")
        tb.setMovable(False)
        self.addToolBar(tb)

        act_new = QAction("New Case…", self)
        act_new.setShortcut(QKeySequence("Ctrl+N"))
        act_new.triggered.connect(self._new_case)
        tb.addAction(act_new)

        act_open = QAction("Open Case…", self)
        act_open.setShortcut(QKeySequence("Ctrl+O"))
        act_open.triggered.connect(self._open_case)
        tb.addAction(act_open)

        tb.addSeparator()

        act_verify = QAction("Verify Audit Chain", self)
        act_verify.setToolTip("Re-derive the SHA-256 hash chain over the case audit "
                              "log to detect tampering. Click the ? button to learn more.")
        act_verify.triggered.connect(self._verify_audit)
        tb.addAction(act_verify)
        act_verify_help = QAction("?", self)
        act_verify_help.setToolTip("What is the Audit Chain?")
        act_verify_help.triggered.connect(lambda: HelpDialog(self, key="audit_chain").exec())
        tb.addAction(act_verify_help)

        tb.addSeparator()
        act_sign = QAction("Sign Manifest", self)
        act_sign.setToolTip("Generate a JSON manifest of the case folder and sign it "
                            "with the case's Ed25519 key. Click the ? for details.")
        act_sign.triggered.connect(self._sign_manifest)
        tb.addAction(act_sign)
        act_sign_help = QAction("?", self)
        act_sign_help.setToolTip("What is the Signed Manifest?")
        act_sign_help.triggered.connect(lambda: HelpDialog(self, key="sign_manifest").exec())
        tb.addAction(act_sign_help)

    def _build_tabs(self):
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        self.case_panel = CasePanel(self)
        self.integrity_panel = IntegrityPanel(self)
        self.ingest_panel = IngestPanel(self)
        self.search_panel = SearchPanel(self)
        self.audit_panel = AuditPanel(self)
        self.deps_panel = DepsPanel(self)

        self.tabs.addTab(self.case_panel, "Case")
        self.tabs.addTab(self.integrity_panel, "Integrity Check")
        self.tabs.addTab(self.ingest_panel, "Ingest")
        self.tabs.addTab(self.search_panel, "Search")
        self.tabs.addTab(self.audit_panel, "Audit Log")
        self.tabs.addTab(self.deps_panel, "Deps Status")

        self.setCentralWidget(self.tabs)

    def _build_statusbar(self):
        sb = QStatusBar()
        self.setStatusBar(sb)
        self.lbl_case = QLabel("No case loaded")
        self.lbl_deps = QLabel("")
        sb.addWidget(self.lbl_case, 1)
        sb.addPermanentWidget(self.lbl_deps)
        self._refresh_deps_label()

    def _refresh_deps_label(self):
        deps = probe_all()
        good = sum(1 for d in deps if d.installed)
        self.lbl_deps.setText(f"deps: {good}/{len(deps)} installed")

    # ---- actions ---------------------------------------------------------

    def _new_case(self):
        dlg = NewCaseDialog(self)
        # The dialog validates internally on OK and refuses to close on
        # missing/invalid fields, so by the time we get here the tuple is
        # guaranteed valid.
        if show_centered(dlg, self) != QDialog.Accepted:
            return
        case_root, name, examiner, policy = dlg.result_tuple()
        if case_root.exists():
            msg_error(self, "Error", f"{case_root} already exists.")
            return
        try:
            case = Case.create(case_root, name, examiner,
                               hash_policy_json=policy.to_json())
        except Exception as exc:  # noqa: BLE001
            msg_error(self, "Error", f"Failed to create case:\n{exc}")
            return
        self.case = case
        self.case_changed.emit(case)
        # Make the new case visible — jump to the Case tab so the examiner
        # sees the freshly-populated metadata, hash policy, and (empty)
        # evidence list immediately.
        self.tabs.setCurrentWidget(self.case_panel)
        msg_info(
            self, "Case created",
            f"Case '{name}' created at:\n{case_root}\n\n"
            f"Hash policy: {policy.describe()}",
        )

    def _open_case(self):
        d = QFileDialog.getExistingDirectory(self, "Open case directory", str(Path.home()))
        if not d:
            return
        try:
            case = Case.open(Path(d))
        except Exception as exc:  # noqa: BLE001
            msg_error(self, "Error", f"Failed to open case:\n{exc}")
            return
        self.case = case
        self.case_changed.emit(case)
        self.tabs.setCurrentWidget(self.case_panel)

    def _verify_audit(self):
        if not self.case:
            msg_info(self, "No case", "Open a case first.")
            return
        ok, msg = self.case.verify_audit_chain()
        if ok:
            msg_info(self, "Audit chain",
                     "Verified: every row's hash matches the chain.\n\n" + msg)
        else:
            msg_error(self, "Audit chain BROKEN",
                      "The hash chain failed to verify. This indicates the audit log "
                      "was modified outside the application.\n\n" + msg)

    def _sign_manifest(self):
        if not self.case:
            msg_info(self, "No case", "Open a case first.")
            return
        from app.core.manifest import ensure_keypair, build_manifest, sign_manifest
        from app.core.deps import probe_all as _probe
        try:
            priv, _pub = ensure_keypair(self.case.keys_dir)
            deps_sum = {d.name: (d.version or "n/a") for d in _probe()}
            m = build_manifest(self.case.root, deps_sum)
            mpath, spath = sign_manifest(self.case.root, m, priv)
            self.case.log("manifest.sign", {"files": len(m["files"])})
            msg_info(
                self, "Manifest signed",
                f"manifest.json signed with Ed25519.\n"
                f"{len(m['files'])} files covered.\n\n"
                f"Manifest path:\n  {mpath}\n\n"
                f"Signature path:\n  {spath}",
            )
            self.audit_panel.refresh()
        except Exception as exc:  # noqa: BLE001
            msg_error(self, "Error", f"Manifest signing failed:\n{exc}")

    def _on_case_changed(self, case: Case | None):
        if case:
            meta = case.meta()
            self.lbl_case.setText(
                f"Case: {meta.name}   |   Examiner: {meta.examiner}   |   {case.root}"
            )
        else:
            self.lbl_case.setText("No case loaded — File → New Case or Open Case")
        for panel in (self.case_panel, self.integrity_panel,
                      self.ingest_panel, self.search_panel, self.audit_panel):
            panel.set_case(case)
