"""New-case wizard: case name, examiner, hash policy."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QVBoxLayout, QWidget,
)

from app.core.hash_policy import HashPolicy, SUPPORTED_ALGOS, DEFAULT_PRIMARY, DEFAULT_EXTRAS
from app.ui.help_dialog import info_button


class NewCaseDialog(QDialog):
    """Returns (case_root: Path, name: str, examiner: str, hash_policy: HashPolicy)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Case")
        self.setMinimumWidth(560)
        self.setStyleSheet(parent.styleSheet() if parent else "")

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 12)
        root.setSpacing(10)

        head = QLabel("New Case")
        head.setObjectName("h1")
        root.addWidget(head)

        intro = QLabel(
            "Create a forensic case. The parent folder will receive a new "
            "subdirectory holding <code>case.db</code>, the Tantivy index, the "
            "Ed25519 signing key, and your evidence."
        )
        intro.setObjectName("muted")
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.RichText)
        root.addWidget(intro)

        # ---- basic fields --------------------------------------------
        box = QGroupBox("Case details")
        form = QFormLayout(box)
        self.ed_name = QLineEdit()
        self.ed_name.setPlaceholderText("e.g. 2026-Q2-Bushell")
        self.ed_examiner = QLineEdit()
        self.ed_examiner.setPlaceholderText("e.g. J. Doe, badge 4815")
        # parent dir
        parent_row = QWidget()
        prl = QHBoxLayout(parent_row); prl.setContentsMargins(0,0,0,0)
        self.ed_parent = QLineEdit()
        self.ed_parent.setPlaceholderText(str(Path.home()))
        btn_browse = QPushButton("Browse…")
        btn_browse.setObjectName("secondary")
        btn_browse.clicked.connect(self._browse_parent)
        prl.addWidget(self.ed_parent, 1)
        prl.addWidget(btn_browse)
        form.addRow("Case name:", self.ed_name)
        form.addRow("Examiner:", self.ed_examiner)
        form.addRow("Parent folder:", parent_row)
        root.addWidget(box)

        # ---- hash policy ---------------------------------------------
        hp_box = QGroupBox("Hash policy")
        hl = QFormLayout(hp_box)

        title_row = QWidget()
        tr = QHBoxLayout(title_row); tr.setContentsMargins(0,0,0,0)
        tr.addWidget(QLabel(
            "Choose the hash algorithm policy used for every file in this case."
        ))
        tr.addStretch(1)
        tr.addWidget(info_button("hash_policy", self))
        hl.addRow(title_row)

        # primary combo
        self.cmb_primary = QComboBox()
        for a in SUPPORTED_ALGOS:
            self.cmb_primary.addItem(a.upper(), a)
        self.cmb_primary.setCurrentText(DEFAULT_PRIMARY.upper())
        hl.addRow("Primary hash:", self.cmb_primary)

        # extras checkboxes
        extras_row = QWidget()
        er = QHBoxLayout(extras_row); er.setContentsMargins(0,0,0,0)
        self._extra_checks: dict[str, QCheckBox] = {}
        for a in SUPPORTED_ALGOS:
            cb = QCheckBox(a.upper())
            cb.setChecked(a in DEFAULT_EXTRAS)
            self._extra_checks[a] = cb
            er.addWidget(cb)
        er.addStretch(1)
        hl.addRow("Extras:", extras_row)

        # explanation
        explain = QLabel(
            "<i>Primary</i> is the canonical fingerprint stored against every file. "
            "<i>Extras</i> are computed in the same pass — useful when your receiving "
            "agency requires multiple digests (e.g. SHA-256 + MD5 for NSRL RDS lookup)."
        )
        explain.setObjectName("muted")
        explain.setWordWrap(True)
        explain.setTextFormat(Qt.RichText)
        hl.addRow(explain)
        root.addWidget(hp_box)

        # primary change disables the matching extra checkbox so we never
        # double-count
        self.cmb_primary.currentIndexChanged.connect(self._sync_extras)
        self._sync_extras()

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self._try_accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    # ---- validation ----------------------------------------------------

    def _try_accept(self):
        """Validate inputs; only accept() if everything is OK. Otherwise
        show the user what's missing without closing the dialog (so they
        don't lose what they already typed).
        """
        result = self.result_tuple()
        if isinstance(result, tuple) and result and result[0] == "error":
            QMessageBox.warning(self, "Cannot create case", result[1])
            return
        # success
        self.accept()

    def _browse_parent(self):
        d = QFileDialog.getExistingDirectory(self, "Pick parent folder",
                                             self.ed_parent.text() or str(Path.home()))
        if d:
            self.ed_parent.setText(d)

    def _sync_extras(self):
        primary = self.cmb_primary.currentData()
        for a, cb in self._extra_checks.items():
            if a == primary:
                cb.setChecked(False)
                cb.setEnabled(False)
                cb.setToolTip("Already the primary hash")
            else:
                cb.setEnabled(True)
                cb.setToolTip("")

    # ---- result --------------------------------------------------------

    def result_tuple(self):
        """Return (case_root, name, examiner, policy) on success, or
        a ('error', reason) tuple if any field is missing.
        """
        name = self.ed_name.text().strip()
        examiner = self.ed_examiner.text().strip()
        parent_text = self.ed_parent.text().strip()
        missing = []
        if not name:
            missing.append("Case name")
        if not examiner:
            missing.append("Examiner")
        if not parent_text:
            missing.append("Parent folder")
        if missing:
            return ("error", "Missing required field(s): " + ", ".join(missing))
        parent = Path(parent_text)
        if not parent.exists():
            return ("error", f"Parent folder does not exist:\n  {parent}")
        if not parent.is_dir():
            return ("error", f"Parent is not a directory:\n  {parent}")

        primary = self.cmb_primary.currentData()
        extras = [a for a, cb in self._extra_checks.items()
                  if cb.isChecked() and cb.isEnabled() and a != primary]
        policy = HashPolicy(primary=primary, extras=extras).normalized()
        case_root = parent / name.replace(" ", "_")
        return case_root, name, examiner, policy
