"""Key-escrow dialog for an encrypted volume.

When the volume scan finds a BitLocker / FileVault / LUKS volume, this
dialog collects the key material from the examiner. The tool never
stores keys — they live only for the duration of the ingest.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget,
)

from app.core.encryption import Credentials, BITLOCKER, FILEVAULT, LUKS, human_name


class EncryptionKeyDialog(QDialog):
    """Collect Credentials for one encrypted volume.

    result_skip() is True if the examiner chose to skip the volume.
    credentials() returns the entered Credentials.
    """

    def __init__(self, parent=None, *, kind: str = "", volume_label: str = ""):
        super().__init__(parent)
        self._kind = kind
        self._skip = False
        self.setWindowTitle(f"Unlock {human_name(kind)} volume")
        self.setMinimumWidth(560)
        self.setStyleSheet(parent.styleSheet() if parent else "")

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 12)
        root.setSpacing(10)

        head = QLabel(f"Encrypted volume: {human_name(kind)}")
        head.setObjectName("h1")
        root.addWidget(head)

        intro = QLabel(
            f"Volume <b>{volume_label}</b> is {human_name(kind)}-encrypted. "
            "Supply <b>one</b> form of key material below to decrypt and index "
            "it. Keys are held only for this ingest and never written to the "
            "case. Leave everything blank and click <b>Skip</b> to tag the "
            "volume 'encrypted, no usable text' and move on."
        )
        intro.setObjectName("muted")
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.RichText)
        root.addWidget(intro)

        box = QGroupBox("Key material")
        form = QFormLayout(box)

        self.ed_password = QLineEdit()
        self.ed_password.setEchoMode(QLineEdit.Password)
        self.ed_password.setPlaceholderText("user password / passphrase")
        form.addRow("Password:", self.ed_password)

        self.ed_recovery = QLineEdit()
        self.ed_recovery.setPlaceholderText(
            "BitLocker 48-digit recovery key, or FileVault recovery key"
        )
        # recovery password is only meaningful for BitLocker / FileVault
        self._row_recovery_label = QLabel("Recovery key:")
        form.addRow(self._row_recovery_label, self.ed_recovery)

        # startup key — BitLocker only
        self._startup_widget = QWidget()
        sl = QHBoxLayout(self._startup_widget)
        sl.setContentsMargins(0, 0, 0, 0)
        self.ed_startup = QLineEdit()
        self.ed_startup.setPlaceholderText("path to BitLocker .BEK startup-key file")
        btn_bek = QPushButton("Browse…")
        btn_bek.setObjectName("secondary")
        btn_bek.clicked.connect(self._browse_bek)
        sl.addWidget(self.ed_startup, 1)
        sl.addWidget(btn_bek)
        self._startup_label = QLabel("Startup key (.BEK):")
        form.addRow(self._startup_label, self._startup_widget)

        self.ed_fvek = QLineEdit()
        self.ed_fvek.setPlaceholderText(
            "advanced — raw full-volume encryption key as hex"
        )
        form.addRow("FVEK / master key (hex):", self.ed_fvek)
        root.addWidget(box)

        # show only the fields relevant to this encryption type
        if kind == LUKS:
            self._row_recovery_label.setVisible(False)
            self.ed_recovery.setVisible(False)
            self._startup_label.setVisible(False)
            self._startup_widget.setVisible(False)
        elif kind == FILEVAULT:
            self._startup_label.setVisible(False)
            self._startup_widget.setVisible(False)

        # buttons
        btns = QDialogButtonBox()
        self.btn_unlock = btns.addButton("Unlock && Continue",
                                         QDialogButtonBox.AcceptRole)
        self.btn_skip = btns.addButton("Skip this volume",
                                       QDialogButtonBox.DestructiveRole)
        btns.addButton(QDialogButtonBox.Cancel)
        self.btn_unlock.clicked.connect(self._on_unlock)
        self.btn_skip.clicked.connect(self._on_skip)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    # ---- handlers ------------------------------------------------------

    def _browse_bek(self):
        p, _ = QFileDialog.getOpenFileName(
            self, "Select BitLocker startup-key file", str(Path.home()),
            "BitLocker startup key (*.BEK *.bek);;All files (*.*)",
        )
        if p:
            self.ed_startup.setText(p)

    def _on_unlock(self):
        self._skip = False
        self.accept()

    def _on_skip(self):
        self._skip = True
        self.accept()

    # ---- results -------------------------------------------------------

    def result_skip(self) -> bool:
        return self._skip

    def credentials(self) -> Credentials:
        return Credentials(
            password=self.ed_password.text().strip(),
            recovery_password=self.ed_recovery.text().strip(),
            startup_key_path=self.ed_startup.text().strip(),
            fvek_hex=self.ed_fvek.text().strip().replace(" ", ""),
        )
