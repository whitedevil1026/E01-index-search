"""Reusable 'files exported' dialog with copy + open buttons per row.

Standard QMessageBox uses a non-selectable label which makes file paths
uncopyable. This dialog renders each path as a read-only QLineEdit so
the examiner can select / copy, plus a one-click 'Copy' button and an
'Open' button (launches the OS default handler).
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QVBoxLayout, QWidget,
)


class ExportedDialog(QDialog):
    """Show a list of exported file paths. Each path is selectable, with
    Copy + Open buttons. Includes a 'Copy all paths' bottom action.

    Usage:
        dlg = ExportedDialog(self, title='Integrity reports exported',
                             intro='Wrote 2 files:', paths=[p1, p2])
        dlg.exec()
    """

    def __init__(self, parent=None, *, title: str = "Exported",
                 intro: str = "Wrote the following file(s):",
                 paths: list[str | Path] | None = None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(620)
        self.setStyleSheet(parent.styleSheet() if parent else "")
        self._paths = [str(p) for p in (paths or [])]

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 14)
        root.setSpacing(10)

        head = QLabel(title)
        head.setObjectName("h1")
        root.addWidget(head)

        lbl = QLabel(intro)
        lbl.setObjectName("muted")
        lbl.setWordWrap(True)
        root.addWidget(lbl)

        for p in self._paths:
            root.addWidget(self._make_row(p))

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("color: #2a2d35;")
        root.addWidget(sep)

        bottom = QHBoxLayout()
        btn_copy_all = QPushButton("Copy all paths")
        btn_copy_all.setObjectName("secondary")
        btn_copy_all.clicked.connect(self._copy_all)
        btn_open_folder = QPushButton("Open containing folder")
        btn_open_folder.setObjectName("secondary")
        btn_open_folder.clicked.connect(self._open_folder)
        bottom.addWidget(btn_copy_all)
        bottom.addWidget(btn_open_folder)
        bottom.addStretch(1)

        btns = QDialogButtonBox(QDialogButtonBox.Ok)
        btns.accepted.connect(self.accept)
        bottom.addWidget(btns)
        root.addLayout(bottom)

    # ---- helpers --------------------------------------------------------

    def _make_row(self, path: str) -> QWidget:
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        edit = QLineEdit(path)
        edit.setReadOnly(True)
        edit.setStyleSheet(
            "QLineEdit { font-family: 'Consolas','Courier New',monospace; "
            "background:#1a1d24; padding:6px; }"
        )
        edit.setCursorPosition(0)
        btn_copy = QPushButton("Copy")
        btn_copy.setObjectName("secondary")
        btn_copy.setFixedWidth(70)
        btn_copy.clicked.connect(lambda _, t=path: self._copy_one(t, btn_copy))
        btn_open = QPushButton("Open")
        btn_open.setObjectName("secondary")
        btn_open.setFixedWidth(70)
        btn_open.clicked.connect(lambda _, t=path: self._open_path(t))
        row.addWidget(edit, 1)
        row.addWidget(btn_copy)
        row.addWidget(btn_open)
        return w

    def _copy_one(self, text: str, btn: QPushButton) -> None:
        QGuiApplication.clipboard().setText(text)
        old = btn.text()
        btn.setText("Copied")
        btn.setEnabled(False)
        from PySide6.QtCore import QTimer
        QTimer.singleShot(800, lambda: (btn.setText(old), btn.setEnabled(True)))

    def _copy_all(self) -> None:
        QGuiApplication.clipboard().setText("\n".join(self._paths))

    def _open_path(self, path: str) -> None:
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception:
            pass

    def _open_folder(self) -> None:
        if not self._paths:
            return
        folder = str(Path(self._paths[0]).parent)
        self._open_path(folder)
