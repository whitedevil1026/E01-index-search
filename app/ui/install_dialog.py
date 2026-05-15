"""Install Missing dependencies dialog.

Runs `python -m pip install <args>` via QProcess after explicit user
confirmation. Streams stdout/stderr live into a console widget and
re-probes deps when finished so the parent panel can refresh.

For packages that have no published Windows wheel on PyPI (currently
`pytsk3` and `python-tlsh`), the repo bundles pre-built .whl files in
`try1/wheels/`. The install command always passes `--find-links` to
that directory so pip picks the bundled wheel up automatically — no
compiler needed.
"""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QProcess, Qt, Signal
from PySide6.QtGui import QGuiApplication, QTextCursor
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QGroupBox, QHBoxLayout,
    QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from app.core.deps import Dep


# The folder that ships pre-built wheels for the C-extension deps that
# don't have Windows binaries on PyPI. Resolved relative to the
# try1/ root (two levels up from this file).
BUNDLED_WHEELS_DIR = (Path(__file__).resolve().parent.parent.parent / "wheels").resolve()


def bundled_wheel_names() -> list[str]:
    if not BUNDLED_WHEELS_DIR.is_dir():
        return []
    return sorted(p.name for p in BUNDLED_WHEELS_DIR.glob("*.whl"))


class InstallDialog(QDialog):
    """Modal installer dialog. Emits `closed_after_install` on accept."""
    closed_after_install = Signal()

    def __init__(self, missing: list[Dep], parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Install missing dependencies")
        self.setMinimumSize(780, 560)
        self.setStyleSheet(parent.styleSheet() if parent else "")
        self._missing = missing
        self._proc: QProcess | None = None
        self._queue: list[Dep] = []
        self._current: Dep | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(12)

        head = QLabel("Install missing Python packages")
        head.setObjectName("h1")
        root.addWidget(head)

        wheels = bundled_wheel_names()
        wheels_note = ""
        if wheels:
            wheels_note = (
                "<br><br><b>Bundled wheels available</b> "
                f"({len(wheels)} file(s) in <code>./wheels/</code>): "
                + ", ".join(f"<code>{w}</code>" for w in wheels)
                + ". These will be used automatically &mdash; no compiler needed."
            )
        else:
            wheels_note = (
                "<br><br><i>No bundled wheels detected. C-extension packages "
                "may require Microsoft C++ Build Tools to compile from source.</i>"
            )

        intro = QLabel(
            "These will be installed via <code>python -m pip install</code> using "
            "the same Python interpreter that runs this app:<br>"
            f"<code>{sys.executable}</code><br><br>"
            "No admin rights needed &mdash; packages install to the user's "
            "site-packages. Nothing is run until you click <b>Install Now</b>."
            + wheels_note
        )
        intro.setObjectName("muted")
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.RichText)
        root.addWidget(intro)

        # ---- selection box ----------------------------------------------
        sel_box = QGroupBox("Select which to install")
        sel_layout = QVBoxLayout(sel_box)
        self._checks: list[tuple[QCheckBox, Dep]] = []
        for d in missing:
            row = QHBoxLayout()
            cb = QCheckBox(f"{d.name}    ({' '.join(d.pip_args)})")
            cb.setChecked(True)
            row.addWidget(cb)
            row.addStretch(1)
            sel_layout.addLayout(row)
            if d.notes:
                note = QLabel(f"    ⚠ {d.notes}")
                note.setObjectName("muted")
                note.setWordWrap(True)
                sel_layout.addWidget(note)
            self._checks.append((cb, d))
        root.addWidget(sel_box)

        # ---- action row -------------------------------------------------
        act = QHBoxLayout()
        self.btn_install = QPushButton("Install Now")
        self.btn_install.clicked.connect(self._start_install)
        self.btn_copy = QPushButton("Copy pip commands")
        self.btn_copy.setObjectName("secondary")
        self.btn_copy.clicked.connect(self._copy_commands)
        self.btn_cancel = QPushButton("Cancel running install")
        self.btn_cancel.setObjectName("danger")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel)
        act.addWidget(self.btn_install)
        act.addWidget(self.btn_copy)
        act.addStretch(1)
        act.addWidget(self.btn_cancel)
        root.addLayout(act)

        # ---- console ----------------------------------------------------
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(5000)
        self.console.setPlaceholderText("pip output will stream here…")
        self.console.setStyleSheet(
            "QPlainTextEdit { font-family: 'Consolas','Courier New',monospace; "
            "font-size: 9pt; background: #0a0c10; color: #d4d4d4; }"
        )
        root.addWidget(self.console, 1)

        # ---- footer -----------------------------------------------------
        foot = QDialogButtonBox(QDialogButtonBox.Close)
        foot.rejected.connect(self.reject)
        foot.accepted.connect(self.accept)
        self.btn_close = foot.button(QDialogButtonBox.Close)
        root.addWidget(foot)

    # ---- helpers ---------------------------------------------------------

    def _selected(self) -> list[Dep]:
        return [d for cb, d in self._checks if cb.isChecked()]

    def _copy_commands(self) -> None:
        cmds = [d.install_hint for d in self._selected()]
        if not cmds:
            return
        QGuiApplication.clipboard().setText("\n".join(cmds))
        self._write_console("\n# copied to clipboard:\n" + "\n".join(cmds) + "\n")

    def _write_console(self, text: str) -> None:
        self.console.moveCursor(QTextCursor.End)
        self.console.insertPlainText(text)
        self.console.moveCursor(QTextCursor.End)

    # ---- install lifecycle ----------------------------------------------

    def _start_install(self) -> None:
        sel = self._selected()
        if not sel:
            self._write_console("# nothing selected\n")
            return
        self._queue = list(sel)
        self._current = None
        self.btn_install.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_close.setEnabled(False)
        self._next()

    def _next(self) -> None:
        if not self._queue:
            self._write_console("\n# ───── all done ─────\n")
            self.btn_install.setEnabled(True)
            self.btn_cancel.setEnabled(False)
            self.btn_close.setEnabled(True)
            self.closed_after_install.emit()
            return
        self._current = self._queue.pop(0)
        d = self._current
        args = ["-m", "pip", "install", "--disable-pip-version-check"]
        # Use bundled wheels (./wheels/) when available so users on a
        # fresh machine don't need MSVC Build Tools just to compile
        # pytsk3 / python-tlsh from source.
        if BUNDLED_WHEELS_DIR.is_dir() and any(BUNDLED_WHEELS_DIR.glob("*.whl")):
            args.extend(["--find-links", str(BUNDLED_WHEELS_DIR)])
        args.extend(d.pip_args)
        self._write_console(
            f"\n# ───── installing {d.name} ─────\n"
            f"$ \"{sys.executable}\" {' '.join(args)}\n"
        )
        proc = QProcess(self)
        proc.setProcessChannelMode(QProcess.MergedChannels)
        proc.readyReadStandardOutput.connect(self._on_stdout)
        proc.finished.connect(self._on_proc_finished)
        proc.errorOccurred.connect(self._on_proc_error)
        self._proc = proc
        proc.start(sys.executable, args)
        if not proc.waitForStarted(5000):
            self._write_console("# failed to start pip\n")
            self._on_proc_finished(-1, QProcess.CrashExit)

    def _on_stdout(self) -> None:
        if not self._proc:
            return
        data = bytes(self._proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        if data:
            self._write_console(data)

    def _on_proc_error(self, err) -> None:
        self._write_console(f"# QProcess error: {err}\n")

    def _on_proc_finished(self, exit_code: int, _status) -> None:
        d = self._current
        tag = "ok" if exit_code == 0 else f"FAILED ({exit_code})"
        self._write_console(f"# {d.name if d else '?'} → {tag}\n")
        if d and exit_code != 0 and d.notes:
            self._write_console(f"# hint: {d.notes}\n")
        self._proc = None
        self._current = None
        self._next()

    def _cancel(self) -> None:
        if self._proc:
            self._write_console("# cancel requested — killing pip\n")
            self._proc.kill()
        self._queue.clear()
