"""QThread base.

IMPORTANT: Never name a custom signal `finished` — it shadows
QThread.finished and causes a runtime crash on emit. We use `done`.
"""
from __future__ import annotations

from typing import Callable

from PySide6.QtCore import QThread, Signal


class Worker(QThread):
    progress = Signal(int, int, str)   # current, total, message
    log = Signal(str)
    done = Signal(bool, str)           # success, summary message
    error = Signal(str)

    def __init__(self, fn: Callable[["Worker"], tuple[bool, str]], parent=None):
        super().__init__(parent)
        self._fn = fn
        self._cancel = False

    def request_cancel(self) -> None:
        self._cancel = True

    @property
    def cancelled(self) -> bool:
        return self._cancel

    def run(self) -> None:  # noqa: D401
        try:
            ok, msg = self._fn(self)
            self.done.emit(bool(ok), str(msg))
        except Exception as exc:  # noqa: BLE001
            self.error.emit(f"{type(exc).__name__}: {exc}")
            self.done.emit(False, f"failed: {exc}")
