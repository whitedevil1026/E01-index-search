"""Helpers that show QMessageBox / QDialog properly centered on parent.

In PySide6/Qt 6 on Windows, modal dialogs don't always pick up the
parent's geometry for positioning — they end up near the cursor or on
the wrong monitor. These helpers force the dialog to centre over the
parent window's current screen rectangle.
"""
from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QMessageBox, QWidget


def _center_on_parent(dlg: QDialog | QMessageBox, parent: Optional[QWidget]) -> None:
    if parent is None:
        return
    # Force the dialog to compute its layout so sizeHint() is accurate.
    dlg.adjustSize()
    parent_geo = parent.frameGeometry()
    parent_center = parent_geo.center()
    dlg_geo = dlg.frameGeometry()
    dlg_geo.moveCenter(parent_center)

    # On multi-monitor setups, Qt sometimes opens the popup on the
    # primary screen rather than the parent's. Clamp the target rect to
    # the parent screen's available geometry to keep the popup on the
    # same monitor as the main window.
    try:
        screen = parent.screen() if hasattr(parent, "screen") else None
        if screen is not None:
            avail = screen.availableGeometry()
            tl = dlg_geo.topLeft()
            x = max(avail.left(),
                    min(tl.x(), avail.right() - dlg_geo.width()))
            y = max(avail.top(),
                    min(tl.y(), avail.bottom() - dlg_geo.height()))
            dlg.move(x, y)
            return
    except Exception:
        pass
    dlg.move(dlg_geo.topLeft())


def msg_info(parent, title: str, text: str) -> None:
    mb = QMessageBox(QMessageBox.Information, title, text, QMessageBox.Ok, parent)
    mb.setWindowModality(Qt.WindowModal)
    _center_on_parent(mb, parent)
    mb.exec()


def msg_warn(parent, title: str, text: str) -> None:
    mb = QMessageBox(QMessageBox.Warning, title, text, QMessageBox.Ok, parent)
    mb.setWindowModality(Qt.WindowModal)
    _center_on_parent(mb, parent)
    mb.exec()


def msg_error(parent, title: str, text: str) -> None:
    mb = QMessageBox(QMessageBox.Critical, title, text, QMessageBox.Ok, parent)
    mb.setWindowModality(Qt.WindowModal)
    _center_on_parent(mb, parent)
    mb.exec()


def msg_question(parent, title: str, text: str,
                 default: int = QMessageBox.Yes) -> int:
    mb = QMessageBox(QMessageBox.Question, title, text,
                     QMessageBox.Yes | QMessageBox.No, parent)
    mb.setDefaultButton(default)
    mb.setWindowModality(Qt.WindowModal)
    _center_on_parent(mb, parent)
    return mb.exec()


def show_centered(dlg: QDialog, parent: Optional[QWidget]) -> int:
    """Use for a QDialog you've constructed yourself."""
    dlg.setWindowModality(Qt.WindowModal)
    _center_on_parent(dlg, parent)
    return dlg.exec()
