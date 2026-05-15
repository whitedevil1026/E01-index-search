"""E01 Indexing Tool — try1 entry point."""
from __future__ import annotations

import sys
from PySide6.QtWidgets import QApplication

from app.ui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("E01 Indexing Tool")
    app.setOrganizationName("e01-indexing")

    win = MainWindow()
    # Default to a size that fits comfortably on a 1366x768 laptop
    # display (common minimum). The user can maximize for more.
    win.resize(1180, 720)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
