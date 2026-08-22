"""E01 Index & Search — application entry point."""
from __future__ import annotations

import sys

# Qt and the UI are imported inside main() on purpose. The raw sweep
# fans work out to worker processes, and on Windows those are spawned —
# each one re-imports this module to find the function it must run.
# Importing PySide6 and the whole UI at module scope would make every
# worker pay seconds of startup for code it never uses.


def main() -> int:
    from PySide6.QtWidgets import QApplication
    from app.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("E01 Index & Search")
    app.setOrganizationName("e01-index-search")

    win = MainWindow()
    # Default to a size that fits comfortably on a 1366x768 laptop
    # display (common minimum). The user can maximize for more.
    win.resize(1180, 720)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
