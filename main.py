"""CyberScope V4 entry point.

  python main.py                         -> desktop GUI
  python main.py --cli TARGET --confirm-authorized [--json out.json] [--markdown out.md]
                                         -> headless scan (also used for smoke tests)
"""
from __future__ import annotations

import sys


def _missing(package: str) -> int:
    msg = (f"CyberScope needs the '{package}' package, which is not installed.\n"
           "Activate your virtual environment and run:  pip install -r requirements.txt")
    print(msg, file=sys.stderr)
    try:  # best effort pop-up for people who double-click the script
        import tkinter
        from tkinter import messagebox
        root = tkinter.Tk()
        root.withdraw()
        messagebox.showerror("CyberScope - missing dependency", msg)
    except Exception:
        pass
    return 2


def main(argv: list[str]) -> int:
    from config.logging_setup import setup_logging
    setup_logging()
    if "--cli" in argv:
        try:
            import requests  # noqa: F401
        except ImportError:
            return _missing("requests")
        from core.cli import run_cli
        return run_cli(argv)
    try:
        import requests  # noqa: F401
    except ImportError:
        return _missing("requests")
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        return _missing("PySide6")
    from gui.main_window import MainWindow
    app = QApplication(argv)
    app.setApplicationName("CyberScope V4")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
