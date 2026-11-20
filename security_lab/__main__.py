"""Entry point: python -m security_lab (from the project root).

Absolute import (not relative): PyInstaller runs this file as a
top-level script, where relative imports would fail.
"""

from security_lab.gui.main import main

if __name__ == "__main__":
    raise SystemExit(main())
