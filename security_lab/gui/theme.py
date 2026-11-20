"""Dark theme + severity colours for the desktop UI."""

SEVERITY_COLORS = {
    "Critical": "#ff4d4f",
    "High": "#ff7a45",
    "Medium": "#faad14",
    "Low": "#52c41a",
    "Informational": "#8c8c8c",
}

STATUS_COLORS = {
    "pass": "#52c41a",
    "fail": "#ff4d4f",
    "warn": "#faad14",
    "skipped": "#8c8c8c",
}

DARK_STYLESHEET = """
QWidget { background-color: #141414; color: #e6e6e6;
  font-family: "Segoe UI", Arial, sans-serif; font-size: 13px; }
QMainWindow::separator { background: #2a2a2a; width: 1px; }
QListWidget { background: #1a1a1a; border: none; outline: none; }
QListWidget::item { padding: 10px 12px; border-radius: 6px; }
QListWidget::item:selected { background: #2f6fed; color: white; }
QPushButton { background: #2f6fed; color: white; border: none;
  border-radius: 6px; padding: 7px 14px; }
QPushButton:hover { background: #3d7bff; }
QPushButton:disabled { background: #3a3a3a; color: #888; }
QPushButton#danger { background: #a61e1e; }
QPushButton#secondary { background: #2a2a2a; border: 1px solid #444; }
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {
  background: #1f1f1f; border: 1px solid #444; border-radius: 6px;
  padding: 6px; selection-background-color: #2f6fed; }
QTableWidget { background: #1a1a1a; gridline-color: #333;
  selection-background-color: #2f6fed; }
QHeaderView::section { background: #222; border: 1px solid #333; padding: 6px; }
QProgressBar { border: 1px solid #444; border-radius: 6px; text-align: center; }
QProgressBar::chunk { background: #2f6fed; border-radius: 6px; }
QGroupBox { border: 1px solid #333; border-radius: 8px; margin-top: 12px;
  padding-top: 16px; font-weight: bold; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; color: #aaa; }
QTabWidget::pane { border: 1px solid #333; }
QLabel#heading { font-size: 18px; font-weight: bold; }
QLabel#muted { color: #aaa; }
"""


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity, "#8c8c8c")
