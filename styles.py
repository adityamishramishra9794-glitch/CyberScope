"""Shared colours and stylesheets."""
SEVERITY_COLORS = {"Informational": "#607D8B", "Low": "#2E86C1", "Medium": "#D68910",
                   "High": "#D35400", "Critical": "#B00020"}
CONFIDENCE_COLORS = {"High": "#2E7D32", "Medium": "#D68910", "Low": "#8E8E93"}


def badge_html(text: str, color: str) -> str:
    return (f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:8px;'
            f'font-weight:600;">{text}</span>')


def build_stylesheet(theme: str) -> str:
    dark = theme == "dark"
    bg, panel, text, muted, border = (("#14181F", "#1D232D", "#E6EAF0", "#9AA5B5", "#2E3745") if dark
                                      else ("#F4F6F9", "#FFFFFF", "#1B2430", "#5B6676", "#D5DBE3"))
    accent = "#3D8BFD" if dark else "#1F5FBF"
    return f"""
    QWidget {{ background: {bg}; color: {text}; font-size: 13px; }}
    QFrame#card, QGroupBox {{ background: {panel}; border: 1px solid {border}; border-radius: 8px; }}
    QGroupBox {{ margin-top: 14px; padding: 10px; font-weight: 600; }}
    QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; background: transparent; }}
    QLabel#title {{ font-size: 22px; font-weight: 700; background: transparent; }}
    QLabel#subtitle, QLabel#muted {{ color: {muted}; background: transparent; }}
    QLabel#cardNumber {{ font-size: 28px; font-weight: 700; background: transparent; }}
    QLabel#warning {{ background: #FFF4E5; color: #7A4B00; border: 1px solid #F0C36D; border-radius: 6px; padding: 8px; }}
    QListWidget#nav {{ background: {panel}; border: none; border-right: 1px solid {border}; font-size: 14px; }}
    QListWidget#nav::item {{ padding: 12px 16px; }}
    QListWidget#nav::item:selected {{ background: {accent}; color: #FFFFFF; }}
    QPushButton {{ background: {accent}; color: #FFFFFF; border: none; border-radius: 6px; padding: 7px 14px; font-weight: 600; }}
    QPushButton:hover {{ background: {accent}CC; }}
    QPushButton:disabled {{ background: {border}; color: {muted}; }}
    QPushButton#danger {{ background: #C0392B; }}
    QPushButton#secondary {{ background: transparent; color: {accent}; border: 1px solid {accent}; }}
    QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextBrowser, QListWidget, QTableWidget {{
        background: {panel}; border: 1px solid {border}; border-radius: 6px; padding: 4px; }}
    QHeaderView::section {{ background: {panel}; color: {muted}; border: none; border-bottom: 1px solid {border}; padding: 6px; font-weight: 600; }}
    QTableWidget {{ gridline-color: {border}; alternate-background-color: {bg}; }}
    QProgressBar {{ border: 1px solid {border}; border-radius: 6px; text-align: center; background: {panel}; }}
    QProgressBar::chunk {{ background: {accent}; border-radius: 5px; }}
    QToolTip {{ background: {panel}; color: {text}; border: 1px solid {border}; }}
    """
