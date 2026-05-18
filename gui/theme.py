"""Nightingale-inspired theme: parchment ground, sepia ink, Times New Roman."""

PARCHMENT      = "#f4ead0"
PARCHMENT_DARK = "#ebdfb8"
INK            = "#3a2818"
INK_FAINT      = "#7a6244"
RULE           = "#8a6f4a"
ACCENT_BLUE    = "#8da7b3"   # "Disease"      (per Nightingale 1858)
ACCENT_CORAL   = "#c87864"   # "Wounds"
ACCENT_OLIVE   = "#6e6a4c"   # "Other Causes"
SELECT_BG      = "#c8b894"
SELECT_FG      = "#2a1c0c"

FONT_FAMILY = '"Times New Roman", "Times", serif'

CLASSIC_THEME = f"""
QMainWindow, QWidget {{
    background-color: {PARCHMENT};
    color: {INK};
    font-family: {FONT_FAMILY};
    font-size: 13px;
}}

/* Tab Widget */
QTabWidget::pane {{
    border: 1px solid {RULE};
    background-color: {PARCHMENT};
}}

QTabBar::tab {{
    background-color: {PARCHMENT_DARK};
    color: {INK};
    padding: 5px 18px;
    margin-right: 2px;
    border: 1px solid {RULE};
    border-bottom: none;
}}

QTabBar::tab:selected {{
    background-color: {PARCHMENT};
    border-bottom: 1px solid {PARCHMENT};
    font-weight: bold;
}}

QTabBar::tab:hover:!selected {{
    background-color: #e8dab0;
}}

/* Tables */
QTableWidget, QTableView {{
    background-color: {PARCHMENT};
    alternate-background-color: {PARCHMENT_DARK};
    color: {INK};
    gridline-color: {RULE};
    border: 1px solid {RULE};
    selection-background-color: {SELECT_BG};
    selection-color: {SELECT_FG};
}}

QTableWidget::item, QTableView::item {{
    padding: 3px 6px;
}}

QHeaderView::section {{
    background-color: {PARCHMENT_DARK};
    color: {INK};
    padding: 4px 8px;
    border: none;
    border-right: 1px solid {RULE};
    border-bottom: 1px solid {RULE};
    font-weight: bold;
}}

QHeaderView::section:hover {{
    background-color: #e8dab0;
}}

/* Buttons */
QPushButton {{
    background-color: {PARCHMENT_DARK};
    color: {INK};
    border: 1px solid {RULE};
    padding: 4px 16px;
    min-height: 18px;
    font-family: {FONT_FAMILY};
}}

QPushButton:hover {{
    background-color: #e8dab0;
}}

QPushButton:pressed {{
    background-color: {SELECT_BG};
    color: {SELECT_FG};
}}

QPushButton:disabled {{
    color: {INK_FAINT};
    background-color: {PARCHMENT};
}}

/* ComboBox */
QComboBox {{
    background-color: {PARCHMENT};
    color: {INK};
    border: 1px solid {RULE};
    padding: 2px 6px;
    min-width: 140px;
}}

QComboBox::drop-down {{
    border-left: 1px solid {RULE};
    background-color: {PARCHMENT_DARK};
    width: 18px;
}}

QComboBox QAbstractItemView {{
    background-color: {PARCHMENT};
    color: {INK};
    border: 1px solid {RULE};
    selection-background-color: {SELECT_BG};
    selection-color: {SELECT_FG};
}}

/* Scroll bars */
QScrollBar:vertical {{
    background-color: {PARCHMENT_DARK};
    width: 14px;
    border-left: 1px solid {RULE};
}}

QScrollBar::handle:vertical {{
    background-color: {INK_FAINT};
    border: 1px solid {RULE};
    min-height: 24px;
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background-color: {PARCHMENT_DARK};
    height: 14px;
    border-top: 1px solid {RULE};
}}

QScrollBar::handle:horizontal {{
    background-color: {INK_FAINT};
    border: 1px solid {RULE};
    min-width: 24px;
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* Labels */
QLabel {{
    color: {INK};
    background: transparent;
}}

QLabel#titleLabel {{
    font-family: {FONT_FAMILY};
    font-size: 30px;
    font-weight: bold;
    color: {INK};
    letter-spacing: 1px;
}}

QLabel#subtitleLabel {{
    font-family: {FONT_FAMILY};
    font-size: 13px;
    color: {INK_FAINT};
}}

QLabel#statValue {{
    font-family: {FONT_FAMILY};
    font-size: 22px;
    font-weight: bold;
    color: {INK};
}}

QLabel#statLabel {{
    font-size: 11px;
    color: {INK_FAINT};
}}

/* GroupBox */
QGroupBox {{
    background-color: {PARCHMENT};
    border: 1px solid {RULE};
    margin-top: 14px;
    padding: 10px;
    padding-top: 22px;
    font-weight: bold;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    background-color: {PARCHMENT};
    color: {INK};
}}

/* TextEdit / PlainTextEdit */
QTextEdit, QPlainTextEdit {{
    background-color: {PARCHMENT};
    color: {INK};
    border: 1px solid {RULE};
    font-family: {FONT_FAMILY};
    font-size: 13px;
    padding: 6px;
}}

/* Splitter */
QSplitter::handle {{
    background-color: {RULE};
}}

QSplitter::handle:horizontal {{
    width: 1px;
}}

QSplitter::handle:vertical {{
    height: 1px;
}}

/* StatusBar */
QStatusBar {{
    background-color: {PARCHMENT_DARK};
    color: {INK};
    border-top: 1px solid {RULE};
    font-size: 11px;
}}

QStatusBar::item {{
    border: none;
}}

/* ToolTip */
QToolTip {{
    background-color: #fff6dc;
    color: {INK};
    border: 1px solid {RULE};
    padding: 3px 6px;
}}

/* Line Edit */
QLineEdit {{
    background-color: {PARCHMENT};
    color: {INK};
    border: 1px solid {RULE};
    padding: 3px 6px;
}}

/* Progress Bar */
QProgressBar {{
    background-color: {PARCHMENT};
    border: 1px solid {RULE};
    text-align: center;
    color: {INK};
    height: 14px;
}}

QProgressBar::chunk {{
    background-color: {ACCENT_CORAL};
}}

/* Menu */
QMenuBar {{
    background-color: {PARCHMENT_DARK};
    color: {INK};
    border-bottom: 1px solid {RULE};
}}

QMenuBar::item:selected {{
    background-color: {SELECT_BG};
    color: {SELECT_FG};
}}

QMenu {{
    background-color: {PARCHMENT};
    color: {INK};
    border: 1px solid {RULE};
}}

QMenu::item {{
    padding: 4px 24px;
}}

QMenu::item:selected {{
    background-color: {SELECT_BG};
    color: {SELECT_FG};
}}

QMenu::separator {{
    height: 1px;
    background-color: {RULE};
    margin: 2px 4px;
}}

QFrame#statCard {{
    background-color: {PARCHMENT_DARK};
    border: 1px solid {RULE};
}}
"""

DARK_THEME = CLASSIC_THEME

PROTOCOL_COLORS = {
    "ARP":      ACCENT_BLUE,
    "DHCP":     ACCENT_CORAL,
    "mDNS":     ACCENT_OLIVE,
    "SSDP":     "#b6916c",
    "NetBIOS":  "#9a4a3a",
    "LLMNR":    "#a4b6a0",
    "DNS":      "#5e7a8a",
    "LLDP":     "#7a5a3a",
    "IPv6-ND":  "#9c6e8a",
}

DEVICE_TYPE_ICONS = {
    "Router/AP":          "[RTR]",
    "Network Device":     "[NET]",
    "Computer":           "[PC]",
    "Computer (Apple)":   "[MAC]",
    "Mobile (Apple)":     "[iOS]",
    "Mobile (Samsung)":   "[MOB]",
    "Apple Device":       "[APL]",
    "Apple TV":           "[TV]",
    "Smart TV (Samsung)": "[TV]",
    "Samsung Device":     "[SAM]",
    "IoT / Smart Home":   "[IoT]",
    "Amazon IoT":         "[AMZ]",
    "Amazon Device":      "[AMZ]",
    "Google IoT":         "[GGL]",
    "Google Device":      "[GGL]",
    "Xiaomi Device":      "[XMI]",
    "Printer":            "[PRN]",
    "Raspberry Pi":       "[PI]",
    "Virtual Machine":    "[VM]",
    "Computer/NIC":       "[PC]",
    "AirPlay Device":     "[AIR]",
    "Broadcast":          "[BC]",
    "Unknown":            "[?]",
}
