"""GhostWire hacker/terminal theme: near-black ground, neon-green ink, monospace.

The public constant *names* are kept identical to the original parchment theme
(``INK``, ``PARCHMENT``, ``RULE`` …) so every custom-painted widget in the GUI
re-skins automatically without touching its paint code.  Only the *values*
changed — sepia became matrix-green.
"""

# ---------------------------------------------------------------------------
# Core palette (new hacker names)
# ---------------------------------------------------------------------------
BG        = "#0a0e14"   # near-black window ground
BG_ALT    = "#0d1117"   # slightly lighter (tables / alt rows)
PANEL     = "#111722"   # raised panels / headers / cards
NEON      = "#00ff41"   # matrix green — primary text & accent
NEON_DIM  = "#12b23a"   # dimmer green
CYAN      = "#00e5ff"   # secondary accent (links, highlights)
AMBER     = "#ffb000"   # warnings
RED       = "#ff3b3b"   # alerts / critical
DIM       = "#213026"   # hairline rules / borders
GREEN_FAINT = "#4a7a5a"  # muted labels

# ---------------------------------------------------------------------------
# Legacy names -> remapped to hacker palette (imported across the GUI)
# ---------------------------------------------------------------------------
PARCHMENT      = BG
PARCHMENT_DARK = PANEL
INK            = NEON
INK_FAINT      = GREEN_FAINT
RULE           = DIM
ACCENT_BLUE    = CYAN
ACCENT_CORAL   = RED
ACCENT_OLIVE   = AMBER
SELECT_BG      = "#003b1a"
SELECT_FG      = NEON

FONT_FAMILY = '"JetBrains Mono","Cascadia Code","Menlo","Consolas","Courier New",monospace'

_BASE_QSS = f"""
QMainWindow, QWidget {{
    background-color: {BG};
    color: {NEON};
    font-family: {FONT_FAMILY};
    font-size: 13px;
}}

/* Tab Widget */
QTabWidget::pane {{
    border: 1px solid {DIM};
    background-color: {BG};
    top: -1px;
}}

QTabBar::tab {{
    background-color: {PANEL};
    color: {GREEN_FAINT};
    padding: 6px 18px;
    margin-right: 2px;
    border: 1px solid {DIM};
    border-bottom: none;
    font-family: {FONT_FAMILY};
    letter-spacing: 1px;
}}

QTabBar::tab:selected {{
    background-color: {BG};
    color: {NEON};
    border-bottom: 2px solid {NEON};
    font-weight: bold;
}}

QTabBar::tab:hover:!selected {{
    background-color: #16202c;
    color: {CYAN};
}}

/* Tables */
QTableWidget, QTableView {{
    background-color: {BG_ALT};
    alternate-background-color: {PANEL};
    color: {NEON};
    gridline-color: {DIM};
    border: 1px solid {DIM};
    selection-background-color: {SELECT_BG};
    selection-color: {NEON};
}}

QTableWidget::item, QTableView::item {{
    padding: 3px 6px;
}}

QTableWidget::item:hover, QTableView::item:hover {{
    background-color: #16202c;
}}

QHeaderView::section {{
    background-color: {PANEL};
    color: {CYAN};
    padding: 5px 8px;
    border: none;
    border-right: 1px solid {DIM};
    border-bottom: 1px solid {NEON_DIM};
    font-weight: bold;
    letter-spacing: 1px;
}}

QHeaderView::section:hover {{
    background-color: #16202c;
    color: {NEON};
}}

/* Buttons */
QPushButton {{
    background-color: {PANEL};
    color: {NEON};
    border: 1px solid {NEON_DIM};
    padding: 5px 16px;
    min-height: 18px;
    font-family: {FONT_FAMILY};
    letter-spacing: 1px;
}}

QPushButton:hover {{
    background-color: #04240f;
    color: {NEON};
    border: 1px solid {NEON};
}}

QPushButton:pressed {{
    background-color: {SELECT_BG};
    color: {CYAN};
    border: 1px solid {CYAN};
}}

QPushButton:disabled {{
    color: #2f4a38;
    background-color: {BG_ALT};
    border: 1px solid {DIM};
}}

QPushButton#startButton {{
    color: {NEON};
    border: 1px solid {NEON};
}}
QPushButton#startButton:hover {{
    background-color: #04240f;
}}
QPushButton#stopButton {{
    color: {RED};
    border: 1px solid #6e2323;
}}
QPushButton#stopButton:hover {{
    background-color: #2a0d0d;
    border: 1px solid {RED};
}}

/* ComboBox */
QComboBox {{
    background-color: {BG_ALT};
    color: {NEON};
    border: 1px solid {NEON_DIM};
    padding: 3px 6px;
    min-width: 140px;
}}

QComboBox:hover {{
    border: 1px solid {NEON};
}}

QComboBox::drop-down {{
    border-left: 1px solid {NEON_DIM};
    background-color: {PANEL};
    width: 18px;
}}

QComboBox QAbstractItemView {{
    background-color: {BG_ALT};
    color: {NEON};
    border: 1px solid {NEON_DIM};
    selection-background-color: {SELECT_BG};
    selection-color: {CYAN};
}}

/* CheckBox (Deep mode toggle) */
QCheckBox {{
    color: {NEON};
    spacing: 6px;
}}
QCheckBox::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {NEON_DIM};
    background: {BG_ALT};
}}
QCheckBox::indicator:checked {{
    background: {NEON};
    border: 1px solid {NEON};
}}

/* Scroll bars */
QScrollBar:vertical {{
    background-color: {BG_ALT};
    width: 12px;
    border-left: 1px solid {DIM};
}}

QScrollBar::handle:vertical {{
    background-color: {NEON_DIM};
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background-color: {NEON};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background-color: {BG_ALT};
    height: 12px;
    border-top: 1px solid {DIM};
}}

QScrollBar::handle:horizontal {{
    background-color: {NEON_DIM};
    min-width: 24px;
}}
QScrollBar::handle:horizontal:hover {{
    background-color: {NEON};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* Labels */
QLabel {{
    color: {NEON};
    background: transparent;
}}

QLabel#titleLabel {{
    font-family: {FONT_FAMILY};
    font-size: 26px;
    font-weight: bold;
    color: {NEON};
    letter-spacing: 3px;
}}

QLabel#subtitleLabel {{
    font-family: {FONT_FAMILY};
    font-size: 12px;
    color: {GREEN_FAINT};
    letter-spacing: 2px;
}}

QLabel#statValue {{
    font-family: {FONT_FAMILY};
    font-size: 22px;
    font-weight: bold;
    color: {NEON};
}}

QLabel#statLabel {{
    font-size: 10px;
    color: {GREEN_FAINT};
    letter-spacing: 1px;
}}

/* GroupBox */
QGroupBox {{
    background-color: {BG_ALT};
    border: 1px solid {DIM};
    margin-top: 14px;
    padding: 10px;
    padding-top: 22px;
    font-weight: bold;
    color: {CYAN};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    background-color: {BG};
    color: {CYAN};
    letter-spacing: 1px;
}}

/* TextEdit / PlainTextEdit */
QTextEdit, QPlainTextEdit {{
    background-color: {BG_ALT};
    color: {NEON};
    border: 1px solid {DIM};
    font-family: {FONT_FAMILY};
    font-size: 13px;
    padding: 6px;
    selection-background-color: {SELECT_BG};
    selection-color: {CYAN};
}}

/* Tree (packet detail / protocol hierarchy) */
QTreeWidget, QTreeView {{
    background-color: {BG_ALT};
    color: {NEON};
    border: 1px solid {DIM};
    selection-background-color: {SELECT_BG};
    selection-color: {CYAN};
    alternate-background-color: {PANEL};
}}
QTreeWidget::item {{ padding: 2px 4px; }}
QTreeWidget::item:hover {{ background-color: #16202c; }}
QTreeView::branch {{ background: {BG_ALT}; }}

/* Splitter */
QSplitter::handle {{
    background-color: {DIM};
}}

QSplitter::handle:horizontal {{ width: 2px; }}
QSplitter::handle:vertical {{ height: 2px; }}

/* StatusBar */
QStatusBar {{
    background-color: {PANEL};
    color: {NEON};
    border-top: 1px solid {NEON_DIM};
    font-size: 11px;
    font-family: {FONT_FAMILY};
}}

QStatusBar::item {{
    border: none;
}}

/* ToolTip */
QToolTip {{
    background-color: {PANEL};
    color: {NEON};
    border: 1px solid {NEON_DIM};
    padding: 3px 6px;
    font-family: {FONT_FAMILY};
}}

/* Line Edit */
QLineEdit {{
    background-color: {BG_ALT};
    color: {NEON};
    border: 1px solid {NEON_DIM};
    padding: 4px 6px;
    selection-background-color: {SELECT_BG};
}}
QLineEdit:focus {{
    border: 1px solid {NEON};
}}

/* Progress Bar */
QProgressBar {{
    background-color: {BG_ALT};
    border: 1px solid {DIM};
    text-align: center;
    color: {NEON};
    height: 14px;
}}

QProgressBar::chunk {{
    background-color: {NEON};
}}

/* Menu */
QMenuBar {{
    background-color: {PANEL};
    color: {NEON};
    border-bottom: 1px solid {DIM};
}}

QMenuBar::item:selected {{
    background-color: {SELECT_BG};
    color: {CYAN};
}}

QMenu {{
    background-color: {BG_ALT};
    color: {NEON};
    border: 1px solid {NEON_DIM};
}}

QMenu::item {{
    padding: 5px 24px;
}}

QMenu::item:selected {{
    background-color: {SELECT_BG};
    color: {CYAN};
}}

QMenu::separator {{
    height: 1px;
    background-color: {DIM};
    margin: 2px 4px;
}}

QFrame#statCard {{
    background-color: {PANEL};
    border: 1px solid {DIM};
}}
QFrame#statCard:hover {{
    border: 1px solid {NEON_DIM};
}}
"""

# ---------------------------------------------------------------------------
# Colour schemes: (primary, secondary, dim). Primary replaces the neon accent,
# secondary the cyan accent, dim the darker-green border colour.
# ---------------------------------------------------------------------------
SCHEMES = {
    "neon-green": (NEON, CYAN, NEON_DIM),
    "amber":      ("#ffb000", "#ffd166", "#a6741f"),
    "cyan":       ("#00e5ff", "#7affb0", "#128a99"),
    "red":        ("#ff4d4d", "#ff9f43", "#992e2e"),
    "purple":     ("#b088ff", "#e056fd", "#6a4fa0"),
    "mono":       ("#d0d0d0", "#9aa0a6", "#5a5a5a"),
}


def build_qss(scheme: str = "neon-green", font_size: int = 13, extra: str = "") -> str:
    """Return the full stylesheet recoloured for ``scheme`` at ``font_size``.

    Implemented as targeted hex substitutions on the base (neon-green) sheet so
    the large QSS body stays in one place.
    """
    primary, secondary, dim = SCHEMES.get(scheme, SCHEMES["neon-green"])
    qss = _BASE_QSS
    if scheme != "neon-green":
        qss = qss.replace(NEON_DIM, dim).replace(NEON, primary).replace(CYAN, secondary)
    if font_size != 13:
        qss = qss.replace("font-size: 13px;", f"font-size: {font_size}px;")
    return qss + (extra or "")


def scheme_accents(scheme: str = "neon-green"):
    """(primary, secondary) accent colours for a scheme — used by painters."""
    primary, secondary, _dim = SCHEMES.get(scheme, SCHEMES["neon-green"])
    return primary, secondary


# Name kept for backwards-compat with main_window import.
CLASSIC_THEME = _BASE_QSS
DARK_THEME = _BASE_QSS

# ---------------------------------------------------------------------------
# Protocol colours — neon palette
# ---------------------------------------------------------------------------
PROTOCOL_COLORS = {
    "ARP":       "#00ff41",
    "DHCP":      "#00e5ff",
    "DHCPv6":    "#3ad0ff",
    "mDNS":      "#ffb000",
    "SSDP":      "#c8a2ff",
    "NetBIOS":   "#ff6b9d",
    "LLMNR":     "#7affb0",
    "DNS":       "#5ec8ff",
    "LLDP":      "#ffd166",
    "IPv6-ND":   "#b088ff",
    "TLS":       "#ff3b3b",
    "HTTP":      "#ff9f43",
    "QUIC":      "#e056fd",
    "CDP":       "#48dbfb",
    "STP":       "#8395a7",
    "WSD":       "#f6e58d",
    "SNMP":      "#badc58",
    "NTP":       "#7ed6df",
    "ICMP":      "#ff7979",
    "IGMP":      "#eb4d4b",
    "TCP":       "#22a6b3",
    "UDP":       "#6ab04c",
}

DEVICE_TYPE_ICONS = {
    "Router/AP":          "[RTR]",
    "Router":             "[RTR]",
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


def risk_color(score: int) -> str:
    """Map a 0-100 risk score to a neon->amber->red colour."""
    if score >= 70:
        return RED
    if score >= 40:
        return AMBER
    if score >= 15:
        return "#d4ff00"
    return NEON


def severity_color(severity: str) -> str:
    return {
        "critical": RED,
        "warn": AMBER,
        "warning": AMBER,
        "info": CYAN,
    }.get((severity or "").lower(), NEON)
