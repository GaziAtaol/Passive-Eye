"""Bundled pixel-font loader (accent use only).

The app body stays in a monospace face for readability; a pixel font is applied
only to accents (title/logo, tab labels, stat-card labels, group-box titles,
splash). ``load_fonts`` must run after the QApplication exists.
"""
import os

from PyQt5.QtGui import QFontDatabase, QFont

_ASSET_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "fonts")

# Populated by load_fonts(); falls back to a generic monospace if loading fails.
PIXEL_FAMILY = "Courier New"
TERM_FAMILY = "Courier New"
_LOADED = False


def load_fonts() -> str:
    """Register bundled fonts and return the pixel-accent family name."""
    global PIXEL_FAMILY, TERM_FAMILY, _LOADED
    if _LOADED:
        return PIXEL_FAMILY
    _LOADED = True
    for fname, target in (("Silkscreen-Regular.ttf", "pixel"),
                          ("VT323-Regular.ttf", "term")):
        path = os.path.join(_ASSET_DIR, fname)
        if not os.path.isfile(path):
            continue
        fid = QFontDatabase.addApplicationFont(path)
        if fid < 0:
            continue
        fams = QFontDatabase.applicationFontFamilies(fid)
        if not fams:
            continue
        if target == "pixel":
            PIXEL_FAMILY = fams[0]
        else:
            TERM_FAMILY = fams[0]
    return PIXEL_FAMILY


def pixel_font(size: int = 11, bold: bool = False) -> QFont:
    f = QFont(PIXEL_FAMILY, size)
    f.setBold(bold)
    return f


def pixel_accent_qss(enabled: bool) -> str:
    """Extra stylesheet that applies the pixel font ONLY to accent widgets."""
    if not enabled:
        return ""
    fam = PIXEL_FAMILY
    # Applied to short accent labels only — NOT tab bars or tables, where the
    # wide pixel glyphs would clip longer (e.g. Turkish) strings.
    return f"""
    QGroupBox::title {{ font-family: "{fam}"; }}
    QLabel#titleLabel {{ font-family: "{fam}"; }}
    QLabel#statLabel {{ font-family: "{fam}"; letter-spacing: 1px; }}
    QMenuBar::item {{ font-family: "{fam}"; }}
    """
