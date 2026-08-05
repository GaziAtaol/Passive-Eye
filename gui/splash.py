"""Boot splash screen with a terminal-style typing animation over matrix rain."""
from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QPropertyAnimation
from PyQt5.QtGui import QFont

from gui.matrix_bg import MatrixRainWidget
from gui.theme import BG, NEON, CYAN, GREEN_FAINT, FONT_FAMILY

_LOGO = r"""
   ________               __ _       __ _
  / ____/ /_  ____  _____/ /| |     / /(_)_______
 / / __/ __ \/ __ \/ ___/ __/ | /| / // / ___/ _ \
/ /_/ / / / / /_/ (__  ) /_ | |/ |/ // / /  /  __/
\____/_/ /_/\____/____/\__/ |__/|__//_/_/   \___/
        p a s s i v e   n e t w o r k   s c a n n e r
"""

_BOOT_LINES = [
    "> initializing GhostWire capture engine ...............  [ OK ]",
    "> loading OUI vendor database [1000+ vendors] .........  [ OK ]",
    "> registering protocol dissectors [22 parsers] ........  [ OK ]",
    "> arming passive anomaly sensors ......................  [ OK ]",
    "> mounting SQLite event store (WAL) ...................  [ OK ]",
    "> calibrating force-directed graph layout .............  [ OK ]",
    "> passive mode confirmed :: zero packets transmitted ..  [ OK ]",
    "",
    ">> ready. press any key or wait to enter console_",
]


class BootSplash(QWidget):
    """Frameless splash; emits :attr:`finished` when the sequence completes."""

    finished = pyqtSignal()

    def __init__(self, parent=None, auto_ms=2600):
        super().__init__(parent, Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setFixedSize(720, 460)
        self.setAttribute(Qt.WA_DeleteOnClose, True)

        self._rain = MatrixRainWidget(self, opacity=0.35, font_size=14)
        self._rain.setGeometry(0, 0, self.width(), self.height())

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 26, 40, 26)

        self._logo = QLabel(_LOGO)
        f = QFont("JetBrains Mono", 9)
        f.setStyleHint(QFont.Monospace)
        self._logo.setFont(f)
        self._logo.setStyleSheet(f"color: {NEON}; background: transparent;")
        self._logo.setAlignment(Qt.AlignHCenter)
        layout.addWidget(self._logo)
        layout.addStretch()

        self._console = QLabel("")
        cf = QFont("JetBrains Mono", 10)
        cf.setStyleHint(QFont.Monospace)
        self._console.setFont(cf)
        self._console.setStyleSheet(f"color: {CYAN}; background: transparent;")
        self._console.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self._console.setTextFormat(Qt.PlainText)
        self._console.setMinimumHeight(190)
        layout.addWidget(self._console)

        hint = QLabel("[ passive · read-only · non-intrusive ]")
        hint.setStyleSheet(f"color: {GREEN_FAINT}; background: transparent;")
        hint.setAlignment(Qt.AlignHCenter)
        layout.addWidget(hint)

        self.setStyleSheet(f"background-color: {BG};")

        self._line_idx = 0
        self._char_idx = 0
        self._shown = ""
        self._done = False

        self._typer = QTimer(self)
        self._typer.timeout.connect(self._type_step)
        self._typer.start(14)

        # Hard fallback so we never hang on the splash.
        QTimer.singleShot(auto_ms + 2500, self._complete)

    def _type_step(self):
        if self._line_idx >= len(_BOOT_LINES):
            self._typer.stop()
            QTimer.singleShot(500, self._complete)
            return
        line = _BOOT_LINES[self._line_idx]
        if self._char_idx <= len(line):
            visible = self._shown + line[:self._char_idx]
            self._console.setText(visible + "▊")
            self._char_idx += 1
        else:
            self._shown += line + "\n"
            self._line_idx += 1
            self._char_idx = 0

    def _complete(self):
        if self._done:
            return
        self._done = True
        self._typer.stop()
        self._anim = QPropertyAnimation(self, b"windowOpacity", self)
        self._anim.setDuration(400)
        self._anim.setStartValue(1.0)
        self._anim.setEndValue(0.0)
        self._anim.finished.connect(self._emit_done)
        self._anim.start()

    def _emit_done(self):
        self.finished.emit()
        self.close()

    def keyPressEvent(self, event):
        self._complete()

    def mousePressEvent(self, event):
        self._complete()
