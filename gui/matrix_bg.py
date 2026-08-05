"""Matrix "digital rain" background widget.

A lightweight, self-throttling QWidget that paints falling columns of glyphs.
Designed to sit *behind* the main content as an ambient background: the leading
glyph of each column glows neon, the trailing glyphs fade to near-black.

Performance notes
------------------
* Runs at ~18 FPS normally, auto-throttled to ~8 FPS while a live capture is
  active (call :meth:`set_busy`) so it never competes with packet processing.
* The timer stops entirely when the widget is hidden or the window is inactive.
"""
import random
import time

from PyQt5.QtWidgets import QWidget
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPainter, QColor, QFont, QFontMetrics

from gui.theme import BG, NEON, NEON_DIM

# Glyphs: half-width katakana + hex digits + a few symbols (classic rain look).
_GLYPHS = (
    "アカサタナハマヤラワイキシチニヒミリウクスツヌフムユルエケセテネヘメレオコソトノホモヨロ"
    "0123456789ABCDEF<>[]{}/\\|=+*#$%&"
)


class _Column:
    __slots__ = ("head", "speed", "length", "glyphs", "tick")

    def __init__(self, rows: int):
        self.reset(rows, initial=True)

    def reset(self, rows: int, initial: bool = False):
        self.head = random.randint(-rows, 0) if initial else -random.randint(0, 6)
        self.speed = random.uniform(0.25, 0.9)
        self.length = random.randint(6, max(8, rows // 2))
        self.glyphs = [random.choice(_GLYPHS) for _ in range(rows + 4)]
        self.tick = 0.0


class MatrixRainWidget(QWidget):
    """Ambient falling-glyph background."""

    def __init__(self, parent=None, opacity: float = 0.55, font_size: int = 14):
        super().__init__(parent)
        # Purely decorative: never intercept mouse events meant for children.
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WA_NoSystemBackground, True)
        self._opacity = opacity
        self._color = NEON
        self._speed = 1.0
        self._density = 1.0
        self._font_size = font_size
        self._font = QFont("JetBrains Mono", font_size)
        self._font.setStyleHint(QFont.Monospace)
        fm = QFontMetrics(self._font)
        self._cell_w = max(8, fm.horizontalAdvance("M"))
        self._cell_h = max(10, fm.height())
        self._cols: list[_Column] = []
        self._rows = 1
        self._ncols = 1
        self._busy = False
        self._last = time.time()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._advance)
        self._interval_idle = 55   # ~18 fps
        self._interval_busy = 120  # ~8 fps
        self._timer.start(self._interval_idle)

    # -- external controls ---------------------------------------------------
    def set_busy(self, busy: bool):
        """Throttle the animation while a live capture is running."""
        if busy == self._busy:
            return
        self._busy = busy
        self._timer.setInterval(self._interval_busy if busy else self._interval_idle)

    def set_opacity(self, value: float):
        self._opacity = max(0.0, min(1.0, value))
        self.update()

    def apply_settings(self, s):
        """Bind matrix.* preferences (opacity/color/speed/density/font size)."""
        self._opacity = max(0.0, min(1.0, float(s.get("matrix.opacity", self._opacity))))
        self._color = s.get("matrix.color", self._color)
        self._speed = max(0.2, float(s.get("matrix.speed", 1.0)))
        self._density = max(0.2, float(s.get("matrix.density", 1.0)))
        fs = int(s.get("matrix.font_size", self._font_size))
        if fs != self._font_size:
            self._font_size = fs
            self._font = QFont("JetBrains Mono", fs)
            self._font.setStyleHint(QFont.Monospace)
            from PyQt5.QtGui import QFontMetrics
            fm = QFontMetrics(self._font)
            self._cell_w = max(8, fm.horizontalAdvance("M"))
            self._cell_h = max(10, fm.height())
            self.resizeEvent(None)
        self.update()

    # -- lifecycle -----------------------------------------------------------
    def showEvent(self, event):
        if not self._timer.isActive():
            self._timer.start()
        super().showEvent(event)

    def hideEvent(self, event):
        self._timer.stop()
        super().hideEvent(event)

    def resizeEvent(self, event):
        self._ncols = max(1, self.width() // self._cell_w + 1)
        self._rows = max(1, self.height() // self._cell_h + 1)
        self._cols = [_Column(self._rows) for _ in range(self._ncols)]
        if event is not None:
            super().resizeEvent(event)

    # -- simulation ----------------------------------------------------------
    def _advance(self):
        if not self.isVisible():
            return
        now = time.time()
        dt = min(0.1, now - self._last)
        self._last = now
        rows = self._rows
        for col in self._cols:
            col.tick += col.speed * self._speed * dt * 60.0
            if col.tick >= 1.0:
                steps = int(col.tick)
                col.tick -= steps
                col.head += steps
                # occasionally mutate a glyph for shimmer
                if random.random() < 0.3:
                    idx = random.randint(0, len(col.glyphs) - 1)
                    col.glyphs[idx] = random.choice(_GLYPHS)
                if col.head - col.length > rows:
                    col.reset(rows)
        self.update()

    # -- painting ------------------------------------------------------------
    def paintEvent(self, event):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(BG))
        p.setOpacity(self._opacity)
        p.setFont(self._font)

        head = QColor(self._color)
        trail = QColor(self._color).darker(160)
        # density < 1 draws fewer columns (skip every Nth)
        skip = max(1, int(round(1.0 / max(0.2, self._density)))) if self._density < 1.0 else 1
        cw, ch = self._cell_w, self._cell_h
        for cx, col in enumerate(self._cols):
            if skip > 1 and (cx % skip):
                continue
            x = cx * cw
            for i in range(col.length):
                row = col.head - i
                if row < 0 or row > self._rows:
                    continue
                y = row * ch + ch
                glyph = col.glyphs[row % len(col.glyphs)]
                if i == 0:
                    p.setPen(QColor("#eaffee"))  # bright head
                elif i == 1:
                    p.setPen(head)
                else:
                    fade = max(0, 255 - int(255 * (i / col.length)))
                    c = QColor(trail)
                    c.setAlpha(fade)
                    p.setPen(c)
                p.drawText(x, y, glyph)
        p.end()
