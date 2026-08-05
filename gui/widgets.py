"""Reusable animated widgets for the GhostWire hacker UI.

Contents
--------
* ``GlowButton``       - QPushButton with an animated neon glow on hover.
* ``Sparkline``        - tiny neon line chart of the last N samples.
* ``AnimatedStatCard`` - stat card with count-up animation + embedded sparkline.
* ``PacketDetailTree`` - Wireshark-style layered dissection tree.
* ``HexView``          - hex + ASCII dump pane.
* ``GlitchLabel``      - title label with a subtle scanline/glitch shimmer.
* ``Toast``            - transient corner notification for critical alerts.
"""
from collections import deque

from PyQt5.QtWidgets import (
    QPushButton, QWidget, QFrame, QVBoxLayout, QLabel, QTreeWidget,
    QTreeWidgetItem, QGraphicsDropShadowEffect, QGraphicsOpacityEffect,
)
from PyQt5.QtCore import (
    Qt, QTimer, QPropertyAnimation, pyqtProperty, QVariantAnimation,
    QEasingCurve, QRectF, QPointF,
)
from PyQt5.QtGui import QPainter, QColor, QFont, QPen, QBrush, QPolygonF

from gui.theme import (
    BG, BG_ALT, PANEL, NEON, NEON_DIM, CYAN, AMBER, RED, DIM, GREEN_FAINT,
    FONT_FAMILY,
)


class GlowButton(QPushButton):
    """QPushButton that animates a neon drop-shadow glow when hovered."""

    def __init__(self, text="", parent=None, glow_color=NEON):
        super().__init__(text, parent)
        self._glow = QGraphicsDropShadowEffect(self)
        self._glow.setColor(QColor(glow_color))
        self._glow.setOffset(0, 0)
        self._glow.setBlurRadius(0)
        self.setGraphicsEffect(self._glow)
        self._anim = QPropertyAnimation(self._glow, b"blurRadius", self)
        self._anim.setDuration(220)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def _run(self, target):
        self._anim.stop()
        self._anim.setStartValue(self._glow.blurRadius())
        self._anim.setEndValue(target)
        self._anim.start()

    def enterEvent(self, event):
        self._run(22)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._run(0)
        super().leaveEvent(event)


class Sparkline(QWidget):
    """Minimal neon sparkline of the most recent samples."""

    def __init__(self, parent=None, maxlen=60, color=NEON):
        super().__init__(parent)
        self._data = deque(maxlen=maxlen)
        self._color = color
        self.setMinimumHeight(18)

    def push(self, value: float):
        self._data.append(float(value))
        self.update()

    def set_color(self, color: str):
        self._color = color
        self.update()

    def paintEvent(self, event):
        if len(self._data) < 2:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w, h = self.width(), self.height()
        lo = min(self._data)
        hi = max(self._data)
        rng = (hi - lo) or 1.0
        n = len(self._data)
        step = w / (n - 1)
        poly = QPolygonF()
        for i, v in enumerate(self._data):
            x = i * step
            y = h - 2 - ((v - lo) / rng) * (h - 4)
            poly.append(QPointF(x, y))
        # fill under curve
        fill = QPolygonF(poly)
        fill.append(QPointF(w, h))
        fill.append(QPointF(0, h))
        c = QColor(self._color)
        c.setAlpha(40)
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(c))
        p.drawPolygon(fill)
        # line
        pen = QPen(QColor(self._color))
        pen.setWidthF(1.4)
        p.setPen(pen)
        p.setBrush(Qt.NoBrush)
        p.drawPolyline(poly)
        p.end()


class AnimatedStatCard(QFrame):
    """Stat card with count-up value animation and an embedded sparkline."""

    def __init__(self, title: str, value: str = "0", parent=None, spark_color=NEON):
        super().__init__(parent)
        self.setObjectName("statCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(2)

        self._value_label = QLabel(value)
        self._value_label.setObjectName("statValue")
        self._value_label.setAlignment(Qt.AlignLeft)

        self._title_label = QLabel(title)
        self._title_label.setObjectName("statLabel")

        self._spark = Sparkline(color=spark_color)

        layout.addWidget(self._value_label)
        layout.addWidget(self._title_label)
        layout.addWidget(self._spark)

        self._current = 0
        self._suffix = ""
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(600)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim.valueChanged.connect(self._on_tick)

    def _on_tick(self, val):
        self._value_label.setText(f"{int(val):,}{self._suffix}")

    def set_value(self, value: str):
        """Accepts a plain string or a leading-number string.

        A value that *starts* with digits (``"1,234"``, ``"12 MB/s"``,
        ``"3m 20s"``) animates the numeric part and keeps the trailing text as a
        suffix. Anything else is shown verbatim.
        """
        text = str(value)
        num, suffix = _split_leading_number(text)
        if num is None:
            self._value_label.setText(text)
            return
        self._suffix = suffix
        self._anim.stop()
        self._anim.setStartValue(self._current)
        self._anim.setEndValue(num)
        self._anim.start()
        self._current = num
        self._spark.push(num)

    def push_spark(self, value: float):
        self._spark.push(value)

    def set_title(self, title: str):
        self._title_label.setText(title)


def _split_leading_number(text: str):
    """Return (int_value, suffix) if ``text`` starts with a number, else (None, '')."""
    i = 0
    while i < len(text) and (text[i].isdigit() or text[i] in ",."):
        i += 1
    head = text[:i].replace(",", "").rstrip(".")
    if not head or not head[0].isdigit():
        return None, ""
    try:
        return int(float(head)), text[i:]
    except ValueError:
        return None, ""


class PacketDetailTree(QTreeWidget):
    """Wireshark-style layered protocol dissection tree."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderHidden(True)
        self.setAlternatingRowColors(False)
        self.setAnimated(True)

    def show_layers(self, layers: list):
        """``layers`` is a list of (title, [(field, value), ...]) tuples."""
        self.clear()
        for title, fields in layers:
            top = QTreeWidgetItem([f"▸ {title}"])
            top.setForeground(0, QColor(CYAN))
            f = top.font(0)
            f.setBold(True)
            top.setFont(0, f)
            for name, value in fields:
                child = QTreeWidgetItem([f"{name}: {value}"])
                child.setForeground(0, QColor(NEON))
                top.addChild(child)
            self.addTopLevelItem(top)
            top.setExpanded(True)


class HexView(QWidget):
    """Hex + ASCII dump of raw packet bytes."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data = b""
        self._font = QFont("JetBrains Mono", 10)
        self._font.setStyleHint(QFont.Monospace)
        self.setMinimumHeight(120)

    def set_data(self, data: bytes):
        self._data = data or b""
        self.setMinimumHeight(max(120, (len(self._data) // 16 + 2) * 15))
        self.update()

    def paintEvent(self, event):
        from PyQt5.QtGui import QFontMetrics
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(BG_ALT))
        p.setFont(self._font)
        if not self._data:
            p.setPen(QColor(GREEN_FAINT))
            p.drawText(self.rect(), Qt.AlignCenter, "no packet selected")
            p.end()
            return
        cw = QFontMetrics(self._font).horizontalAdvance("0")
        hex_x = 8 + cw * 6                       # after the 4-hex offset column
        ascii_x = hex_x + cw * (16 * 3) + cw * 2  # after 16 "xx " groups + gap
        line_h = 15
        y = 14
        for off in range(0, len(self._data), 16):
            chunk = self._data[off:off + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            p.setPen(QColor(GREEN_FAINT))
            p.drawText(8, y, f"{off:04x}")
            p.setPen(QColor(NEON))
            p.drawText(hex_x, y, hex_part)
            p.setPen(QColor(CYAN))
            p.drawText(ascii_x, y, ascii_part)
            y += line_h
            if y > self.height():
                break
        p.end()


class GlitchLabel(QLabel):
    """Neon title label with a periodic subtle glitch/flicker."""

    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setObjectName("titleLabel")
        self._base = text
        self._glow = QGraphicsDropShadowEffect(self)
        self._glow.setColor(QColor(NEON))
        self._glow.setOffset(0, 0)
        self._glow.setBlurRadius(14)
        self.setGraphicsEffect(self._glow)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._pulse)
        self._timer.start(1400)
        self._up = True

    def _pulse(self):
        target = 22 if self._up else 10
        self._glow.setBlurRadius(target)
        self._up = not self._up


class Toast(QFrame):
    """Transient corner notification.

    Toasts **stack** vertically (managed per-parent) so simultaneous critical
    alerts don't pile up on the same spot, and they fade out via a
    ``QGraphicsOpacityEffect`` (which — unlike ``windowOpacity`` — actually
    animates a child widget).
    """

    # Per-parent-window list of live toasts, top (newest) first.
    _stacks = {}
    TOP_MARGIN = 70
    GAP = 8

    def __init__(self, parent, text: str, color=RED, timeout=4200):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setStyleSheet(
            f"background-color: {PANEL}; border: 1px solid {color};"
        )
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8)
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color: {color}; font-family: {FONT_FAMILY}; font-weight: bold;")
        lbl.setWordWrap(True)
        lay.addWidget(lbl)
        self.adjustSize()

        self._effect = QGraphicsOpacityEffect(self)
        self._effect.setOpacity(1.0)
        self.setGraphicsEffect(self._effect)

        stack = Toast._stacks.setdefault(parent, [])
        stack.insert(0, self)
        self._reflow(parent)

        QTimer.singleShot(timeout, self._fade_out)
        self.show()
        self.raise_()

    @classmethod
    def _reflow(cls, parent):
        if not parent:
            return
        y = cls.TOP_MARGIN
        for t in cls._stacks.get(parent, []):
            t.move(parent.width() - t.width() - 24, y)
            t.raise_()
            y += t.height() + cls.GAP

    def _fade_out(self):
        self._anim = QPropertyAnimation(self._effect, b"opacity", self)
        self._anim.setDuration(500)
        self._anim.setStartValue(1.0)
        self._anim.setEndValue(0.0)
        self._anim.finished.connect(self._remove)
        self._anim.start()

    def _remove(self):
        parent = self.parent()
        stack = Toast._stacks.get(parent)
        if stack and self in stack:
            stack.remove(self)
            Toast._reflow(parent)
        self.deleteLater()
