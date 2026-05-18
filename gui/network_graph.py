"""Force-directed network graph of discovered devices."""
import math
import random
import time
from PyQt5.QtWidgets import QWidget
from PyQt5.QtCore import Qt, QPointF, QRectF, QTimer
from PyQt5.QtGui import QPainter, QPen, QBrush, QColor, QFont

from gui.theme import (
    PROTOCOL_COLORS, DEVICE_TYPE_ICONS,
    PARCHMENT, PARCHMENT_DARK, INK, INK_FAINT, RULE, ACCENT_CORAL,
)


class GraphNode:
    def __init__(self, mac, label="", device_type="", vendor=""):
        self.mac = mac
        self.label = label or mac
        self.device_type = device_type
        self.vendor = vendor
        self.x = random.uniform(-200, 200)
        self.y = random.uniform(-200, 200)
        self.vx = 0.0
        self.vy = 0.0
        self.radius = 20
        self.connections = {}  # mac -> weight
        self.is_router = "router" in device_type.lower() or "gateway" in device_type.lower()
        self.last_active = time.time()


class NetworkGraphWidget(QWidget):
    """Interactive force-directed network graph."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.nodes: dict = {}  # mac -> GraphNode
        self.setMinimumSize(400, 300)

        # Physics parameters
        self._repulsion = 5000
        self._attraction = 0.01
        self._damping = 0.85
        self._center_gravity = 0.01

        # View state
        self._zoom = 1.0
        self._offset_x = 0.0
        self._offset_y = 0.0
        self._dragging = False
        self._drag_start = QPointF()
        self._selected_node = None
        self._hover_node = None

        # Animation
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._physics_step)
        self._timer.start(33)  # ~30 FPS

        self.setMouseTracking(True)

    def update_device(self, device):
        """Add or update a device node."""
        mac = device.mac.lower()
        if mac == "ff:ff:ff:ff:ff:ff":
            return

        if mac not in self.nodes:
            label = device.hostname or device.vendor or mac[:8]
            self.nodes[mac] = GraphNode(
                mac=mac,
                label=label,
                device_type=device.device_type,
                vendor=device.vendor,
            )
        else:
            node = self.nodes[mac]
            if device.hostname:
                node.label = device.hostname
            elif device.vendor and device.vendor != "Unknown":
                node.label = device.vendor
            node.device_type = device.device_type or node.device_type
            node.vendor = device.vendor or node.vendor
            node.is_router = "router" in (device.device_type or "").lower()
            node.last_active = time.time()

    def update_connections(self, connections: list):
        """Update edges from database connection data."""
        for conn in connections:
            src = conn.get("source_mac", "").lower()
            dst = conn.get("dest_mac", "").lower()
            weight = conn.get("weight", 1)
            if src in self.nodes and dst in self.nodes:
                self.nodes[src].connections[dst] = weight
                self.nodes[dst].connections[src] = weight

    def _physics_step(self):
        """One step of force-directed layout simulation."""
        if len(self.nodes) < 2:
            self.update()
            return

        nodes = list(self.nodes.values())

        # Repulsion (all pairs)
        for i, a in enumerate(nodes):
            for b in nodes[i + 1:]:
                dx = a.x - b.x
                dy = a.y - b.y
                dist = max(math.sqrt(dx * dx + dy * dy), 1)
                force = self._repulsion / (dist * dist)
                fx = (dx / dist) * force
                fy = (dy / dist) * force
                a.vx += fx
                a.vy += fy
                b.vx -= fx
                b.vy -= fy

        # Attraction (edges)
        for node in nodes:
            for target_mac, weight in node.connections.items():
                if target_mac in self.nodes:
                    target = self.nodes[target_mac]
                    dx = target.x - node.x
                    dy = target.y - node.y
                    dist = max(math.sqrt(dx * dx + dy * dy), 1)
                    force = self._attraction * dist * min(weight, 5)
                    node.vx += (dx / dist) * force
                    node.vy += (dy / dist) * force

        # Center gravity
        for node in nodes:
            node.vx -= node.x * self._center_gravity
            node.vy -= node.y * self._center_gravity

        # Apply velocity and damping
        for node in nodes:
            if node is not self._selected_node:
                node.vx *= self._damping
                node.vy *= self._damping
                node.x += node.vx
                node.y += node.vy
            else:
                node.vx = 0
                node.vy = 0

        self.update()

    def _world_to_screen(self, x, y):
        w, h = self.width(), self.height()
        sx = (x * self._zoom) + w / 2 + self._offset_x
        sy = (y * self._zoom) + h / 2 + self._offset_y
        return sx, sy

    def _screen_to_world(self, sx, sy):
        w, h = self.width(), self.height()
        x = (sx - w / 2 - self._offset_x) / self._zoom
        y = (sy - h / 2 - self._offset_y) / self._zoom
        return x, y

    def _node_at(self, sx, sy):
        wx, wy = self._screen_to_world(sx, sy)
        for node in self.nodes.values():
            dx = wx - node.x
            dy = wy - node.y
            if dx * dx + dy * dy < (node.radius / self._zoom + 5) ** 2:
                return node
        return None

    def paintEvent(self, event):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(PARCHMENT))
        p.setPen(QPen(QColor(RULE), 1))
        p.drawRect(0, 0, self.width() - 1, self.height() - 1)

        if not self.nodes:
            p.setPen(QColor(INK_FAINT))
            p.setFont(QFont("Times New Roman", 12))
            p.drawText(self.rect(), Qt.AlignCenter,
                       "Awaiting observation...\nDevices appear here as they are discovered.")
            p.end()
            return

        p.setRenderHint(QPainter.Antialiasing, True)

        # Edges: line width is proportional to traffic weight.
        for node in self.nodes.values():
            sx1, sy1 = self._world_to_screen(node.x, node.y)
            for target_mac, weight in node.connections.items():
                if target_mac in self.nodes:
                    target = self.nodes[target_mac]
                    sx2, sy2 = self._world_to_screen(target.x, target.y)
                    pen = QPen(QColor(INK))
                    pen.setWidthF(max(0.4, min(weight * 0.25, 2.0)))
                    p.setPen(pen)
                    p.drawLine(QPointF(sx1, sy1), QPointF(sx2, sy2))

        for node in self.nodes.values():
            sx, sy = self._world_to_screen(node.x, node.y)
            r = node.radius * self._zoom

            if node.is_router:
                fill = QColor(ACCENT_CORAL)
                text_color = QColor(INK)
            elif node is self._hover_node:
                fill = QColor(PARCHMENT_DARK)
                text_color = QColor(INK)
            else:
                fill = QColor(PARCHMENT)
                text_color = QColor(INK)

            p.setBrush(QBrush(fill))
            p.setPen(QPen(QColor(INK), 1))
            p.drawEllipse(QPointF(sx, sy), r, r)

            tag = DEVICE_TYPE_ICONS.get(node.device_type, "[?]")
            p.setPen(text_color)
            p.setFont(QFont("Times New Roman", max(7, int(r * 0.36)), QFont.Bold))
            p.drawText(QRectF(sx - r, sy - r, r * 2, r * 2), Qt.AlignCenter, tag)

            p.setPen(QColor(INK))
            p.setFont(QFont("Times New Roman", max(8, int(9 * self._zoom))))
            label_rect = QRectF(sx - 90, sy + r + 2, 180, 16)
            p.drawText(label_rect, Qt.AlignHCenter | Qt.AlignTop, node.label[:24])

        if self._hover_node:
            self._draw_tooltip(p, self._hover_node)

        p.end()

    def _draw_tooltip(self, p, node):
        sx, sy = self._world_to_screen(node.x, node.y)
        lines = [
            f"MAC: {node.mac}",
            f"Vendor: {node.vendor or '-'}",
            f"Type: {node.device_type or '-'}",
            f"Connections: {len(node.connections)}",
        ]

        font = QFont("Times New Roman", 10)
        p.setFont(font)
        fm = p.fontMetrics()
        line_h = fm.height() + 2
        max_w = max(fm.horizontalAdvance(l) for l in lines) + 14
        box_h = line_h * len(lines) + 10
        bx = sx + node.radius * self._zoom + 8
        by = sy - box_h / 2

        p.setBrush(QBrush(QColor("#fff6dc")))
        p.setPen(QPen(QColor(RULE), 1))
        p.drawRect(QRectF(bx, by, max_w, box_h))

        p.setPen(QColor(INK))
        ty = by + 5
        for line in lines:
            p.drawText(QPointF(bx + 7, ty + fm.ascent()), line)
            ty += line_h

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            node = self._node_at(event.x(), event.y())
            if node:
                self._selected_node = node
            else:
                self._dragging = True
                self._drag_start = event.pos()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._selected_node = None
            self._dragging = False

    def mouseMoveEvent(self, event):
        if self._selected_node:
            wx, wy = self._screen_to_world(event.x(), event.y())
            self._selected_node.x = wx
            self._selected_node.y = wy
        elif self._dragging:
            dx = event.x() - self._drag_start.x()
            dy = event.y() - self._drag_start.y()
            self._offset_x += dx
            self._offset_y += dy
            self._drag_start = event.pos()
        else:
            self._hover_node = self._node_at(event.x(), event.y())
            self.setCursor(Qt.PointingHandCursor if self._hover_node else Qt.ArrowCursor)

    def wheelEvent(self, event):
        delta = event.angleDelta().y() / 120
        factor = 1.1 if delta > 0 else 0.9
        self._zoom = max(0.2, min(5.0, self._zoom * factor))
        self.update()
