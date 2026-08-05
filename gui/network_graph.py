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
    BG, BG_ALT, PANEL, NEON, CYAN, RED, DIM, risk_color,
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
        self._risk_map: dict = {}  # mac -> risk score
        self.setMinimumSize(400, 300)

        # Physics parameters
        self._repulsion = 5000
        self._attraction = 0.01
        self._damping = 0.85
        self._center_gravity = 0.01
        self._repulsion_cutoff = 600.0  # ignore pairs farther than this (perf)
        self._settle_energy = 0.05      # kinetic energy below which layout freezes
        self._interval_ms = 40          # ~25 FPS

        # View state
        self._zoom = 1.0
        self._offset_x = 0.0
        self._offset_y = 0.0
        self._dragging = False
        self._drag_start = QPointF()
        self._selected_node = None
        self._hover_node = None
        self._freeze_when_hidden = True

        # Visual tunables (bound from settings via apply_settings)
        self._node_size = 20
        self._label_len = 24
        self._show_labels = True
        self._show_edges = True
        self._edge_scale = 1.0
        self._edge_opacity = 1.0
        self._highlight_routers = True
        self._color_by = "risk"

        # Animation — timer only runs while the layout is "hot" and visible.
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._physics_step)

        self.setMouseTracking(True)

    # -- lifecycle / wake control -------------------------------------------
    def _wake(self):
        """(Re)start the simulation if it has settled or was paused."""
        if self.isVisible() and not self._timer.isActive():
            self._timer.start(self._interval_ms)

    def showEvent(self, event):
        # Becomes the current tab -> resume simulating.
        self._wake()
        super().showEvent(event)

    def hideEvent(self, event):
        # Left the current tab -> stop burning CPU on off-screen physics.
        if self._freeze_when_hidden:
            self._timer.stop()
        super().hideEvent(event)

    def apply_settings(self, s):
        """Bind live tunables from the Settings object (optional)."""
        self._repulsion = s.get("graph.repulsion", self._repulsion)
        self._attraction = s.get("graph.attraction", self._attraction)
        self._damping = s.get("graph.damping", self._damping)
        self._center_gravity = s.get("graph.gravity", self._center_gravity)
        self._settle_energy = s.get("graph.settle_energy", self._settle_energy)
        self._freeze_when_hidden = s.get("graph.freeze_when_hidden", True)
        self._node_size = int(s.get("graph.node_size", 20))
        self._label_len = int(s.get("graph.label_len", 24))
        self._show_labels = bool(s.get("graph.show_labels", True))
        self._show_edges = bool(s.get("graph.show_edges", True))
        self._edge_scale = float(s.get("graph.edge_scale", 1.0))
        self._edge_opacity = float(s.get("graph.edge_opacity", 1.0))
        self._highlight_routers = bool(s.get("graph.highlight_routers", True))
        self._color_by = s.get("graph.color_by", "risk")
        for n in self.nodes.values():
            n.radius = self._node_size
        fps = max(5, int(s.get("graph.fps", 25)))
        self._interval_ms = int(1000 / fps)
        if self._timer.isActive():
            self._timer.setInterval(self._interval_ms)
        self._wake()
        self.update()

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
        self._wake()

    def set_risk_map(self, risk_map: dict):
        """Provide per-MAC risk scores to colour the nodes."""
        self._risk_map = {k.lower(): v for k, v in risk_map.items()}
        # Repaint colours even if the physics loop has frozen.
        if self.isVisible():
            self.update()

    def update_connections(self, connections: list):
        """Update edges from database connection data."""
        changed = False
        for conn in connections:
            src = conn.get("source_mac", "").lower()
            dst = conn.get("dest_mac", "").lower()
            weight = conn.get("weight", 1)
            if src in self.nodes and dst in self.nodes:
                if self.nodes[src].connections.get(dst) != weight:
                    changed = True
                self.nodes[src].connections[dst] = weight
                self.nodes[dst].connections[src] = weight
        if changed:
            self._wake()

    def _physics_step(self):
        """One step of force-directed layout simulation.

        Stops itself (freezes) once the layout has settled, and skips distant
        node pairs, so it does not spin the CPU forever on a stable graph.
        """
        if len(self.nodes) < 2:
            self._timer.stop()
            self.update()
            return

        nodes = list(self.nodes.values())
        cutoff2 = self._repulsion_cutoff * self._repulsion_cutoff

        # Repulsion (all pairs, skipping distant ones for performance)
        for i, a in enumerate(nodes):
            for b in nodes[i + 1:]:
                dx = a.x - b.x
                dy = a.y - b.y
                d2 = dx * dx + dy * dy
                if d2 > cutoff2:
                    continue
                dist = max(math.sqrt(d2), 1)
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

        # Apply velocity and damping, accumulating total kinetic energy.
        energy = 0.0
        for node in nodes:
            if node is not self._selected_node:
                node.vx *= self._damping
                node.vy *= self._damping
                node.x += node.vx
                node.y += node.vy
                energy += node.vx * node.vx + node.vy * node.vy
            else:
                node.vx = 0
                node.vy = 0

        self.update()

        # Freeze once the graph is essentially still (unless the user is
        # dragging a node). It re-wakes on new devices/edges or interaction.
        if energy < self._settle_energy and not self._dragging and self._selected_node is None:
            self._timer.stop()

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
            f = QFont("JetBrains Mono", 12); f.setStyleHint(QFont.Monospace)
            p.setFont(f)
            p.drawText(self.rect(), Qt.AlignCenter,
                       "Awaiting observation...\nDevices appear here as they are discovered.")
            p.end()
            return

        p.setRenderHint(QPainter.Antialiasing, True)

        # Edges: line width is proportional to traffic weight.
        if self._show_edges:
            edge_col = QColor(INK)
            edge_col.setAlphaF(max(0.1, min(1.0, self._edge_opacity)))
            for node in self.nodes.values():
                sx1, sy1 = self._world_to_screen(node.x, node.y)
                for target_mac, weight in node.connections.items():
                    if target_mac in self.nodes:
                        target = self.nodes[target_mac]
                        sx2, sy2 = self._world_to_screen(target.x, target.y)
                        pen = QPen(edge_col)
                        pen.setWidthF(max(0.4, min(weight * 0.25, 2.0)) * self._edge_scale)
                        p.setPen(pen)
                        p.drawLine(QPointF(sx1, sy1), QPointF(sx2, sy2))

        for node in self.nodes.values():
            sx, sy = self._world_to_screen(node.x, node.y)
            r = node.radius * self._zoom

            risk = self._risk_map.get(node.mac, 0)
            ring = self._node_color(node, risk)
            if node.is_router and self._highlight_routers:
                fill = QColor(RED)
                fill.setAlpha(70)
            elif node is self._hover_node:
                fill = QColor(PANEL)
            else:
                fill = QColor(BG_ALT)

            p.setBrush(QBrush(fill))
            pen = QPen(ring)
            pen.setWidthF(2.0 if risk >= 40 else 1.2)
            p.setPen(pen)
            p.drawEllipse(QPointF(sx, sy), r, r)

            tag = DEVICE_TYPE_ICONS.get(node.device_type, "[?]")
            p.setPen(QColor(NEON))
            tf = QFont("JetBrains Mono", max(7, int(r * 0.32)), QFont.Bold)
            tf.setStyleHint(QFont.Monospace)
            p.setFont(tf)
            p.drawText(QRectF(sx - r, sy - r, r * 2, r * 2), Qt.AlignCenter, tag)

            if self._show_labels:
                p.setPen(QColor(NEON))
                lf = QFont("JetBrains Mono", max(8, int(9 * self._zoom)))
                lf.setStyleHint(QFont.Monospace)
                p.setFont(lf)
                label_rect = QRectF(sx - 90, sy + r + 2, 180, 16)
                p.drawText(label_rect, Qt.AlignHCenter | Qt.AlignTop,
                           node.label[:self._label_len])

        if self._hover_node:
            self._draw_tooltip(p, self._hover_node)

        p.end()

    _PALETTE = ["#00e5ff", "#ffb000", "#b088ff", "#7affb0", "#ff6b9d",
                "#ffd166", "#48dbfb", "#badc58", "#e056fd", "#ff7979"]

    def _node_color(self, node, risk):
        if self._color_by == "risk":
            return QColor(risk_color(risk)) if risk >= 15 else QColor(NEON)
        key = (node.vendor if self._color_by == "vendor" else node.device_type) or "?"
        return QColor(self._PALETTE[hash(key) % len(self._PALETTE)])

    def _draw_tooltip(self, p, node):
        sx, sy = self._world_to_screen(node.x, node.y)
        lines = [
            f"MAC: {node.mac}",
            f"Vendor: {node.vendor or '-'}",
            f"Type: {node.device_type or '-'}",
            f"Connections: {len(node.connections)}",
        ]

        font = QFont("JetBrains Mono", 9)
        font.setStyleHint(QFont.Monospace)
        p.setFont(font)
        fm = p.fontMetrics()
        line_h = fm.height() + 2
        max_w = max(fm.horizontalAdvance(l) for l in lines) + 14
        box_h = line_h * len(lines) + 10
        bx = sx + node.radius * self._zoom + 8
        by = sy - box_h / 2

        p.setBrush(QBrush(QColor(PANEL)))
        p.setPen(QPen(QColor(NEON), 1))
        p.drawRect(QRectF(bx, by, max_w, box_h))

        p.setPen(QColor(NEON))
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
            self._wake()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._selected_node = None
            self._dragging = False
            self._wake()  # let it re-settle after a drag

    def mouseMoveEvent(self, event):
        if self._selected_node:
            wx, wy = self._screen_to_world(event.x(), event.y())
            self._selected_node.x = wx
            self._selected_node.y = wy
            self._wake()
        elif self._dragging:
            dx = event.x() - self._drag_start.x()
            dy = event.y() - self._drag_start.y()
            self._offset_x += dx
            self._offset_y += dy
            self._drag_start = event.pos()
            self.update()
        else:
            prev = self._hover_node
            self._hover_node = self._node_at(event.x(), event.y())
            self.setCursor(Qt.PointingHandCursor if self._hover_node else Qt.ArrowCursor)
            if prev is not self._hover_node:
                self.update()  # repaint hover highlight even when frozen

    def wheelEvent(self, event):
        delta = event.angleDelta().y() / 120
        factor = 1.1 if delta > 0 else 0.9
        self._zoom = max(0.2, min(5.0, self._zoom * factor))
        self.update()
