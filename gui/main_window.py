"""GhostWire main application window (hacker/terminal theme)."""
import os
import json
import threading
from datetime import datetime
from collections import Counter, deque

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QLabel, QPushButton,
    QComboBox, QLabel as _QLabel, QSplitter, QTextEdit, QGroupBox,
    QFileDialog, QMessageBox, QAbstractItemView, QFrame, QLineEdit,
    QCheckBox, QMenu, QInputDialog, QTreeWidget, QTreeWidgetItem, QAction,
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject, QRectF, QPointF
from PyQt5.QtGui import QFont, QColor, QPainter, QPen, QBrush, QPainterPath

import math

from gui.theme import (
    DARK_THEME, PROTOCOL_COLORS, DEVICE_TYPE_ICONS,
    PARCHMENT, PARCHMENT_DARK, INK, INK_FAINT, RULE,
    BG, BG_ALT, PANEL, NEON, CYAN, AMBER, RED, DIM, GREEN_FAINT,
    risk_color, severity_color, build_qss, scheme_accents,
)
from gui.network_graph import NetworkGraphWidget
from gui.matrix_bg import MatrixRainWidget
from gui.widgets import (
    GlowButton, AnimatedStatCard, PacketDetailTree, HexView, GlitchLabel, Toast,
)
from gui.fonts import pixel_accent_qss
from core.i18n import tr
from core.sniffer import Sniffer
from core.parsers import dissect_layers
from core.device_manager import DeviceManager, Device
from core.database import Database


class SignalBridge(QObject):
    """Thread-safe signal bridge for callbacks from the sniffer thread."""
    device_updated = pyqtSignal(object, bool)   # (Device, is_new)
    packet_received = pyqtSignal(str)
    alert_raised = pyqtSignal(dict)


# --------------------------------------------------------------------------- #
#  Custom-painted stat widgets (auto-dark via theme constants)               #
# --------------------------------------------------------------------------- #
class ProtocolBarWidget(QWidget):
    """Horizontal stacked bar showing protocol distribution."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(30)
        self.setMaximumHeight(30)
        self._data = {}

    def set_data(self, data: dict):
        self._data = data
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(BG_ALT))
        p.setPen(QPen(QColor(DIM), 1))
        p.drawRect(0, 0, self.width() - 1, self.height() - 1)
        if not self._data:
            p.setPen(QColor(GREEN_FAINT))
            p.setFont(QFont("JetBrains Mono", 9))
            p.drawText(self.rect(), Qt.AlignCenter, "awaiting protocol traffic...")
            p.end()
            return
        total = sum(self._data.values())
        if total == 0:
            p.end()
            return
        x = 1
        w = self.width() - 2
        h = self.height() - 2
        for proto, count in sorted(self._data.items(), key=lambda kv: -kv[1]):
            bar_w = max(2, (count / total) * w)
            colour = QColor(PROTOCOL_COLORS.get(proto, GREEN_FAINT))
            p.setBrush(QBrush(colour))
            p.setPen(QPen(QColor(BG), 1))
            p.drawRect(int(x), 1, int(bar_w), h)
            if bar_w > 64:
                p.setPen(QColor(BG))
                p.setFont(QFont("JetBrains Mono", 9, QFont.Bold))
                p.drawText(int(x + 6), 1, int(bar_w - 12), h,
                           Qt.AlignVCenter | Qt.AlignLeft, f"{proto} {count}")
            x += bar_w
        p.end()


class CoxcombWidget(QWidget):
    """Polar-area (rose) diagram — wedge area proportional to count."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(300)
        self._data: dict = {}

    def set_data(self, data: dict):
        self._data = data
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(BG_ALT))
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setPen(QColor(CYAN))
        p.setFont(QFont("JetBrains Mono", 12, QFont.Bold))
        p.drawText(0, 6, self.width(), 22, Qt.AlignHCenter,
                   "// protocol chatter rose")
        if not self._data:
            p.setFont(QFont("JetBrains Mono", 11))
            p.setPen(QColor(GREEN_FAINT))
            p.drawText(self.rect(), Qt.AlignCenter, "(awaiting observation)")
            p.end()
            return
        items = sorted(self._data.items(), key=lambda kv: -kv[1])
        n = len(items)
        if n == 0 or sum(c for _, c in items) == 0:
            p.end()
            return
        cx = self.width() / 2
        cy = self.height() / 2 + 18
        max_count = max(c for _, c in items) or 1
        max_radius = min(self.width(), self.height() - 60) / 2 - 60
        max_radius = max(40.0, max_radius)
        angle_each = 360.0 / n
        start_angle = 90.0
        p.setPen(QPen(QColor(DIM), 1, Qt.DotLine))
        p.setBrush(Qt.NoBrush)
        for frac in (1 / 3, 2 / 3, 1.0):
            r = max_radius * frac
            p.drawEllipse(QPointF(cx, cy), r, r)
        for i, (proto, count) in enumerate(items):
            radius = math.sqrt(count / max_count) * max_radius
            colour = QColor(PROTOCOL_COLORS.get(proto, GREEN_FAINT))
            colour.setAlpha(200)
            path = QPainterPath()
            path.moveTo(cx, cy)
            path.arcTo(QRectF(cx - radius, cy - radius, radius * 2, radius * 2),
                       (start_angle - (i + 1) * angle_each), angle_each)
            path.closeSubpath()
            p.setBrush(QBrush(colour))
            p.setPen(QPen(QColor(BG), 1))
            p.drawPath(path)
        p.setFont(QFont("JetBrains Mono", 9, QFont.Bold))
        p.setPen(QColor(NEON))
        for i, (proto, count) in enumerate(items):
            mid = math.radians(start_angle - (i + 0.5) * angle_each)
            lx = cx + math.cos(mid) * (max_radius + 18)
            ly = cy - math.sin(mid) * (max_radius + 18)
            p.drawText(QRectF(lx - 40, ly - 8, 80, 16), Qt.AlignCenter, proto)
        p.end()


class IOGraphWidget(QWidget):
    """Scrolling line chart of packets/sec and bytes/sec over time."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(220)
        self._pps = deque(maxlen=120)
        self._bps = deque(maxlen=120)

    def push(self, pps: float, bps: float):
        self._pps.append(pps)
        self._bps.append(bps)
        self.update()

    def _series(self, p, data, color, top_label):
        if len(data) < 2:
            return
        w, h = self.width(), self.height()
        hi = max(data) or 1.0
        n = len(data)
        step = w / (n - 1)
        from PyQt5.QtGui import QPolygonF
        poly = QPolygonF()
        for i, v in enumerate(data):
            x = i * step
            y = h - 14 - (v / hi) * (h - 40)
            poly.append(QPointF(x, y))
        pen = QPen(QColor(color))
        pen.setWidthF(1.6)
        p.setPen(pen)
        p.setBrush(Qt.NoBrush)
        p.drawPolyline(poly)
        p.setPen(QColor(color))
        p.setFont(QFont("JetBrains Mono", 9))
        p.drawText(8, 16 if top_label == "pps" else 30,
                   f"{top_label}: {data[-1]:.1f} (peak {hi:.1f})")

    def paintEvent(self, event):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(BG_ALT))
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setPen(QPen(QColor(DIM), 1))
        for gy in range(1, 4):
            y = self.height() * gy / 4
            p.drawLine(0, int(y), self.width(), int(y))
        self._series(p, self._pps, NEON, "pps")
        self._series(p, self._bps, CYAN, "Bps")
        p.end()


class _MatrixCentral(QWidget):
    """Central widget that keeps a matrix-rain layer stretched behind content."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rain = MatrixRainWidget(self, opacity=0.28, font_size=14)
        self.content = QWidget(self)
        self.content.setObjectName("contentLayer")
        self.content.setStyleSheet("#contentLayer { background: transparent; }")
        self.rain.lower()

    def resizeEvent(self, event):
        self.rain.setGeometry(0, 0, self.width(), self.height())
        self.content.setGeometry(0, 0, self.width(), self.height())
        super().resizeEvent(event)


class MainWindow(QMainWindow):
    def __init__(self, db_path: str = "passive_scanner.db", deep: bool = False,
                 pcap: str = None, settings=None):
        super().__init__()
        from core.settings import get_settings
        self.settings = settings or get_settings()
        self.setWindowTitle("GhostWire :: Passive Network Scanner")
        self.setMinimumSize(1260, 780)
        self.resize(1480, 900)

        self.db = Database(db_path)
        # Optional retention prune at startup.
        if self.settings.get("storage.autoprune", False):
            try:
                self.db.prune_events(int(self.settings.get("storage.autoprune_hours", 24)) * 3600)
            except Exception:
                pass
        self.device_manager = DeviceManager(self.db, settings=self.settings)
        # Hand the shared settings to the analytics engine (detectors/weights).
        try:
            self.device_manager.analytics.apply_settings(self.settings)
        except Exception:
            pass
        self.sniffer = Sniffer(self.device_manager, settings=self.settings)
        self.sniffer.deep = deep
        self._pcap_path = pcap
        self._ring_index = []  # maps live-packet table rows -> ring entries

        self._signals = SignalBridge()
        self._signals.device_updated.connect(self._on_device_updated)
        self._signals.packet_received.connect(self._on_packet_log)
        self._signals.alert_raised.connect(self._on_alert)
        self.device_manager.on_device_update(
            lambda dev, is_new: self._signals.device_updated.emit(dev, is_new))
        self.device_manager.on_alert(
            lambda alert: self._signals.alert_raised.emit(alert))
        self.sniffer.on_flow(self.device_manager.record_flow)
        self.sniffer.on_packet(
            lambda pkt, results: self._signals.packet_received.emit(
                results[0].summary if results else ""))

        self._build_ui()
        self._build_menu()

        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_stats)
        self._refresh_timer.start(int(self.settings.get("capture.refresh_ms", 2000)))

        self._status_label = QLabel(f"{tr('Ready')} :: passive mode :: 0 packets transmitted")
        self.statusBar().addWidget(self._status_label, 1)
        self._pps_label = QLabel("")
        self.statusBar().addPermanentWidget(self._pps_label)

        self._shortcut_actions = []
        self._install_shortcuts()

        # Apply all persisted preferences, then react to any live change.
        self._apply_all_settings()
        self.settings.changed.connect(self._on_setting_changed)

        # Restore window geometry / startup tab.
        geo = self.settings.get("window.geometry", "")
        if geo:
            try:
                self.restoreGeometry(bytes.fromhex(geo))
            except Exception:
                pass
        self._tabs.setCurrentIndex(int(self.settings.get("appearance.startup_tab", 0)))

    # ------------------------------------------------------------------ #
    #  UI construction                                                    #
    # ------------------------------------------------------------------ #
    def _build_ui(self):
        central = _MatrixCentral()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central.content)
        main_layout.setContentsMargins(12, 8, 12, 8)
        main_layout.setSpacing(8)

        # -- top bar --
        top_bar = QHBoxLayout()
        top_bar.setSpacing(8)
        title = GlitchLabel("GhostWire")
        top_bar.addWidget(title)
        subtitle = QLabel("// passive recon")
        subtitle.setObjectName("subtitleLabel")
        top_bar.addWidget(subtitle)
        top_bar.addStretch()

        self._iface_combo = QComboBox()
        self._populate_interfaces()
        top_bar.addWidget(QLabel(tr("iface:")))
        top_bar.addWidget(self._iface_combo)

        self._bpf_input = QLineEdit()
        self._bpf_input.setPlaceholderText(tr("custom BPF filter (optional)"))
        self._bpf_input.setMaximumWidth(220)
        top_bar.addWidget(self._bpf_input)

        self._deep_check = QCheckBox(tr("Deep"))
        self._deep_check.setChecked(self.sniffer.deep)
        self._deep_check.setToolTip("Deep Capture Mode: dissect all TCP/UDP, not just discovery")
        top_bar.addWidget(self._deep_check)

        self._start_btn = GlowButton(f"▶ {tr('Start')}", glow_color=NEON)
        self._start_btn.setObjectName("startButton")
        self._start_btn.clicked.connect(self._start_capture)
        top_bar.addWidget(self._start_btn)

        self._pause_btn = GlowButton(f"⏸ {tr('Pause')}", glow_color=AMBER)
        self._pause_btn.setEnabled(False)
        self._pause_btn.clicked.connect(self._toggle_pause)
        top_bar.addWidget(self._pause_btn)

        self._stop_btn = GlowButton(f"⏹ {tr('Stop')}", glow_color=RED)
        self._stop_btn.setObjectName("stopButton")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_capture)
        top_bar.addWidget(self._stop_btn)

        open_btn = GlowButton(tr("Open PCAP"), glow_color=CYAN)
        open_btn.clicked.connect(self._open_pcap_dialog)
        top_bar.addWidget(open_btn)

        save_btn = GlowButton(tr("Save PCAP"), glow_color=CYAN)
        save_btn.clicked.connect(self._save_pcap)
        top_bar.addWidget(save_btn)

        export_btn = GlowButton(f"{tr('Export')} ▾", glow_color=CYAN)
        export_menu = QMenu(export_btn)
        export_menu.addAction("JSON report", lambda: self._export("json"))
        export_menu.addAction("CSV (devices)", lambda: self._export("csv"))
        export_menu.addAction("HTML report", lambda: self._export("html"))
        export_btn.setMenu(export_menu)
        top_bar.addWidget(export_btn)

        main_layout.addLayout(top_bar)

        # -- stat cards --
        stats_bar = QHBoxLayout()
        stats_bar.setSpacing(8)
        self._stat_devices = AnimatedStatCard(tr("DEVICES"), spark_color=NEON)
        self._stat_packets = AnimatedStatCard(tr("PACKETS"), spark_color=CYAN)
        self._stat_protocols = AnimatedStatCard(tr("PROTOCOLS"), spark_color=AMBER)
        self._stat_active = AnimatedStatCard(tr("ACTIVE 5m"), spark_color=NEON)
        self._stat_alerts = AnimatedStatCard(tr("ALERTS"), spark_color=RED)
        self._stat_throughput = AnimatedStatCard(tr("THROUGHPUT"), spark_color=CYAN)
        self._stat_uptime = AnimatedStatCard(tr("UPTIME"), spark_color=NEON)
        for card in (self._stat_devices, self._stat_packets, self._stat_protocols,
                     self._stat_active, self._stat_alerts, self._stat_throughput,
                     self._stat_uptime):
            stats_bar.addWidget(card)
        main_layout.addLayout(stats_bar)

        self._proto_bar = ProtocolBarWidget()
        main_layout.addWidget(self._proto_bar)

        # -- tabs --
        tabs = QTabWidget()
        self._tabs = tabs
        main_layout.addWidget(tabs, 1)
        tabs.addTab(self._build_devices_tab(), tr("Devices"))
        tabs.addTab(self._build_graph_tab(), tr("Network Map"))
        tabs.addTab(self._build_live_tab(), tr("Live Packets"))
        tabs.addTab(self._build_alerts_tab(), tr("Alerts"))
        tabs.addTab(self._build_conversations_tab(), tr("Conversations"))
        tabs.addTab(self._build_events_tab(), tr("Event Log"))
        tabs.addTab(self._build_dns_tab(), tr("DNS"))
        tabs.addTab(self._build_io_tab(), tr("IO Graph"))
        tabs.addTab(self._build_hierarchy_tab(), tr("Protocol Tree"))
        tabs.addTab(self._build_statistics_tab(), tr("Statistics"))
        # index -> internal name used by the lazy-refresh dispatcher
        self._tab_names = {
            0: "devices", 1: "map", 2: "live", 3: "alerts", 4: "conversations",
            5: "events", 6: "dns", 7: "io", 8: "hierarchy", 9: "statistics",
        }
        # Refresh the newly shown tab immediately (don't wait for the timer tick).
        tabs.currentChanged.connect(lambda _idx: self._refresh_stats())

    # ---- individual tabs -------------------------------------------------
    def _build_devices_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 4, 0, 0)
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText(tr("filter by MAC / IP / host / vendor / OS / tag ..."))
        self._search_input.textChanged.connect(self._filter_devices)
        layout.addWidget(self._search_input)

        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter, 1)
        self._device_table = QTableWidget()
        self._device_table.setColumnCount(10)
        self._device_table.setHorizontalHeaderLabels([tr(h) for h in (
            "Type", "MAC", "IP", "Host/Alias", "Vendor", "OS",
            "Risk", "Protocols", "Pkts", "Last Seen",
        )])
        self._device_table.setAlternatingRowColors(True)
        self._device_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._device_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._device_table.horizontalHeader().setStretchLastSection(True)
        self._device_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        widths = [58, 140, 118, 150, 120, 110, 54, 150, 60]
        for i, w in enumerate(widths):
            self._device_table.setColumnWidth(i, w)
        self._device_table.setSortingEnabled(True)
        self._device_table.currentCellChanged.connect(self._on_device_selected)
        self._device_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._device_table.customContextMenuRequested.connect(self._device_context_menu)
        splitter.addWidget(self._device_table)

        self._detail_panel = QTextEdit()
        self._detail_panel.setReadOnly(True)
        self._detail_panel.setMaximumHeight(220)
        self._detail_panel.setPlaceholderText(tr("select a device for its full dossier..."))
        splitter.addWidget(self._detail_panel)
        splitter.setSizes([540, 220])
        return widget

    def _build_graph_tab(self) -> QWidget:
        self._graph_widget = NetworkGraphWidget()
        return self._graph_widget

    def _build_live_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 4, 0, 0)
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)

        self._live_table = QTableWidget()
        self._live_table.setColumnCount(5)
        self._live_table.setHorizontalHeaderLabels(["Time", "Proto", "Len", "Summary", "#"])
        self._live_table.setColumnHidden(4, True)
        self._live_table.setAlternatingRowColors(True)
        self._live_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._live_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._live_table.horizontalHeader().setStretchLastSection(True)
        self._live_table.setColumnWidth(0, 90)
        self._live_table.setColumnWidth(1, 70)
        self._live_table.setColumnWidth(2, 50)
        self._live_table.currentCellChanged.connect(self._on_live_selected)
        splitter.addWidget(self._live_table)

        right = QSplitter(Qt.Vertical)
        self._detail_tree = PacketDetailTree()
        self._hex_view = HexView()
        right.addWidget(self._detail_tree)
        right.addWidget(self._hex_view)
        right.setSizes([320, 200])
        splitter.addWidget(right)
        splitter.setSizes([620, 620])
        return widget

    def _build_alerts_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 4, 0, 0)
        self._alerts_table = QTableWidget()
        self._alerts_table.setColumnCount(5)
        self._alerts_table.setHorizontalHeaderLabels(
            ["Time", "Severity", "Category", "Device", "Detail"])
        self._alerts_table.setAlternatingRowColors(True)
        self._alerts_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._alerts_table.horizontalHeader().setStretchLastSection(True)
        for i, w in enumerate([90, 90, 130, 170]):
            self._alerts_table.setColumnWidth(i, w)
        layout.addWidget(self._alerts_table, 1)
        return widget

    def _build_conversations_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 4, 0, 0)
        self._conv_table = QTableWidget()
        self._conv_table.setColumnCount(7)
        self._conv_table.setHorizontalHeaderLabels(
            ["Source", "Destination", "Proto", "S.Port", "D.Port", "Packets", "Bytes"])
        self._conv_table.setAlternatingRowColors(True)
        self._conv_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._conv_table.setSortingEnabled(True)
        self._conv_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self._conv_table, 1)
        return widget

    def _build_events_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 4, 0, 0)
        self._event_table = QTableWidget()
        self._event_table.setColumnCount(6)
        self._event_table.setHorizontalHeaderLabels(
            ["Time", "Protocol", "Source", "Destination", "Type", "Summary"])
        self._event_table.setAlternatingRowColors(True)
        self._event_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._event_table.horizontalHeader().setStretchLastSection(True)
        for i, w in enumerate([90, 80, 140, 140, 80]):
            self._event_table.setColumnWidth(i, w)
        layout.addWidget(self._event_table, 1)
        return widget

    def _build_dns_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 4, 0, 0)
        self._dns_table = QTableWidget()
        self._dns_table.setColumnCount(2)
        self._dns_table.setHorizontalHeaderLabels(["Domain", "Query Count"])
        self._dns_table.setAlternatingRowColors(True)
        self._dns_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._dns_table.horizontalHeader().setStretchLastSection(True)
        self._dns_table.setColumnWidth(0, 520)
        self._dns_table.setSortingEnabled(True)
        layout.addWidget(self._dns_table, 1)
        return widget

    def _build_io_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        grp = QGroupBox("Live Throughput (packets/sec · bytes/sec)")
        gl = QVBoxLayout(grp)
        self._io_graph = IOGraphWidget()
        gl.addWidget(self._io_graph)
        layout.addWidget(grp)
        tgrp = QGroupBox("Top Talkers")
        tl = QVBoxLayout(tgrp)
        self._talkers_table = QTableWidget()
        self._talkers_table.setColumnCount(3)
        self._talkers_table.setHorizontalHeaderLabels(["IP", "Packets", "Bytes"])
        self._talkers_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._talkers_table.horizontalHeader().setStretchLastSection(True)
        tl.addWidget(self._talkers_table)
        layout.addWidget(tgrp)
        return widget

    def _build_hierarchy_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(4, 4, 4, 4)
        self._hierarchy_tree = QTreeWidget()
        self._hierarchy_tree.setHeaderLabels(["Protocol", "Events", "Share"])
        self._hierarchy_tree.setColumnWidth(0, 260)
        layout.addWidget(self._hierarchy_tree, 1)
        return widget

    def _build_statistics_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        rose_group = QGroupBox("Protocol Chatter Rose")
        rose_layout = QVBoxLayout(rose_group)
        self._coxcomb = CoxcombWidget()
        rose_layout.addWidget(self._coxcomb)
        layout.addWidget(rose_group)

        proto_group = QGroupBox("Protocol Event Distribution")
        proto_layout = QVBoxLayout(proto_group)
        self._proto_detail_table = QTableWidget()
        self._proto_detail_table.setColumnCount(3)
        self._proto_detail_table.setHorizontalHeaderLabels(["Protocol", "Events", "Percentage"])
        self._proto_detail_table.setAlternatingRowColors(True)
        self._proto_detail_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._proto_detail_table.horizontalHeader().setStretchLastSection(True)
        proto_layout.addWidget(self._proto_detail_table)
        layout.addWidget(proto_group)

        row = QHBoxLayout()
        dtype_group = QGroupBox("Device Types")
        dtype_layout = QVBoxLayout(dtype_group)
        self._dtype_table = QTableWidget()
        self._dtype_table.setColumnCount(2)
        self._dtype_table.setHorizontalHeaderLabels(["Type", "Count"])
        self._dtype_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._dtype_table.horizontalHeader().setStretchLastSection(True)
        dtype_layout.addWidget(self._dtype_table)
        row.addWidget(dtype_group)

        vendor_group = QGroupBox("Vendors")
        vendor_layout = QVBoxLayout(vendor_group)
        self._vendor_table = QTableWidget()
        self._vendor_table.setColumnCount(2)
        self._vendor_table.setHorizontalHeaderLabels(["Vendor", "Devices"])
        self._vendor_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._vendor_table.horizontalHeader().setStretchLastSection(True)
        vendor_layout.addWidget(self._vendor_table)
        row.addWidget(vendor_group)
        layout.addLayout(row)
        return widget

    # ------------------------------------------------------------------ #
    #  Capture control                                                    #
    # ------------------------------------------------------------------ #
    def _populate_interfaces(self):
        self._iface_combo.clear()
        self._iface_combo.addItem("All Interfaces (default)")
        for iface in Sniffer.get_interfaces():
            if iface != "lo":
                self._iface_combo.addItem(iface)

    def _start_capture(self):
        iface = None
        if self._iface_combo.currentIndex() > 0:
            iface = self._iface_combo.currentText()
        bpf = self._bpf_input.text().strip() or None
        self.sniffer.deep = self._deep_check.isChecked()
        self.sniffer.start(interface=iface, bpf_filter=bpf)
        self._set_running_ui(True)
        mode = "deep" if self.sniffer.deep else "discovery"
        self._status_label.setText(f"Capturing on {iface or 'all interfaces'} [{mode}] :: passive")
        self.centralWidget().rain.set_busy(True)
        QTimer.singleShot(1000, self._check_sniffer_error)

    def _check_sniffer_error(self):
        if self.sniffer.error:
            QMessageBox.critical(self, "Capture Error", self.sniffer.error)
            self._stop_capture()

    def _toggle_pause(self):
        if self.sniffer.is_paused:
            self.sniffer.resume()
            self._pause_btn.setText("⏸ Pause")
            self._status_label.setText("Capture resumed")
        else:
            self.sniffer.pause()
            self._pause_btn.setText("▶ Resume")
            self._status_label.setText("Capture paused")

    def _stop_capture(self):
        self.sniffer.stop()
        self._set_running_ui(False)
        self._status_label.setText("Capture stopped :: passive mode")
        self.centralWidget().rain.set_busy(False)

    def _set_running_ui(self, running: bool):
        self._start_btn.setEnabled(not running)
        self._stop_btn.setEnabled(running)
        self._pause_btn.setEnabled(running)
        self._iface_combo.setEnabled(not running)
        self._deep_check.setEnabled(not running)
        self._bpf_input.setEnabled(not running)

    # ------------------------------------------------------------------ #
    #  PCAP                                                               #
    # ------------------------------------------------------------------ #
    def _open_pcap_dialog(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open capture file", "", "Capture Files (*.pcap *.pcapng *.cap);;All Files (*)")
        if path:
            self.load_pcap(path)

    def load_pcap(self, path: str):
        self._status_label.setText(f"Analysing {os.path.basename(path)} ...")

        def worker():
            self.sniffer.read_pcap(path)
        threading.Thread(target=worker, daemon=True).start()
        QTimer.singleShot(1500, lambda: self._status_label.setText(
            f"Loaded {os.path.basename(path)} :: {self.sniffer.packet_count} packets"))

    def _save_pcap(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save capture buffer", "ghostwire_capture.pcap", "PCAP (*.pcap)")
        if not path:
            return
        try:
            n = self.sniffer.save_pcap(path)
            QMessageBox.information(self, "Save PCAP", f"Wrote {n} packets to:\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "Save PCAP", str(e))

    # ------------------------------------------------------------------ #
    #  Signal handlers                                                    #
    # ------------------------------------------------------------------ #
    def _on_device_updated(self, device: Device, is_new: bool):
        self._update_device_row(device)
        self._graph_widget.update_device(device)

    def _on_packet_log(self, summary: str):
        pass

    def _on_alert(self, alert: dict):
        sev = alert.get("severity", "info")
        if sev == "critical":
            Toast(self, f"⚠ {alert.get('title', 'alert')}", color=RED)

    # ------------------------------------------------------------------ #
    #  Device table                                                       #
    # ------------------------------------------------------------------ #
    def _display_mac(self, mac: str) -> str:
        """Format a MAC for display per settings (format + optional anonymize)."""
        fmt = self.settings.get("devices.mac_format", "colon-lower")
        shown = format_mac(mac, fmt)
        if self.settings.get("privacy.anonymize_mac", False):
            parts = shown.replace("-", ":").split(":")
            if len(parts) == 6:
                sep = "-" if fmt == "dash" else ":"
                shown = sep.join(parts[:3] + ["xx", "xx", "xx"])
        return shown

    def _update_device_row(self, device: Device):
        table = self._device_table
        mac = device.mac  # canonical (colon-lower), used for lookups
        row = -1
        for r in range(table.rowCount()):
            item = table.item(r, 1)
            if item and item.data(Qt.UserRole) == mac:
                row = r
                break
        if row == -1:
            table.setSortingEnabled(False)
            row = table.rowCount()
            table.insertRow(row)

        icon = DEVICE_TYPE_ICONS.get(device.device_type, "[?]")
        last_seen = datetime.fromtimestamp(device.last_seen).strftime("%H:%M:%S") if device.last_seen else ""
        protocols = ",".join(sorted(device.protocols_seen)) if device.protocols_seen else ""
        host = device.alias or device.hostname or ""
        if device.alias and device.hostname:
            host = f"{device.alias} ({device.hostname})"
        if self.settings.get("privacy.redact_hostnames", False) and host:
            host = "***"

        values = [icon, self._display_mac(mac), device.ip or "", host, device.vendor or "",
                  device.os_guess or "", str(device.risk_score), protocols,
                  str(device.packet_count), last_seen]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignVCenter | (Qt.AlignCenter if col in (0, 6) else Qt.AlignLeft))
            if col == 1:
                item.setData(Qt.UserRole, mac)  # keep canonical for lookups
                if device.watchlist and self.settings.get("devices.highlight_watchlist", True):
                    item.setForeground(QColor(AMBER))
            if col == 6:  # risk
                item.setForeground(QColor(risk_color(device.risk_score)))
                f = item.font(); f.setBold(True); item.setFont(f)
            table.setItem(row, col, item)
        table.setSortingEnabled(True)

    def _on_device_selected(self, row, col, prev_row, prev_col):
        if row < 0:
            return
        mac_item = self._device_table.item(row, 1)
        if not mac_item:
            return
        mac = mac_item.data(Qt.UserRole) or mac_item.text()
        device = self.device_manager.get_device(mac)
        if not device:
            return
        services = self.db.get_device_services(mac)
        fps = self.db.get_fingerprints(mac)
        reasons = self.device_manager.analytics.get_risk_reasons(mac)
        tag = DEVICE_TYPE_ICONS.get(device.device_type, '[?]')
        first_seen_str = (datetime.fromtimestamp(device.first_seen).strftime('%Y-%m-%d %H:%M:%S')
                          if device.first_seen else '-')
        rc = risk_color(device.risk_score)
        html = f"""
        <div style="font-family:'JetBrains Mono',monospace; color:{NEON}; background-color:{BG_ALT};">
          <h3 style="margin:0 0 8px 0; color:{CYAN}; border-bottom:1px solid {DIM}; padding-bottom:4px;">
            {tag} &nbsp; {device.alias or device.hostname or device.mac}
            &nbsp;<span style="color:{rc};">[risk {device.risk_score}]</span>
          </h3>
          <table cellspacing="0" cellpadding="3" style="border-collapse:collapse; width:100%;">
            <tr><td style="color:{GREEN_FAINT};"><b>MAC</b></td><td>{device.mac}
                {' <span style="color:'+AMBER+';">(randomized)</span>' if device.randomized_mac else ''}</td></tr>
            <tr><td style="color:{GREEN_FAINT};"><b>IP</b></td><td>{device.ip or '-'}</td></tr>
            <tr><td style="color:{GREEN_FAINT};"><b>IPv6</b></td><td>{device.ipv6 or '-'}</td></tr>
            <tr><td style="color:{GREEN_FAINT};"><b>Vendor</b></td><td>{device.vendor or '-'}</td></tr>
            <tr><td style="color:{GREEN_FAINT};"><b>OS</b></td><td>{device.os_guess or '-'}</td></tr>
            <tr><td style="color:{GREEN_FAINT};"><b>Type</b></td><td>{device.device_type or '-'}</td></tr>
            <tr><td style="color:{GREEN_FAINT};"><b>Protocols</b></td><td>{', '.join(sorted(device.protocols_seen)) or '-'}</td></tr>
            <tr><td style="color:{GREEN_FAINT};"><b>Packets</b></td><td>{device.packet_count}</td></tr>
            <tr><td style="color:{GREEN_FAINT};"><b>First seen</b></td><td>{first_seen_str}</td></tr>
            <tr><td style="color:{GREEN_FAINT};"><b>Tags</b></td><td>{device.tags or '-'}</td></tr>
            <tr><td style="color:{GREEN_FAINT};"><b>Note</b></td><td>{device.note or '-'}</td></tr>
            <tr><td style="color:{GREEN_FAINT};"><b>Risk factors</b></td><td style="color:{rc};">{', '.join(reasons) or '-'}</td></tr>
          </table>
        """
        if fps:
            html += f'<h4 style="color:{CYAN}; margin:10px 0 4px;">Fingerprints</h4><table cellpadding="3" style="width:100%;">'
            for fp in fps:
                html += f'<tr><td style="color:{GREEN_FAINT};">{fp["kind"]}</td><td>{fp["value"]} {("("+fp["detail"]+")") if fp["detail"] else ""}</td></tr>'
            html += "</table>"
        if services:
            html += f'<h4 style="color:{CYAN}; margin:10px 0 4px;">Services</h4><table cellpadding="3" style="width:100%;">'
            for svc in services[:20]:
                html += (f'<tr><td style="color:{GREEN_FAINT};">{svc.get("protocol","")}</td>'
                         f'<td>{svc.get("service_name","") or "-"}</td>'
                         f'<td>{svc.get("service_type","") or "-"}</td>'
                         f'<td>{svc.get("port","") or "-"}</td></tr>')
            html += "</table>"
        html += "</div>"
        self._detail_panel.setHtml(html)

    def _device_context_menu(self, pos):
        item = self._device_table.itemAt(pos)
        if not item:
            return
        row = item.row()
        mac_item = self._device_table.item(row, 1)
        if not mac_item:
            return
        mac = mac_item.data(Qt.UserRole) or mac_item.text()
        device = self.device_manager.get_device(mac)
        menu = QMenu(self)
        act_alias = menu.addAction("Set alias...")
        act_note = menu.addAction("Set note...")
        watch_label = "Remove from watchlist" if (device and device.watchlist) else "Add to watchlist"
        act_watch = menu.addAction(watch_label)
        menu.addSeparator()
        act_copy = menu.addAction("Copy MAC")
        chosen = menu.exec_(self._device_table.viewport().mapToGlobal(pos))
        if chosen == act_alias:
            text, ok = QInputDialog.getText(self, "Set alias", f"Alias for {mac}:",
                                            text=(device.alias if device else ""))
            if ok:
                self.device_manager.set_tag(mac, alias=text)
                self._update_device_row(self.device_manager.get_device(mac))
        elif chosen == act_note:
            text, ok = QInputDialog.getText(self, "Set note", f"Note for {mac}:",
                                            text=(device.note if device else ""))
            if ok:
                self.device_manager.set_tag(mac, note=text)
        elif chosen == act_watch:
            self.device_manager.toggle_watchlist(mac)
            self._update_device_row(self.device_manager.get_device(mac))
        elif chosen == act_copy:
            from PyQt5.QtWidgets import QApplication
            QApplication.clipboard().setText(mac)

    def _filter_devices(self, text: str):
        text = text.lower()
        for row in range(self._device_table.rowCount()):
            match = False
            for col in range(self._device_table.columnCount()):
                item = self._device_table.item(row, col)
                if item and text in item.text().lower():
                    match = True
                    break
            self._device_table.setRowHidden(row, not match)

    # ------------------------------------------------------------------ #
    #  Live packets                                                       #
    # ------------------------------------------------------------------ #
    def _refresh_live(self):
        table = self._live_table
        # Preserve the user's inspection: don't rebuild the list (and lose the
        # selection / detail panes) while a packet row is selected.
        if table.currentRow() >= 0:
            return
        ring = self.sniffer.get_ring()
        recent = ring[-200:]
        self._ring_index = recent
        table.setRowCount(0)
        for entry in recent:
            r = table.rowCount()
            table.insertRow(r)
            ts = datetime.fromtimestamp(entry["ts"]).strftime("%H:%M:%S")
            proto = entry.get("protocol", "") or "-"
            cells = [ts, proto, str(entry.get("length", 0)), entry.get("summary", "")[:120], str(r)]
            for c, val in enumerate(cells):
                it = QTableWidgetItem(val)
                if c == 1:
                    it.setForeground(QColor(PROTOCOL_COLORS.get(proto, NEON)))
                table.setItem(r, c, it)
        table.scrollToBottom()

    def _on_live_selected(self, row, col, prev_row, prev_col):
        if row < 0 or row >= len(self._ring_index):
            return
        entry = self._ring_index[row]
        pkt = entry.get("pkt")
        if pkt is None:
            return
        self._detail_tree.show_layers(dissect_layers(pkt))
        try:
            self._hex_view.set_data(bytes(pkt))
        except Exception:
            self._hex_view.set_data(b"")

    # ------------------------------------------------------------------ #
    #  Periodic refresh                                                   #
    # ------------------------------------------------------------------ #
    def _refresh_stats(self):
        devices = self.device_manager.get_devices()
        self._stat_devices.set_value(str(len(devices)))
        self._stat_packets.set_value(f"{self.sniffer.packet_count:,}")
        active = self.device_manager.get_active_devices(300)
        self._stat_active.set_value(str(len(active)))

        proto_stats = self.db.get_protocol_stats()
        self._stat_protocols.set_value(str(len(proto_stats)))
        self._proto_bar.set_data(proto_stats)

        alert_counts = self.db.get_alert_counts()
        total_alerts = sum(alert_counts.values())
        self._stat_alerts.set_value(str(total_alerts))

        units = self.settings.get("locale.byte_units", "IEC")
        bps = self.sniffer.bytes_per_second
        self._stat_throughput.set_value(f"{_human_bytes(bps, units)}/s")

        uptime = self.sniffer.uptime
        if uptime > 0:
            self._stat_uptime.set_value(f"{int(uptime // 60)}m {int(uptime % 60)}s")
        else:
            self._stat_uptime.set_value("—")

        pps = self.sniffer.packets_per_second
        self._io_graph.push(pps, bps)
        self._pps_label.setText(
            f"  {pps:.1f} pkt/s · {_human_bytes(bps, units)}/s · buf {len(self.sniffer.get_ring())} ")

        # Network graph is cheap to feed and self-throttles; update always so it
        # is current the moment the user switches to the Network Map tab.
        connections = self.db.get_connections()
        self._graph_widget.update_connections(connections)
        self._graph_widget.set_risk_map({d.mac.lower(): d.risk_score for d in devices})

        # Heavy table rebuilds happen ONLY for the currently visible tab, so we
        # never spend CPU re-populating tables the user cannot see.
        name = self._current_tab_name()
        if name == "live":
            self._refresh_live()
        elif name == "alerts":
            self._refresh_alerts()
        elif name == "conversations":
            self._refresh_conversations()
        elif name == "events":
            self._refresh_events()
        elif name == "dns":
            self._refresh_dns()
        elif name == "io":
            self._refresh_talkers()
        elif name == "hierarchy":
            self._refresh_hierarchy(proto_stats)
        elif name == "statistics":
            self._refresh_statistics_tab(proto_stats, devices)

    def _current_tab_name(self) -> str:
        idx = self._tabs.currentIndex() if hasattr(self, "_tabs") else -1
        return self._tab_names.get(idx, "")

    def _refresh_events(self):
        events = self.db.get_recent_events(200)
        t = self._event_table
        t.setSortingEnabled(False)
        t.setRowCount(0)
        for ev in events:
            r = t.rowCount()
            t.insertRow(r)
            ts = datetime.fromtimestamp(ev["timestamp"]).strftime("%H:%M:%S")
            proto = ev.get("protocol", "")
            cells = [ts, proto, ev.get("source_mac", "") or ev.get("source_ip", ""),
                     ev.get("dest_mac", "") or ev.get("dest_ip", ""),
                     ev.get("event_type", ""), ev.get("summary", "")]
            for c, val in enumerate(cells):
                it = QTableWidgetItem(str(val or ""))
                if c == 1:
                    it.setForeground(QColor(PROTOCOL_COLORS.get(proto, NEON)))
                t.setItem(r, c, it)
        t.setSortingEnabled(True)

    def _refresh_dns(self):
        dns_data = self.db.get_top_dns_queries(60)
        t = self._dns_table
        t.setSortingEnabled(False)
        t.setRowCount(0)
        for entry in dns_data:
            r = t.rowCount()
            t.insertRow(r)
            t.setItem(r, 0, QTableWidgetItem(entry["query_name"]))
            ci = QTableWidgetItem()
            ci.setData(Qt.DisplayRole, entry["cnt"])
            t.setItem(r, 1, ci)
        t.setSortingEnabled(True)

    def _refresh_alerts(self):
        alerts = self.db.get_alerts(300)
        t = self._alerts_table
        t.setRowCount(0)
        for a in alerts:
            r = t.rowCount()
            t.insertRow(r)
            ts = datetime.fromtimestamp(a["timestamp"]).strftime("%H:%M:%S")
            sev = a.get("severity", "info")
            cells = [ts, sev, a.get("category", ""),
                     a.get("mac") or a.get("ip") or "", a.get("title", "")]
            for c, val in enumerate(cells):
                it = QTableWidgetItem(str(val or ""))
                if c == 1:
                    it.setForeground(QColor(severity_color(sev)))
                    f = it.font(); f.setBold(True); it.setFont(f)
                t.setItem(r, c, it)

    def _refresh_conversations(self):
        convs = self.db.get_conversations(400)
        t = self._conv_table
        t.setSortingEnabled(False)
        t.setRowCount(0)
        for c in convs:
            r = t.rowCount()
            t.insertRow(r)
            vals = [c.get("src_ip", ""), c.get("dst_ip", ""), c.get("proto", ""),
                    c.get("src_port"), c.get("dst_port"), c.get("packets"), c.get("bytes")]
            for col, val in enumerate(vals):
                it = QTableWidgetItem()
                if isinstance(val, int):
                    it.setData(Qt.DisplayRole, val)
                else:
                    it.setText(str(val or ""))
                t.setItem(r, col, it)
        t.setSortingEnabled(True)

    def _refresh_talkers(self):
        talkers = self.db.get_top_talkers(15)
        t = self._talkers_table
        t.setRowCount(0)
        for tk in talkers:
            r = t.rowCount()
            t.insertRow(r)
            t.setItem(r, 0, QTableWidgetItem(tk.get("ip", "")))
            for col, key in ((1, "packets"), (2, "bytes")):
                it = QTableWidgetItem()
                it.setData(Qt.DisplayRole, tk.get(key, 0))
                t.setItem(r, col, it)

    def _refresh_hierarchy(self, proto_stats):
        tree = self._hierarchy_tree
        tree.clear()
        total = sum(proto_stats.values()) or 1
        # Group by rough layer for a hierarchy feel.
        groups = {
            "Link Layer": ["ARP", "LLDP", "CDP", "STP"],
            "Network Layer": ["IPv6-ND", "ICMP", "IGMP"],
            "Transport / App (UDP)": ["DHCP", "DHCPv6", "mDNS", "SSDP", "NetBIOS",
                                       "LLMNR", "DNS", "WSD", "SNMP", "NTP", "QUIC"],
            "Transport / App (TCP)": ["TLS", "HTTP"],
        }
        for gname, protos in groups.items():
            present = [(p, proto_stats[p]) for p in protos if p in proto_stats]
            if not present:
                continue
            gsum = sum(c for _, c in present)
            gitem = QTreeWidgetItem([gname, str(gsum), f"{gsum/total*100:.1f}%"])
            gitem.setForeground(0, QColor(CYAN))
            for p, c in sorted(present, key=lambda x: -x[1]):
                ch = QTreeWidgetItem([p, str(c), f"{c/total*100:.1f}%"])
                ch.setForeground(0, QColor(PROTOCOL_COLORS.get(p, NEON)))
                gitem.addChild(ch)
            tree.addTopLevelItem(gitem)
            gitem.setExpanded(True)

    def _refresh_statistics_tab(self, proto_stats: dict, devices: list):
        self._coxcomb.set_data(proto_stats)
        total_events = sum(proto_stats.values()) if proto_stats else 1
        self._proto_detail_table.setRowCount(0)
        self._proto_detail_table.setSortingEnabled(False)
        for proto, count in sorted(proto_stats.items(), key=lambda x: -x[1]):
            r = self._proto_detail_table.rowCount()
            self._proto_detail_table.insertRow(r)
            pct = (count / total_events * 100) if total_events else 0
            ni = QTableWidgetItem(proto)
            ni.setForeground(QColor(PROTOCOL_COLORS.get(proto, NEON)))
            self._proto_detail_table.setItem(r, 0, ni)
            ci = QTableWidgetItem(); ci.setData(Qt.DisplayRole, count)
            self._proto_detail_table.setItem(r, 1, ci)
            self._proto_detail_table.setItem(r, 2, QTableWidgetItem(f"{pct:.1f}%"))
        self._proto_detail_table.setSortingEnabled(True)

        type_counts = Counter(d.device_type or "Unknown" for d in devices)
        self._dtype_table.setRowCount(0)
        for dtype, count in type_counts.most_common():
            r = self._dtype_table.rowCount()
            self._dtype_table.insertRow(r)
            tag = DEVICE_TYPE_ICONS.get(dtype, "[?]")
            self._dtype_table.setItem(r, 0, QTableWidgetItem(f"{tag} {dtype}"))
            ci = QTableWidgetItem(); ci.setData(Qt.DisplayRole, count)
            self._dtype_table.setItem(r, 1, ci)

        vendor_counts = Counter(d.vendor or "Unknown" for d in devices)
        self._vendor_table.setRowCount(0)
        for vendor, count in vendor_counts.most_common():
            r = self._vendor_table.rowCount()
            self._vendor_table.insertRow(r)
            self._vendor_table.setItem(r, 0, QTableWidgetItem(vendor))
            ci = QTableWidgetItem(); ci.setData(Qt.DisplayRole, count)
            self._vendor_table.setItem(r, 1, ci)

    # ------------------------------------------------------------------ #
    #  Export / shortcuts / lifecycle                                    #
    # ------------------------------------------------------------------ #
    def _export(self, kind: str):
        exts = {"json": ("JSON (*.json)", "ghostwire_export.json"),
                "csv": ("CSV (*.csv)", "ghostwire_devices.csv"),
                "html": ("HTML (*.html)", "ghostwire_report.html")}
        flt, default = exts[kind]
        path, _ = QFileDialog.getSaveFileName(self, f"Export {kind.upper()}", default, flt)
        if not path:
            return
        try:
            getattr(self.db, f"export_{kind}")(path)
            QMessageBox.information(self, "Export", f"{kind.upper()} written to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _install_shortcuts(self):
        # Rebuildable from settings (Hotkeys category).
        for act in getattr(self, "_shortcut_actions", []):
            self.removeAction(act)
        self._shortcut_actions = []

        def add(seq, fn):
            if not seq:
                return
            act = QAction(self)
            act.setShortcut(seq)
            act.triggered.connect(fn)
            self.addAction(act)
            self._shortcut_actions.append(act)

        s = self.settings
        add(s.get("hotkeys.search", "Ctrl+K"), lambda: self._search_input.setFocus())
        add(s.get("hotkeys.pause", "Space"), self._space_toggle)
        add(s.get("hotkeys.export", "Ctrl+E"), lambda: self._export("html"))
        add(s.get("hotkeys.open_pcap", "Ctrl+O"), self._open_pcap_dialog)
        add(s.get("hotkeys.start", "Ctrl+R"), self._start_capture)
        add(s.get("hotkeys.stop", "Ctrl+."), self._stop_capture)

    def _space_toggle(self):
        if self.sniffer.is_running:
            self._toggle_pause()

    # ------------------------------------------------------------------ #
    #  Menu bar + preferences                                            #
    # ------------------------------------------------------------------ #
    def _build_menu(self):
        bar = self.menuBar()
        m_file = bar.addMenu(tr("File"))
        m_file.addAction(tr("Open PCAP"), self._open_pcap_dialog)
        m_file.addAction(tr("Save PCAP"), self._save_pcap)
        exp = m_file.addMenu(tr("Export"))
        exp.addAction("JSON", lambda: self._export("json"))
        exp.addAction("CSV", lambda: self._export("csv"))
        exp.addAction("HTML", lambda: self._export("html"))
        m_file.addSeparator()
        m_file.addAction(tr("Quit"), self.close)

        m_cap = bar.addMenu(tr("Capture"))
        m_cap.addAction(tr("Start"), self._start_capture)
        m_cap.addAction(tr("Pause"), self._toggle_pause)
        m_cap.addAction(tr("Stop"), self._stop_capture)

        m_set = bar.addMenu(tr("Settings"))
        m_set.addAction(tr("Preferences..."), self._open_preferences)

        m_help = bar.addMenu(tr("Help"))
        m_help.addAction(tr("About"), self._show_about)

    def _open_preferences(self):
        from gui.settings_dialog import SettingsDialog
        factory = None
        try:
            from gui.netconfig_panel import build_netconfig_panel
            factory = lambda parent: build_netconfig_panel(parent, self.settings, self.db)
        except Exception:
            factory = None
        dlg = SettingsDialog(self.settings, self, netconfig_factory=factory)
        dlg.exec_()

    def _show_about(self):
        QMessageBox.information(
            self, tr("About"),
            "GhostWire — Passive Network Scanner\n\n"
            "The capture engine is strictly passive (no packets transmitted).\n"
            "The optional 'System Network' module is a separate, manual admin\n"
            "tool and is NOT part of the passive guarantee.")

    # ------------------------------------------------------------------ #
    #  Live settings application                                         #
    # ------------------------------------------------------------------ #
    def _apply_all_settings(self):
        self._apply_qss()
        self._apply_window_prefs()
        self._apply_matrix()
        self._apply_graph()
        self._apply_columns()
        # refresh interval
        self._refresh_timer.setInterval(int(self.settings.get("capture.refresh_ms", 2000)))

    def _apply_qss(self):
        scheme = self.settings.get("appearance.color_scheme", "neon-green")
        font_size = int(self.settings.get("appearance.font_size", 13))
        use_pixel = bool(self.settings.get("appearance.pixel_font", True))
        self.setStyleSheet(build_qss(scheme, font_size, pixel_accent_qss(use_pixel)))

    def _apply_window_prefs(self):
        op = float(self.settings.get("appearance.window_opacity", 1.0))
        self.setWindowOpacity(op)
        flag = bool(self.settings.get("appearance.always_on_top", False))
        # Toggling the flag needs a re-show; only do it if it actually changed.
        cur = bool(self.windowFlags() & Qt.WindowStaysOnTopHint)
        if flag != cur:
            self.setWindowFlag(Qt.WindowStaysOnTopHint, flag)
            self.show()
        self.statusBar().setVisible(bool(self.settings.get("appearance.statusbar", True)))
        pos = self.settings.get("appearance.tab_position", "top")
        self._tabs.setTabPosition({
            "top": QTabWidget.North, "bottom": QTabWidget.South,
            "left": QTabWidget.West, "right": QTabWidget.East,
        }.get(pos, QTabWidget.North))

    def _apply_matrix(self):
        rain = self.centralWidget().rain
        enabled = bool(self.settings.get("matrix.enabled", True))
        rain.setVisible(enabled)
        if hasattr(rain, "apply_settings"):
            rain.apply_settings(self.settings)

    def _apply_graph(self):
        if hasattr(self._graph_widget, "apply_settings"):
            self._graph_widget.apply_settings(self.settings)

    def _apply_columns(self):
        # Device table column visibility.
        cols = self.settings.get("devices.columns", {})
        for i, name in enumerate(["Type", "MAC", "IP", "Host/Alias", "Vendor",
                                  "OS", "Risk", "Protocols", "Pkts", "Last Seen"]):
            self._device_table.setColumnHidden(i, not cols.get(name, True))
        # Live packet column visibility (keep hidden index #4).
        live_cols = self.settings.get("live.columns", {})
        for i, name in enumerate(["Time", "Proto", "Len", "Summary"]):
            self._live_table.setColumnHidden(i, not live_cols.get(name, True))

    def _on_setting_changed(self, key: str):
        if key == "*" or key.startswith("appearance."):
            self._apply_qss()
            self._apply_window_prefs()
        if key == "*" or key.startswith("matrix."):
            self._apply_matrix()
        if key == "*" or key.startswith("graph."):
            self._apply_graph()
        if key == "*" or key in ("devices.columns", "live.columns"):
            self._apply_columns()
        if key == "*" or key == "capture.refresh_ms":
            self._refresh_timer.setInterval(int(self.settings.get("capture.refresh_ms", 2000)))
        if key == "*" or key.startswith("hotkeys."):
            self._install_shortcuts()
        if key == "*" or key.startswith(("security.", "risk.", "dns.")):
            try:
                self.device_manager.analytics.apply_settings(self.settings)
            except Exception:
                pass
        if key == "*" or key == "locale.language":
            from core.i18n import set_language
            set_language(self.settings.get("locale.language", "en"))
            self._retranslate()

    def _retranslate(self):
        """Re-label tabs/menus/columns/cards after a language switch."""
        names = ["Devices", "Network Map", "Live Packets", "Alerts", "Conversations",
                 "Event Log", "DNS", "IO Graph", "Protocol Tree", "Statistics"]
        for i, n in enumerate(names):
            self._tabs.setTabText(i, tr(n))
        self.menuBar().clear()
        self._build_menu()
        headers = ["Type", "MAC", "IP", "Host/Alias", "Vendor", "OS", "Risk",
                   "Protocols", "Pkts", "Last Seen"]
        self._device_table.setHorizontalHeaderLabels([tr(h) for h in headers])
        # Stat card titles + placeholders.
        for card, key in ((self._stat_devices, "DEVICES"), (self._stat_packets, "PACKETS"),
                          (self._stat_protocols, "PROTOCOLS"), (self._stat_active, "ACTIVE 5m"),
                          (self._stat_alerts, "ALERTS"), (self._stat_throughput, "THROUGHPUT"),
                          (self._stat_uptime, "UPTIME")):
            card.set_title(tr(key))
        self._search_input.setPlaceholderText(tr("filter by MAC / IP / host / vendor / OS / tag ..."))
        self._start_btn.setText(f"▶ {tr('Start')}")
        self._stop_btn.setText(f"⏹ {tr('Stop')}")

    def closeEvent(self, event):
        if self.settings.get("appearance.confirm_on_quit", False):
            if QMessageBox.question(self, tr("Quit"), "Quit GhostWire?") != QMessageBox.Yes:
                event.ignore()
                return
        try:
            self.settings.set("window.geometry", bytes(self.saveGeometry()).hex(), save=False)
            self.settings.set("window.last_tab", self._tabs.currentIndex())
        except Exception:
            pass
        self.sniffer.stop()
        self.db.close()
        event.accept()


def _human_bytes(n: float, units: str = "IEC") -> str:
    base = 1000 if units == "SI" else 1024
    suffixes = ("B", "KB", "MB", "GB") if units == "SI" else ("B", "KiB", "MiB", "GiB")
    for unit in suffixes:
        if n < base:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= base
    return f"{n:.1f}{'TB' if units == 'SI' else 'TiB'}"


def format_mac(mac: str, fmt: str = "colon-lower") -> str:
    """Reformat a colon-lower MAC per the user's preference."""
    if not mac:
        return mac
    hexes = mac.replace(":", "").replace("-", "").replace(".", "")
    if len(hexes) != 12:
        return mac
    pairs = [hexes[i:i + 2] for i in range(0, 12, 2)]
    if fmt == "colon-upper":
        return ":".join(pairs).upper()
    if fmt == "dash":
        return "-".join(pairs).lower()
    if fmt == "dot":
        return ".".join(hexes[i:i + 4] for i in range(0, 12, 4)).lower()
    return ":".join(pairs).lower()
