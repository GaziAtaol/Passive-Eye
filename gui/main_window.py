"""Main application window."""
import os
import sys
import time
import json
from datetime import datetime
from collections import Counter

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QLabel, QPushButton,
    QComboBox, QStatusBar, QSplitter, QTextEdit, QGroupBox, QGridLayout,
    QFileDialog, QMessageBox, QAbstractItemView, QFrame, QApplication,
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject, QRectF, QPointF
from PyQt5.QtGui import QFont, QColor, QIcon, QPainter, QPen, QBrush, QPainterPath

import math

from gui.theme import (
    DARK_THEME, PROTOCOL_COLORS, DEVICE_TYPE_ICONS,
    PARCHMENT, PARCHMENT_DARK, INK, INK_FAINT, RULE,
)
from gui.network_graph import NetworkGraphWidget
from core.sniffer import Sniffer
from core.device_manager import DeviceManager, Device
from core.database import Database


class SignalBridge(QObject):
    """Thread-safe signal bridge for callbacks from sniffer thread."""
    device_updated = pyqtSignal(object, bool)  # (Device, is_new)
    packet_received = pyqtSignal(str)  # summary text


class StatCard(QFrame):
    """Plain bordered statistics card (styled by the global QSS)."""
    def __init__(self, title: str, value: str = "0", parent=None):
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
        self._title_label.setAlignment(Qt.AlignLeft)

        layout.addWidget(self._value_label)
        layout.addWidget(self._title_label)

    def set_value(self, value: str):
        self._value_label.setText(value)


class ProtocolBarWidget(QWidget):
    """Horizontal stacked bar showing protocol distribution."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(32)
        self.setMaximumHeight(32)
        self._data = {}

    def set_data(self, data: dict):
        self._data = data
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(PARCHMENT))
        p.setPen(QPen(QColor(RULE), 1))
        p.drawRect(0, 0, self.width() - 1, self.height() - 1)

        if not self._data:
            p.end()
            return

        total = sum(self._data.values())
        if total == 0:
            p.end()
            return

        x = 1
        w = self.width() - 2
        h = self.height() - 2

        for proto, count in sorted(self._data.items(), key=lambda x: -x[1]):
            bar_w = max(2, (count / total) * w)
            colour = QColor(PROTOCOL_COLORS.get(proto, INK_FAINT))
            p.setBrush(QBrush(colour))
            p.setPen(QPen(QColor(RULE), 1))
            p.drawRect(int(x), 1, int(bar_w), h)

            if bar_w > 60:
                p.setPen(QColor(INK))
                p.setFont(QFont("Times New Roman", 9, QFont.Bold))
                p.drawText(int(x + 6), 1, int(bar_w - 12), h,
                           Qt.AlignVCenter | Qt.AlignLeft,
                           f"{proto}  {count}")
            x += bar_w

        p.end()


class CoxcombWidget(QWidget):
    """Polar-area (Nightingale rose) diagram. Wedge area is proportional to count."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(280)
        self._data: dict = {}

    def set_data(self, data: dict):
        self._data = data
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(PARCHMENT))
        p.setRenderHint(QPainter.Antialiasing, True)

        p.setPen(QColor(INK))
        p.setFont(QFont("Times New Roman", 12, QFont.Bold))
        p.drawText(0, 6, self.width(), 22, Qt.AlignHCenter,
                   "Diagram of the Causes of Network Chatter")

        if not self._data:
            p.setFont(QFont("Times New Roman", 11))
            p.setPen(QColor(INK_FAINT))
            p.drawText(self.rect(), Qt.AlignCenter, "(awaiting observation)")
            p.end()
            return

        items = sorted(self._data.items(), key=lambda x: -x[1])
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
        start_angle = 90.0  # 12 o'clock, clockwise

        p.setPen(QPen(QColor(INK_FAINT), 1, Qt.DotLine))
        p.setBrush(Qt.NoBrush)
        for frac in (1 / 3, 2 / 3, 1.0):
            r = max_radius * frac
            p.drawEllipse(QPointF(cx, cy), r, r)

        # radius = sqrt(count / max) * max_r  ⇒  wedge area ∝ count
        for i, (proto, count) in enumerate(items):
            radius = math.sqrt(count / max_count) * max_radius
            colour = QColor(PROTOCOL_COLORS.get(proto, INK_FAINT))
            colour.setAlpha(190)

            path = QPainterPath()
            path.moveTo(cx, cy)
            path.arcTo(QRectF(cx - radius, cy - radius, radius * 2, radius * 2),
                       (start_angle - (i + 1) * angle_each), angle_each)
            path.closeSubpath()

            p.setBrush(QBrush(colour))
            p.setPen(QPen(QColor(INK), 1))
            p.drawPath(path)

        p.setFont(QFont("Times New Roman", 10, QFont.Bold))
        p.setPen(QColor(INK))
        for i, (proto, count) in enumerate(items):
            mid = math.radians(start_angle - (i + 0.5) * angle_each)
            lx = cx + math.cos(mid) * (max_radius + 18)
            ly = cy - math.sin(mid) * (max_radius + 18)
            p.drawText(QRectF(lx - 40, ly - 8, 80, 16),
                       Qt.AlignCenter, proto)

        p.end()


class MainWindow(QMainWindow):
    def __init__(self, db_path: str = "passive_scanner.db"):
        super().__init__()
        self.setWindowTitle("PassiveEye - Passive Network Scanner")
        self.setMinimumSize(1200, 750)
        self.resize(1400, 850)

        self.db = Database(db_path)
        self.device_manager = DeviceManager(self.db)
        self.sniffer = Sniffer(self.device_manager)

        # Bridge sniffer-thread callbacks onto the GUI thread via Qt signals.
        self._signals = SignalBridge()
        self._signals.device_updated.connect(self._on_device_updated)
        self._signals.packet_received.connect(self._on_packet_log)
        self.device_manager.on_device_update(
            lambda dev, is_new: self._signals.device_updated.emit(dev, is_new)
        )
        self.sniffer.on_packet(
            lambda pkt, results: self._signals.packet_received.emit(
                results[0].summary if results else ""
            )
        )

        self.setStyleSheet(DARK_THEME)
        self._build_ui()

        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_stats)
        self._refresh_timer.start(2000)

        self._status_label = QLabel("Ready")
        self.statusBar().addWidget(self._status_label, 1)
        self._pps_label = QLabel("")
        self.statusBar().addPermanentWidget(self._pps_label)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(12, 8, 12, 8)
        main_layout.setSpacing(8)

        top_bar = QHBoxLayout()
        top_bar.setSpacing(12)

        title = QLabel("PassiveEye")
        title.setObjectName("titleLabel")
        top_bar.addWidget(title)
        top_bar.addStretch()

        iface_label = QLabel("Interface:")
        iface_label.setStyleSheet("font-weight: bold;")
        top_bar.addWidget(iface_label)

        self._iface_combo = QComboBox()
        self._populate_interfaces()
        top_bar.addWidget(self._iface_combo)

        self._start_btn = QPushButton("Start Capture")
        self._start_btn.setObjectName("startButton")
        self._start_btn.clicked.connect(self._start_capture)
        top_bar.addWidget(self._start_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setObjectName("stopButton")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_capture)
        top_bar.addWidget(self._stop_btn)

        export_btn = QPushButton("Export...")
        export_btn.clicked.connect(self._export_data)
        top_bar.addWidget(export_btn)

        main_layout.addLayout(top_bar)

        stats_bar = QHBoxLayout()
        stats_bar.setSpacing(10)

        self._stat_devices = StatCard("Devices Discovered")
        self._stat_packets = StatCard("Packets Captured")
        self._stat_protocols = StatCard("Protocols Seen")
        self._stat_active = StatCard("Active (5 min)")
        self._stat_uptime = StatCard("Capture Uptime")

        for card in (self._stat_devices, self._stat_packets, self._stat_protocols,
                     self._stat_active, self._stat_uptime):
            stats_bar.addWidget(card)

        main_layout.addLayout(stats_bar)

        self._proto_bar = ProtocolBarWidget()
        main_layout.addWidget(self._proto_bar)

        tabs = QTabWidget()
        main_layout.addWidget(tabs, 1)

        tabs.addTab(self._build_devices_tab(), "Devices")
        tabs.addTab(self._build_graph_tab(), "Network Map")
        tabs.addTab(self._build_events_tab(), "Event Log")
        tabs.addTab(self._build_dns_tab(), "DNS Analytics")
        tabs.addTab(self._build_statistics_tab(), "Statistics")

    def _build_devices_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 4, 0, 0)

        filter_bar = QHBoxLayout()
        self._search_input = None
        try:
            from PyQt5.QtWidgets import QLineEdit
            self._search_input = QLineEdit()
            self._search_input.setPlaceholderText("Filter devices by MAC, IP, hostname, vendor...")
            self._search_input.textChanged.connect(self._filter_devices)
            filter_bar.addWidget(self._search_input)
        except Exception:
            pass
        layout.addLayout(filter_bar)

        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter, 1)

        self._device_table = QTableWidget()
        self._device_table.setColumnCount(9)
        self._device_table.setHorizontalHeaderLabels([
            "Type", "MAC Address", "IP Address", "Hostname",
            "Vendor", "OS", "Protocols", "Packets", "Last Seen",
        ])
        self._device_table.setAlternatingRowColors(True)
        self._device_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._device_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._device_table.horizontalHeader().setStretchLastSection(True)
        self._device_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._device_table.setColumnWidth(0, 60)
        self._device_table.setColumnWidth(1, 140)
        self._device_table.setColumnWidth(2, 120)
        self._device_table.setColumnWidth(3, 160)
        self._device_table.setColumnWidth(4, 120)
        self._device_table.setColumnWidth(5, 100)
        self._device_table.setColumnWidth(6, 140)
        self._device_table.setColumnWidth(7, 70)
        self._device_table.setSortingEnabled(True)
        self._device_table.currentCellChanged.connect(self._on_device_selected)
        splitter.addWidget(self._device_table)

        self._detail_panel = QTextEdit()
        self._detail_panel.setReadOnly(True)
        self._detail_panel.setMaximumHeight(200)
        self._detail_panel.setPlaceholderText("Select a device to see details...")
        splitter.addWidget(self._detail_panel)

        splitter.setSizes([500, 200])
        return widget

    def _build_graph_tab(self) -> QWidget:
        self._graph_widget = NetworkGraphWidget()
        return self._graph_widget

    def _build_events_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 4, 0, 0)

        self._event_table = QTableWidget()
        self._event_table.setColumnCount(6)
        self._event_table.setHorizontalHeaderLabels([
            "Time", "Protocol", "Source", "Destination", "Type", "Summary",
        ])
        self._event_table.setAlternatingRowColors(True)
        self._event_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._event_table.horizontalHeader().setStretchLastSection(True)
        self._event_table.setColumnWidth(0, 90)
        self._event_table.setColumnWidth(1, 80)
        self._event_table.setColumnWidth(2, 130)
        self._event_table.setColumnWidth(3, 130)
        self._event_table.setColumnWidth(4, 80)
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
        self._dns_table.setColumnWidth(0, 500)
        self._dns_table.setSortingEnabled(True)
        layout.addWidget(self._dns_table, 1)

        return widget

    def _build_statistics_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)

        rose_group = QGroupBox("Rose Diagram of the Causes of Network Chatter")
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

        dtype_group = QGroupBox("Device Type Distribution")
        dtype_layout = QVBoxLayout(dtype_group)
        self._dtype_table = QTableWidget()
        self._dtype_table.setColumnCount(2)
        self._dtype_table.setHorizontalHeaderLabels(["Device Type", "Count"])
        self._dtype_table.setAlternatingRowColors(True)
        self._dtype_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._dtype_table.horizontalHeader().setStretchLastSection(True)
        dtype_layout.addWidget(self._dtype_table)
        layout.addWidget(dtype_group)

        vendor_group = QGroupBox("Vendor Distribution")
        vendor_layout = QVBoxLayout(vendor_group)
        self._vendor_table = QTableWidget()
        self._vendor_table.setColumnCount(2)
        self._vendor_table.setHorizontalHeaderLabels(["Vendor", "Devices"])
        self._vendor_table.setAlternatingRowColors(True)
        self._vendor_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._vendor_table.horizontalHeader().setStretchLastSection(True)
        vendor_layout.addWidget(self._vendor_table)
        layout.addWidget(vendor_group)

        return widget

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

        self.sniffer.start(interface=iface)
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._iface_combo.setEnabled(False)
        self._status_label.setText(f"Capturing on {iface or 'all interfaces'}...")
        QTimer.singleShot(1000, self._check_sniffer_error)

    def _check_sniffer_error(self):
        if self.sniffer.error:
            QMessageBox.critical(self, "Capture Error", self.sniffer.error)
            self._stop_capture()

    def _stop_capture(self):
        self.sniffer.stop()
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._iface_combo.setEnabled(True)
        self._status_label.setText("Capture stopped")

    def _on_device_updated(self, device: Device, is_new: bool):
        """Handle device update signal (thread-safe via signal)."""
        self._update_device_row(device)
        self._graph_widget.update_device(device)

    def _on_packet_log(self, summary: str):
        """Handle new packet log entry."""
        pass  # Events are loaded in bulk during refresh

    def _update_device_row(self, device: Device):
        """Add or update a row in the device table."""
        table = self._device_table
        mac = device.mac

        # Find existing row
        row = -1
        for r in range(table.rowCount()):
            item = table.item(r, 1)
            if item and item.text() == mac:
                row = r
                break

        if row == -1:
            table.setSortingEnabled(False)
            row = table.rowCount()
            table.insertRow(row)

        icon = DEVICE_TYPE_ICONS.get(device.device_type, "[?]")
        last_seen = datetime.fromtimestamp(device.last_seen).strftime("%H:%M:%S") if device.last_seen else ""
        protocols = ", ".join(sorted(device.protocols_seen)) if device.protocols_seen else ""

        items = [
            icon,
            mac,
            device.ip or "",
            device.hostname or "",
            device.vendor or "",
            device.os_guess or "",
            protocols,
            str(device.packet_count),
            last_seen,
        ]

        for col, val in enumerate(items):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            if col == 0:
                item.setTextAlignment(Qt.AlignCenter)
            table.setItem(row, col, item)

        table.setSortingEnabled(True)

    def _on_device_selected(self, row, col, prev_row, prev_col):
        """Show device details when a row is selected."""
        if row < 0:
            return
        mac_item = self._device_table.item(row, 1)
        if not mac_item:
            return

        mac = mac_item.text()
        device = self.device_manager.get_device(mac)
        if not device:
            return

        services = self.db.get_device_services(mac)

        tag = DEVICE_TYPE_ICONS.get(device.device_type, '[?]')
        first_seen_str = (
            datetime.fromtimestamp(device.first_seen).strftime('%Y-%m-%d %H:%M:%S')
            if device.first_seen else '-'
        )
        html = f"""
        <div style="font-family: 'Times New Roman', Times, serif;
                    color: {INK}; background-color: {PARCHMENT};">
            <h3 style="margin: 0 0 8px 0; font-weight: bold;
                       border-bottom: 1px solid {RULE}; padding-bottom: 4px;">
                {tag} &nbsp; {device.hostname or device.mac}
            </h3>
            <table border="1" cellspacing="0" cellpadding="3" bgcolor="{PARCHMENT}"
                   style="border-collapse: collapse; width: 100%; border-color: {RULE};">
                <tr><td bgcolor="{PARCHMENT_DARK}"><b>MAC</b></td>
                    <td>{device.mac}</td></tr>
                <tr><td bgcolor="{PARCHMENT_DARK}"><b>IP</b></td>
                    <td>{device.ip or '-'}</td></tr>
                <tr><td bgcolor="{PARCHMENT_DARK}"><b>IPv6</b></td>
                    <td>{device.ipv6 or '-'}</td></tr>
                <tr><td bgcolor="{PARCHMENT_DARK}"><b>Vendor</b></td>
                    <td>{device.vendor or '-'}</td></tr>
                <tr><td bgcolor="{PARCHMENT_DARK}"><b>Operating System</b></td>
                    <td>{device.os_guess or '-'}</td></tr>
                <tr><td bgcolor="{PARCHMENT_DARK}"><b>Type</b></td>
                    <td>{device.device_type or '-'}</td></tr>
                <tr><td bgcolor="{PARCHMENT_DARK}"><b>Protocols heard</b></td>
                    <td>{', '.join(sorted(device.protocols_seen)) or '-'}</td></tr>
                <tr><td bgcolor="{PARCHMENT_DARK}"><b>Packets</b></td>
                    <td>{device.packet_count}</td></tr>
                <tr><td bgcolor="{PARCHMENT_DARK}"><b>First observed</b></td>
                    <td>{first_seen_str}</td></tr>
            </table>
        """

        if services:
            html += f"""
            <h4 style="margin: 12px 0 4px 0;">Discovered Services</h4>
            <table border="1" cellspacing="0" cellpadding="3" bgcolor="{PARCHMENT}"
                   style="border-collapse: collapse; width: 100%; border-color: {RULE};">
                <tr bgcolor="{PARCHMENT_DARK}">
                    <th align="left"><b>Protocol</b></th>
                    <th align="left"><b>Service</b></th>
                    <th align="left"><b>Type</b></th>
                    <th align="left"><b>Port</b></th>
                </tr>
            """
            for svc in services:
                html += (
                    "<tr>"
                    f"<td>{svc.get('protocol', '')}</td>"
                    f"<td>{svc.get('service_name', '') or '-'}</td>"
                    f"<td>{svc.get('service_type', '') or '-'}</td>"
                    f"<td>{svc.get('port', '') or '-'}</td>"
                    "</tr>"
                )
            html += "</table>"

        if device.metadata:
            meta_items = {k: v for k, v in device.metadata.items()
                          if k not in ("arp_type",) and v}
            if meta_items:
                html += f"""
                <h4 style="margin: 12px 0 4px 0;">Metadata</h4>
                <table border="1" cellspacing="0" cellpadding="3" bgcolor="{PARCHMENT}"
                       style="border-collapse: collapse; width: 100%; border-color: {RULE};">
                """
                for k, v in list(meta_items.items())[:10]:
                    val = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
                    if len(val) > 120:
                        val = val[:120] + "..."
                    html += (
                        "<tr>"
                        f"<td bgcolor=\"{PARCHMENT_DARK}\"><b>{k}</b></td>"
                        f"<td>{val}</td>"
                        "</tr>"
                    )
                html += "</table>"

        html += "</div>"
        self._detail_panel.setHtml(html)

    def _filter_devices(self, text: str):
        """Filter device table by search text."""
        text = text.lower()
        for row in range(self._device_table.rowCount()):
            match = False
            for col in range(self._device_table.columnCount()):
                item = self._device_table.item(row, col)
                if item and text in item.text().lower():
                    match = True
                    break
            self._device_table.setRowHidden(row, not match)

    def _refresh_stats(self):
        """Periodically refresh statistics and other panels."""
        # Stat cards
        devices = self.device_manager.get_devices()
        self._stat_devices.set_value(str(len(devices)))
        self._stat_packets.set_value(f"{self.sniffer.packet_count:,}")
        active = self.device_manager.get_active_devices(300)
        self._stat_active.set_value(str(len(active)))

        proto_stats = self.db.get_protocol_stats()
        self._stat_protocols.set_value(str(len(proto_stats)))
        self._proto_bar.set_data(proto_stats)

        uptime = self.sniffer.uptime
        if uptime > 0:
            mins = int(uptime // 60)
            secs = int(uptime % 60)
            self._stat_uptime.set_value(f"{mins}m {secs}s")
        else:
            self._stat_uptime.set_value("—")

        # PPS
        pps = self.sniffer.packets_per_second
        if pps > 0:
            self._pps_label.setText(f"  {pps:.1f} pkt/s  ")

        # Event log table
        events = self.db.get_recent_events(200)
        self._event_table.setRowCount(0)
        self._event_table.setSortingEnabled(False)
        for ev in events[:200]:
            row = self._event_table.rowCount()
            self._event_table.insertRow(row)
            ts = datetime.fromtimestamp(ev["timestamp"]).strftime("%H:%M:%S")
            items = [
                ts,
                ev.get("protocol", ""),
                ev.get("source_mac", "") or ev.get("source_ip", ""),
                ev.get("dest_mac", "") or ev.get("dest_ip", ""),
                ev.get("event_type", ""),
                ev.get("summary", ""),
            ]
            for col, val in enumerate(items):
                item = QTableWidgetItem(str(val or ""))
                self._event_table.setItem(row, col, item)
        self._event_table.setSortingEnabled(True)

        # DNS table
        dns_data = self.db.get_top_dns_queries(50)
        self._dns_table.setRowCount(0)
        self._dns_table.setSortingEnabled(False)
        for entry in dns_data:
            row = self._dns_table.rowCount()
            self._dns_table.insertRow(row)
            self._dns_table.setItem(row, 0, QTableWidgetItem(entry["query_name"]))
            count_item = QTableWidgetItem()
            count_item.setData(Qt.DisplayRole, entry["cnt"])
            self._dns_table.setItem(row, 1, count_item)
        self._dns_table.setSortingEnabled(True)

        # Statistics tab
        self._refresh_statistics_tab(proto_stats, devices)

        # Network graph connections
        connections = self.db.get_connections()
        self._graph_widget.update_connections(connections)

    def _refresh_statistics_tab(self, proto_stats: dict, devices: list):
        # Rose diagram
        self._coxcomb.set_data(proto_stats)

        # Protocol table
        total_events = sum(proto_stats.values()) if proto_stats else 1
        self._proto_detail_table.setRowCount(0)
        self._proto_detail_table.setSortingEnabled(False)
        for proto, count in sorted(proto_stats.items(), key=lambda x: -x[1]):
            row = self._proto_detail_table.rowCount()
            self._proto_detail_table.insertRow(row)
            pct = (count / total_events * 100) if total_events else 0

            name_item = QTableWidgetItem(proto)
            self._proto_detail_table.setItem(row, 0, name_item)

            count_item = QTableWidgetItem()
            count_item.setData(Qt.DisplayRole, count)
            self._proto_detail_table.setItem(row, 1, count_item)

            self._proto_detail_table.setItem(row, 2, QTableWidgetItem(f"{pct:.1f}%"))
        self._proto_detail_table.setSortingEnabled(True)

        # Device type table
        type_counts = Counter(d.device_type or "Unknown" for d in devices)
        self._dtype_table.setRowCount(0)
        self._dtype_table.setSortingEnabled(False)
        for dtype, count in type_counts.most_common():
            row = self._dtype_table.rowCount()
            self._dtype_table.insertRow(row)
            tag = DEVICE_TYPE_ICONS.get(dtype, "[?]")
            self._dtype_table.setItem(row, 0, QTableWidgetItem(f"{tag} {dtype}"))
            c_item = QTableWidgetItem()
            c_item.setData(Qt.DisplayRole, count)
            self._dtype_table.setItem(row, 1, c_item)
        self._dtype_table.setSortingEnabled(True)

        # Vendor table
        vendor_counts = Counter(d.vendor or "Unknown" for d in devices)
        self._vendor_table.setRowCount(0)
        self._vendor_table.setSortingEnabled(False)
        for vendor, count in vendor_counts.most_common():
            row = self._vendor_table.rowCount()
            self._vendor_table.insertRow(row)
            self._vendor_table.setItem(row, 0, QTableWidgetItem(vendor))
            c_item = QTableWidgetItem()
            c_item.setData(Qt.DisplayRole, count)
            self._vendor_table.setItem(row, 1, c_item)
        self._vendor_table.setSortingEnabled(True)

    def _export_data(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Data", "passive_scan_export.json",
            "JSON Files (*.json);;All Files (*)"
        )
        if path:
            try:
                self.db.export_json(path)
                QMessageBox.information(self, "Export", f"Data exported to:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", str(e))

    def closeEvent(self, event):
        self.sniffer.stop()
        self.db.close()
        event.accept()
