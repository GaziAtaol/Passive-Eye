"""Schema-driven Preferences dialog.

Rather than hand-wiring 200+ widgets, every control is generated from a
declarative ``SPEC``: a list of categories, each holding field descriptors.
Each control reads its value from :class:`~core.settings.Settings` and writes
back on change, so preferences apply live (the ``Settings.changed`` signal then
notifies the rest of the app).
"""
from PyQt5.QtWidgets import (
    QDialog, QHBoxLayout, QVBoxLayout, QListWidget, QStackedWidget, QWidget,
    QFormLayout, QCheckBox, QSpinBox, QDoubleSpinBox, QComboBox, QLineEdit,
    QPushButton, QLabel, QScrollArea, QColorDialog, QGridLayout, QPlainTextEdit,
    QLineEdit as _QLineEdit, QMessageBox,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from core.settings import (
    PROTOCOLS, DETECTORS, RISK_FACTORS, DEVICE_COLUMNS, COLOR_SCHEMES,
)
from core.i18n import tr
from gui.theme import NEON, CYAN, AMBER, RED, GREEN_FAINT, PANEL, BG_ALT, DIM

TAB_NAMES = ["Devices", "Network Map", "Live Packets", "Alerts", "Conversations",
             "Event Log", "DNS", "IO Graph", "Protocol Tree", "Statistics"]


def _field(key, label, ftype, **kw):
    d = {"key": key, "label": label, "type": ftype}
    d.update(kw)
    return d


# ---- The full settings schema (drives the whole dialog) -------------------
SPEC = [
    ("Appearance", [
        _field("appearance.color_scheme", "Color scheme", "choice", options=COLOR_SCHEMES),
        _field("appearance.pixel_font", "Pixel font (titles/tabs)", "bool"),
        _field("appearance.font_size", "Base font size", "int", min=7, max=20),
        _field("appearance.ui_scale", "UI scale", "float", min=0.8, max=1.6, step=0.1),
        _field("appearance.window_opacity", "Window opacity", "float", min=0.5, max=1.0, step=0.05),
        _field("appearance.always_on_top", "Always on top", "bool"),
        _field("appearance.startup_tab", "Startup tab", "choice_int", options=list(range(10)), labels=TAB_NAMES),
        _field("appearance.glow", "Glow effects", "bool"),
        _field("appearance.animations", "Animations", "bool"),
        _field("appearance.countup", "Count-up stat cards", "bool"),
        _field("appearance.statusbar", "Show status bar", "bool"),
        _field("appearance.splash", "Boot splash on launch", "bool"),
        _field("appearance.tab_position", "Tab position", "choice",
               options=["top", "bottom", "left", "right"]),
        _field("appearance.row_height", "Table row height", "int", min=16, max=40),
        _field("appearance.show_tooltips", "Show tooltips", "bool"),
        _field("appearance.compact_mode", "Compact mode", "bool"),
        _field("appearance.confirm_on_quit", "Confirm on quit", "bool"),
    ]),
    ("Matrix Background", [
        _field("matrix.enabled", "Enabled", "bool"),
        _field("matrix.opacity", "Opacity", "float", min=0.0, max=1.0, step=0.05),
        _field("matrix.density", "Density", "float", min=0.2, max=2.0, step=0.1),
        _field("matrix.speed", "Speed", "float", min=0.2, max=3.0, step=0.1),
        _field("matrix.color", "Glyph color", "color"),
        _field("matrix.font_size", "Glyph size", "int", min=8, max=24),
    ]),
    ("Protocols", [
        _field("protocols.enabled", "Enabled dissectors", "group_bool", members=PROTOCOLS),
        _field("protocols.flow_tracking", "TCP/UDP flow tracking", "bool"),
    ]),
    ("Protocol Logging", [
        _field("protocols.log_events", "Log to Event Log", "group_bool", members=PROTOCOLS),
    ]),
    ("Protocol Colors", [
        _field("protocols.colors", "Per-protocol colors", "group_color", members=PROTOCOLS),
    ]),
    ("Capture", [
        _field("capture.interface", "Default interface", "text"),
        _field("capture.deep", "Deep Capture Mode by default", "bool"),
        _field("capture.promiscuous", "Promiscuous mode", "bool"),
        _field("capture.snaplen", "Snap length (0=full)", "int", min=0, max=65535),
        _field("capture.buffer", "Ring buffer size", "int", min=50, max=5000),
        _field("capture.packet_limit", "Packet limit (0=∞)", "int", min=0, max=1000000),
        _field("capture.autostart", "Auto-start capture on launch", "bool"),
        _field("capture.refresh_ms", "UI refresh interval (ms)", "int", min=250, max=10000, step=250),
        _field("capture.ignore_own_traffic", "Ignore own host traffic", "bool"),
        _field("capture.stop_after_packets", "Stop after N packets (0=∞)", "int", min=0, max=10000000),
        _field("capture.auto_save_pcap", "Auto-save capture to PCAP", "bool"),
        _field("capture.auto_save_path", "Auto-save PCAP path", "text"),
    ]),
    ("DNS", [
        _field("dns.reverse_lookup", "Reverse-DNS resolution", "bool"),
        _field("dns.resolver", "Resolver server (blank=system)", "text"),
        _field("dns.top_n", "Top-N queries shown", "int", min=5, max=500),
        _field("dns.tunnel_entropy", "Tunnel entropy threshold", "float", min=1.0, max=6.0, step=0.1),
        _field("dns.tunnel_minlen", "Tunnel min label length", "int", min=5, max=120),
        _field("dns.show_query_type", "Show query type", "bool"),
        _field("dns.highlight_suspicious", "Highlight suspicious", "bool"),
        _field("dns.cache_size", "Resolver cache size", "int", min=0, max=65536),
        _field("dns.blocklist", "Blocklisted domains", "list_text"),
    ]),
    ("Security Detectors", [
        _field("security.detectors", "Enabled detectors", "group_bool", members=DETECTORS),
        _field("security.scan_ports", "Port-scan: distinct ports", "int", min=3, max=200),
        _field("security.scan_hosts", "Port-scan: distinct hosts", "int", min=2, max=200),
        _field("security.scan_window", "Port-scan: window (s)", "int", min=1, max=120),
    ]),
    ("Risk Scoring", [
        _field("risk.enabled", "Enabled", "bool"),
        _field("risk.threshold_warn", "Warn threshold", "int", min=0, max=100),
        _field("risk.threshold_crit", "Critical threshold", "int", min=0, max=100),
        _field("risk.weights", "Factor weights", "group_int", members=RISK_FACTORS, min=0, max=100),
    ]),
    ("Alerts", [
        _field("alerts.toast", "Toast notifications", "bool"),
        _field("alerts.toast_ms", "Toast duration (ms)", "int", min=1000, max=15000, step=200),
        _field("alerts.sound", "Play sound", "bool"),
        _field("alerts.critical_only_sound", "Sound only for critical", "bool"),
        _field("alerts.retention_hours", "Alert retention (h, 0=∞)", "int", min=0, max=720),
        _field("alerts.desktop_notifications", "Desktop notifications", "bool"),
        _field("alerts.auto_acknowledge", "Auto-acknowledge", "bool"),
        _field("alerts.max_per_min", "Max alerts/min (0=∞)", "int", min=0, max=600),
    ]),
    ("Network Map", [
        _field("graph.repulsion", "Repulsion", "float", min=500, max=20000, step=100),
        _field("graph.attraction", "Attraction", "float", min=0.0, max=0.2, step=0.005),
        _field("graph.damping", "Damping", "float", min=0.5, max=0.99, step=0.01),
        _field("graph.gravity", "Center gravity", "float", min=0.0, max=0.1, step=0.005),
        _field("graph.fps", "Max FPS", "int", min=5, max=60),
        _field("graph.settle_energy", "Settle energy", "float", min=0.001, max=1.0, step=0.01),
        _field("graph.node_size", "Node size", "int", min=8, max=48),
        _field("graph.label_len", "Label length", "int", min=4, max=48),
        _field("graph.show_labels", "Show labels", "bool"),
        _field("graph.show_edges", "Show edges", "bool"),
        _field("graph.edge_scale", "Edge width scale", "float", min=0.2, max=4.0, step=0.1),
        _field("graph.edge_opacity", "Edge opacity", "float", min=0.1, max=1.0, step=0.05),
        _field("graph.highlight_routers", "Highlight routers", "bool"),
        _field("graph.color_by", "Color nodes by", "choice", options=["risk", "vendor", "type"]),
        _field("graph.freeze_when_hidden", "Freeze when tab hidden", "bool"),
    ]),
    ("Live Packets", [
        _field("live.max_rows", "Max rows", "int", min=50, max=2000, step=50),
        _field("live.autoscroll", "Auto-scroll", "bool"),
        _field("live.hex_per_line", "Hex bytes/line", "choice_int", options=[8, 16, 32]),
        _field("live.follow_selection", "Pause on selection", "bool"),
        _field("live.colorize_rows", "Colorize by protocol", "bool"),
        _field("live.columns", "Visible columns", "group_bool",
               members=["Time", "Proto", "Len", "Summary"]),
    ]),
    ("Devices / L2", [
        _field("devices.mac_format", "MAC format", "choice",
               options=["colon-lower", "colon-upper", "dash", "dot"]),
        _field("devices.show_broadcast", "Show broadcast", "bool"),
        _field("devices.show_multicast", "Show multicast", "bool"),
        _field("devices.show_local", "Show local/randomized MACs", "bool"),
        _field("devices.show_ipv6", "Show IPv6 addresses", "bool"),
        _field("devices.highlight_watchlist", "Highlight watchlist", "bool"),
        _field("devices.double_click_action", "Double-click action", "choice",
               options=["details", "watchlist", "copy-mac"]),
        _field("devices.columns", "Visible columns", "group_bool", members=DEVICE_COLUMNS),
    ]),
    ("Storage", [
        _field("storage.retention_hours", "Event retention (h, 0=∞)", "int", min=0, max=8760),
        _field("storage.autoprune", "Auto-prune old data", "bool"),
        _field("storage.autoprune_hours", "Prune older than (h)", "int", min=1, max=720),
        _field("storage.export_dir", "Default export folder", "text"),
        _field("storage.export_format", "Default export format", "choice", options=["json", "csv", "html"]),
        _field("storage.anonymize_export", "Anonymize MACs on export", "bool"),
        _field("storage.wal_mode", "SQLite WAL mode", "bool"),
        _field("storage.vacuum_on_close", "VACUUM on close", "bool"),
    ]),
    ("Hotkeys", [
        _field("hotkeys.search", "Focus search", "text"),
        _field("hotkeys.pause", "Pause/resume", "text"),
        _field("hotkeys.export", "Export", "text"),
        _field("hotkeys.open_pcap", "Open PCAP", "text"),
        _field("hotkeys.start", "Start capture", "text"),
        _field("hotkeys.stop", "Stop capture", "text"),
    ]),
    ("Localization", [
        _field("locale.language", "Language", "choice_labeled",
               options=["en", "tr"], labels=["English", "Türkçe"]),
        _field("locale.date_format", "Date format", "text"),
        _field("locale.time_format", "Time format", "text"),
        _field("locale.byte_units", "Byte units", "choice", options=["IEC", "SI"]),
    ]),
    ("Privacy", [
        _field("privacy.anonymize_mac", "Anonymize MACs in UI", "bool"),
        _field("privacy.redact_hostnames", "Redact hostnames", "bool"),
        _field("privacy.no_persist", "No-persist (memory only)", "bool"),
    ]),
    ("System Network ⚠", [
        _field("netconfig.enabled", "Enable System Network module", "bool"),
        _field("_netconfig_ui", "", "netconfig"),
    ]),
]


class _ColorButton(QPushButton):
    def __init__(self, value, on_change):
        super().__init__()
        self._value = value
        self._on_change = on_change
        self.setFixedWidth(90)
        self._apply()
        self.clicked.connect(self._pick)

    def _apply(self):
        self.setText(self._value)
        self.setStyleSheet(f"background:{self._value}; color:#000; border:1px solid {DIM};")

    def _pick(self):
        col = QColorDialog.getColor(QColor(self._value), self, "Pick color")
        if col.isValid():
            self._value = col.name()
            self._apply()
            self._on_change(self._value)


class SettingsDialog(QDialog):
    def __init__(self, settings, parent=None, netconfig_factory=None):
        super().__init__(parent)
        self.settings = settings
        self._netconfig_factory = netconfig_factory
        self.setWindowTitle(tr("Preferences"))
        self.resize(820, 620)

        outer = QVBoxLayout(self)

        # Search box
        self._search = _QLineEdit()
        self._search.setPlaceholderText(tr("Search settings..."))
        self._search.textChanged.connect(self._filter)
        outer.addWidget(self._search)

        body = QHBoxLayout()
        outer.addLayout(body, 1)

        self._list = QListWidget()
        self._list.setMaximumWidth(210)
        self._list.currentRowChanged.connect(self._on_category)
        body.addWidget(self._list)

        self._stack = QStackedWidget()
        body.addWidget(self._stack, 1)

        self._pages = []  # (category_name, page_widget, [(field, widget_row)])
        for name, fields in SPEC:
            self._list.addItem(name)
            page = self._build_page(name, fields)
            self._stack.addWidget(page)

        # Footer buttons
        footer = QHBoxLayout()
        reset = QPushButton(tr("Reset all to defaults"))
        reset.clicked.connect(self._reset_all)
        footer.addWidget(reset)
        footer.addStretch()
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        outer.addLayout(footer)

        if self._list.count():
            self._list.setCurrentRow(0)

    # -- page/control construction -----------------------------------------
    def _build_page(self, name, fields):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        form = QFormLayout(container)
        form.setLabelAlignment(Qt.AlignLeft)
        rows = []
        for f in fields:
            w = self._make_control(f)
            if w is None:
                continue
            if f["type"] in ("group_bool", "group_int", "group_color", "netconfig", "list_text"):
                lbl = QLabel(f["label"])
                lbl.setStyleSheet(f"color:{CYAN}; font-weight:bold;")
                if f["label"]:
                    form.addRow(lbl)
                form.addRow(w)
                rows.append((f, lbl))
            else:
                form.addRow(f["label"], w)
                rows.append((f, w))
        scroll.setWidget(container)
        self._pages.append((name, scroll, rows))
        return scroll

    def _make_control(self, f):
        key, ftype = f["key"], f["type"]
        cur = self.settings.get(key)

        if ftype == "bool":
            w = QCheckBox()
            w.setChecked(bool(cur))
            w.toggled.connect(lambda v, k=key: self.settings.set(k, bool(v)))
            return w
        if ftype == "int":
            w = QSpinBox()
            w.setRange(f.get("min", 0), f.get("max", 1000000))
            w.setSingleStep(f.get("step", 1))
            w.setValue(int(cur or 0))
            w.valueChanged.connect(lambda v, k=key: self.settings.set(k, int(v)))
            return w
        if ftype == "float":
            w = QDoubleSpinBox()
            w.setRange(f.get("min", 0.0), f.get("max", 1.0))
            w.setSingleStep(f.get("step", 0.1))
            w.setDecimals(3)
            w.setValue(float(cur or 0.0))
            w.valueChanged.connect(lambda v, k=key: self.settings.set(k, float(v)))
            return w
        if ftype == "choice":
            w = QComboBox()
            w.addItems([str(o) for o in f["options"]])
            if str(cur) in [str(o) for o in f["options"]]:
                w.setCurrentText(str(cur))
            w.currentTextChanged.connect(lambda v, k=key: self.settings.set(k, v))
            return w
        if ftype == "choice_int":
            w = QComboBox()
            labels = f.get("labels")
            for i, o in enumerate(f["options"]):
                w.addItem(labels[i] if labels else str(o), o)
            idx = f["options"].index(cur) if cur in f["options"] else 0
            w.setCurrentIndex(idx)
            w.currentIndexChanged.connect(
                lambda i, k=key, wd=w: self.settings.set(k, wd.itemData(i)))
            return w
        if ftype == "choice_labeled":
            w = QComboBox()
            for i, o in enumerate(f["options"]):
                w.addItem(f["labels"][i], o)
            idx = f["options"].index(cur) if cur in f["options"] else 0
            w.setCurrentIndex(idx)
            w.currentIndexChanged.connect(
                lambda i, k=key, wd=w: self.settings.set(k, wd.itemData(i)))
            return w
        if ftype == "text":
            w = QLineEdit(str(cur or ""))
            w.editingFinished.connect(lambda k=key, wd=w: self.settings.set(k, wd.text()))
            return w
        if ftype == "list_text":
            w = QPlainTextEdit("\n".join(cur or []))
            w.setMaximumHeight(120)
            def _commit(k=key, wd=w):
                lines = [l.strip() for l in wd.toPlainText().splitlines() if l.strip()]
                self.settings.set(k, lines)
            w.textChanged.connect(_commit)
            return w
        if ftype == "color":
            return _ColorButton(cur or "#00ff41", lambda v, k=key: self.settings.set(k, v))
        if ftype == "group_bool":
            return self._group_bool(key, f["members"])
        if ftype == "group_int":
            return self._group_int(key, f["members"], f.get("min", 0), f.get("max", 100))
        if ftype == "group_color":
            return self._group_color(key, f["members"])
        if ftype == "netconfig":
            return self._netconfig_panel()
        return None

    def _group_bool(self, key, members):
        cur = self.settings.get(key) or {}
        box = QWidget()
        grid = QGridLayout(box)
        grid.setContentsMargins(0, 0, 0, 0)
        for i, m in enumerate(members):
            cb = QCheckBox(m)
            cb.setChecked(bool(cur.get(m, True)))
            cb.toggled.connect(lambda v, mm=m, k=key: self._set_member(k, mm, bool(v)))
            grid.addWidget(cb, i // 3, i % 3)
        return box

    def _group_int(self, key, members, lo, hi):
        cur = self.settings.get(key) or {}
        box = QWidget()
        grid = QGridLayout(box)
        grid.setContentsMargins(0, 0, 0, 0)
        for i, m in enumerate(members):
            grid.addWidget(QLabel(m), i, 0)
            sp = QSpinBox()
            sp.setRange(lo, hi)
            sp.setValue(int(cur.get(m, 0)))
            sp.valueChanged.connect(lambda v, mm=m, k=key: self._set_member(k, mm, int(v)))
            grid.addWidget(sp, i, 1)
        return box

    def _group_color(self, key, members):
        cur = self.settings.get(key) or {}
        box = QWidget()
        grid = QGridLayout(box)
        grid.setContentsMargins(0, 0, 0, 0)
        for i, m in enumerate(members):
            grid.addWidget(QLabel(m), i // 2, (i % 2) * 2)
            btn = _ColorButton(cur.get(m, "#00ff41"),
                               lambda v, mm=m, k=key: self._set_member(k, mm, v))
            grid.addWidget(btn, i // 2, (i % 2) * 2 + 1)
        return box

    def _set_member(self, key, member, value):
        d = self.settings.get(key) or {}
        d[member] = value
        self.settings.set(key, d)

    def _netconfig_panel(self):
        if self._netconfig_factory:
            try:
                return self._netconfig_factory(self)
            except Exception:
                pass
        w = QLabel(tr("System Network controls are unavailable on this platform."))
        w.setStyleSheet(f"color:{GREEN_FAINT};")
        w.setWordWrap(True)
        return w

    # -- interaction --------------------------------------------------------
    def _on_category(self, row):
        if 0 <= row < self._stack.count():
            self._stack.setCurrentIndex(row)

    def _filter(self, text):
        text = text.lower().strip()
        # Filter categories by whether any field label matches.
        for i, (name, page, rows) in enumerate(self._pages):
            match = (not text) or (text in name.lower()) or any(
                text in f["label"].lower() for f, _ in rows)
            self._list.item(i).setHidden(not match)
        # jump to first visible
        for i in range(self._list.count()):
            if not self._list.item(i).isHidden():
                self._list.setCurrentRow(i)
                break

    def _reset_all(self):
        if QMessageBox.question(self, tr("Reset"), tr("Reset ALL settings to defaults?")) \
                == QMessageBox.Yes:
            self.settings.reset_all()
            QMessageBox.information(self, tr("Reset"),
                                    tr("Settings reset. Some changes apply after restart."))
            self.accept()
