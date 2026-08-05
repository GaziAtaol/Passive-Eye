"""System Network settings panel (opt-in, guarded) for the Preferences dialog.

Every mutating action: (1) is gated on the master toggle + root + platform,
(2) asks for confirmation, (3) is backed up first, (4) logs an alert/event, and
(5) can be reverted. The capture engine stays passive; this is a manual admin tool.
"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QFormLayout, QLabel, QComboBox, QLineEdit, QSpinBox,
    QPushButton, QCheckBox, QHBoxLayout, QMessageBox,
)
from PyQt5.QtCore import Qt

from core import netconfig
from core.i18n import tr
from gui.theme import RED, AMBER, GREEN_FAINT, CYAN


def build_netconfig_panel(parent, settings, db=None) -> QWidget:
    return _NetPanel(parent, settings, db)


class _NetPanel(QWidget):
    def __init__(self, parent, settings, db):
        super().__init__(parent)
        self.settings = settings
        self.db = db
        lay = QVBoxLayout(self)

        warn = QLabel(
            "⚠ These controls change your OPERATING SYSTEM's network settings\n"
            "(DNS, proxy, MTU, interface state). They are NOT passive, require\n"
            "root/Administrator, and can disrupt connectivity. Every change is\n"
            "backed up and can be reverted.")
        warn.setWordWrap(True)
        warn.setStyleSheet(f"color:{RED}; font-weight:bold;")
        lay.addWidget(warn)

        supported = netconfig.supported()
        root = netconfig.is_root()
        status = QLabel(
            f"platform: {netconfig.platform_name()}  ·  "
            f"root: {'yes' if root else 'NO'}  ·  "
            f"supported: {'yes' if supported else 'no'}")
        status.setStyleSheet(f"color:{CYAN};")
        lay.addWidget(status)

        self._enable = QCheckBox("I understand — enable System Network controls")
        self._enable.setChecked(bool(settings.get("netconfig.enabled", False)))
        self._enable.toggled.connect(self._on_enable)
        lay.addWidget(self._enable)

        form = QWidget()
        fl = QFormLayout(form)
        self._service = QComboBox()
        services = netconfig.list_services() if supported else []
        self._service.addItems(services or ["(none)"])
        self._service.currentTextChanged.connect(self._reload_current)
        fl.addRow("Service", self._service)

        self._dns = QLineEdit()
        self._dns.setPlaceholderText("comma/space separated, e.g. 1.1.1.1 8.8.8.8")
        dns_row = _row(self._dns, "Apply DNS", self._apply_dns)
        fl.addRow("DNS servers", dns_row)

        self._proxy_host = QLineEdit()
        self._proxy_port = QSpinBox(); self._proxy_port.setRange(0, 65535); self._proxy_port.setValue(8080)
        self._proxy_on = QCheckBox("enabled")
        prow = QHBoxLayout(); pw = QWidget(); pw.setLayout(prow)
        prow.addWidget(self._proxy_host); prow.addWidget(self._proxy_port); prow.addWidget(self._proxy_on)
        pbtn = QPushButton("Apply Proxy"); pbtn.clicked.connect(self._apply_proxy)
        prow.addWidget(pbtn)
        fl.addRow("Web proxy", pw)

        self._mtu = QSpinBox(); self._mtu.setRange(576, 9000); self._mtu.setValue(1500)
        fl.addRow("MTU", _row(self._mtu, "Apply MTU", self._apply_mtu))

        lay.addWidget(form)

        btns = QHBoxLayout()
        self._revert_btn = QPushButton("Revert this service")
        self._revert_btn.clicked.connect(self._revert)
        btns.addWidget(self._revert_btn)
        btns.addStretch()
        lay.addLayout(btns)
        lay.addStretch()

        self._form = form
        self._reload_current()
        self._update_enabled_state()

    # -- helpers -----------------------------------------------------------
    def _service_name(self):
        s = self._service.currentText()
        return s if s and s != "(none)" else ""

    def _reload_current(self):
        svc = self._service_name()
        if not svc or not netconfig.supported():
            return
        try:
            self._dns.setText(" ".join(netconfig.get_dns(svc)))
            proxy = netconfig.get_proxy(svc)
            self._proxy_host.setText(proxy.get("server", ""))
            if proxy.get("port", "").isdigit():
                self._proxy_port.setValue(int(proxy["port"]))
            self._proxy_on.setChecked(proxy.get("enabled", "no").lower() in ("yes", "on", "1"))
            mtu = netconfig.get_mtu(svc)
            if mtu.isdigit():
                self._mtu.setValue(int(mtu))
        except Exception:
            pass

    def _on_enable(self, v):
        self.settings.set("netconfig.enabled", bool(v))
        self._update_enabled_state()

    def _update_enabled_state(self):
        ok = (self._enable.isChecked() and netconfig.supported() and netconfig.is_root())
        self._form.setEnabled(ok)
        self._revert_btn.setEnabled(ok)

    def _confirm(self, what: str) -> bool:
        return QMessageBox.warning(
            self, "Confirm system change",
            f"Apply this change to your OS?\n\n{what}\n\n"
            "The previous value is backed up and can be reverted.",
            QMessageBox.Yes | QMessageBox.Cancel) == QMessageBox.Yes

    def _log(self, ok, msg):
        if self.db is not None:
            try:
                self.db.add_alert("warn" if ok else "info", "netconfig",
                                  "System network change", msg)
            except Exception:
                pass
        QMessageBox.information(self, "System Network", msg)

    # -- actions -----------------------------------------------------------
    def _apply_dns(self):
        svc = self._service_name()
        servers = [s for s in self._dns.text().replace(",", " ").split() if s]
        if not svc or not self._confirm(f"DNS for {svc} → {', '.join(servers) or 'cleared'}"):
            return
        ok, msg = netconfig.set_dns(svc, servers)
        self._log(ok, msg)

    def _apply_proxy(self):
        svc = self._service_name()
        if not svc or not self._confirm(
                f"Proxy for {svc} → {self._proxy_host.text()}:{self._proxy_port.value()} "
                f"({'on' if self._proxy_on.isChecked() else 'off'})"):
            return
        ok, msg = netconfig.set_proxy(svc, self._proxy_host.text(),
                                      self._proxy_port.value(), self._proxy_on.isChecked())
        self._log(ok, msg)

    def _apply_mtu(self):
        svc = self._service_name()
        if not svc or not self._confirm(f"MTU for {svc} → {self._mtu.value()}"):
            return
        ok, msg = netconfig.set_mtu(svc, self._mtu.value())
        self._log(ok, msg)

    def _revert(self):
        svc = self._service_name()
        if not svc or not netconfig.has_backup(svc):
            QMessageBox.information(self, "Revert", "No backup for this service yet.")
            return
        if not self._confirm(f"Revert {svc} to its backed-up settings"):
            return
        ok, msg = netconfig.revert_service(svc)
        self._log(ok, msg)
        self._reload_current()


def _row(widget, btn_text, slot):
    box = QWidget()
    h = QHBoxLayout(box)
    h.setContentsMargins(0, 0, 0, 0)
    h.addWidget(widget)
    b = QPushButton(btn_text)
    b.clicked.connect(slot)
    h.addWidget(b)
    return box
