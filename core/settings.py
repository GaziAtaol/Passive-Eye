"""Persistent, live-applying settings for GhostWire.

A single :class:`Settings` object (see :func:`get_settings`) backs every
preference in the app. Values are addressed by dotted keys (``"graph.fps"``),
persisted as JSON, and any change emits :attr:`Settings.changed` so widgets can
react immediately without a restart.

Group values (per-protocol toggles, risk weights, detector switches, column
visibility …) are stored as dict/list values under a single key; callers read
the dict, mutate a member, and ``set`` it back — which still emits ``changed``.
"""
import os
import json
import copy
import threading

from PyQt5.QtCore import QObject, pyqtSignal

# All 22 registered dissectors (keep in sync with core.parsers.ALL_PARSERS).
PROTOCOLS = [
    "ARP", "DHCP", "DHCPv6", "mDNS", "SSDP", "NetBIOS", "LLMNR", "LLDP",
    "CDP", "STP", "WSD", "SNMP", "NTP", "IPv6-ND", "IGMP", "ICMP",
    "TLS", "HTTP", "QUIC", "DNS",
]

DETECTORS = [
    "arp-spoof", "duplicate-ip", "rogue-dhcp", "router-advert", "new-device",
    "port-scan", "dns-tunnel", "plaintext-auth", "weak-snmp", "watchlist",
]

RISK_FACTORS = [
    "randomized_mac", "unknown_vendor", "plaintext_http_auth", "weak_snmp",
    "open_port", "arp_spoof", "rogue_dhcp", "port_scan", "dns_tunnel",
    "watchlist", "new_device",
]

DEVICE_COLUMNS = [
    "Type", "MAC", "IP", "Host/Alias", "Vendor", "OS", "Risk",
    "Protocols", "Pkts", "Last Seen",
]

COLOR_SCHEMES = ["neon-green", "amber", "cyan", "red", "purple", "mono"]

# Default protocol colours mirror gui.theme.PROTOCOL_COLORS.
_DEFAULT_PROTO_COLORS = {
    "ARP": "#00ff41", "DHCP": "#00e5ff", "DHCPv6": "#3ad0ff", "mDNS": "#ffb000",
    "SSDP": "#c8a2ff", "NetBIOS": "#ff6b9d", "LLMNR": "#7affb0", "DNS": "#5ec8ff",
    "LLDP": "#ffd166", "IPv6-ND": "#b088ff", "TLS": "#ff3b3b", "HTTP": "#ff9f43",
    "QUIC": "#e056fd", "CDP": "#48dbfb", "STP": "#8395a7", "WSD": "#f6e58d",
    "SNMP": "#badc58", "NTP": "#7ed6df", "ICMP": "#ff7979", "IGMP": "#eb4d4b",
}

_DEFAULT_RISK_WEIGHTS = {
    "randomized_mac": 8, "unknown_vendor": 5, "plaintext_http_auth": 22,
    "weak_snmp": 16, "open_port": 3, "arp_spoof": 40, "rogue_dhcp": 35,
    "port_scan": 45, "dns_tunnel": 30, "watchlist": 25, "new_device": 4,
}


def _defaults():
    return {
        # -- appearance --
        "appearance.color_scheme": "neon-green",
        "appearance.font_size": 10,
        "appearance.ui_scale": 1.0,
        "appearance.window_opacity": 1.0,
        "appearance.always_on_top": False,
        "appearance.startup_tab": 0,
        "appearance.glow": True,
        "appearance.animations": True,
        "appearance.countup": True,
        "appearance.statusbar": True,
        "appearance.splash": True,
        "appearance.pixel_font": True,

        # -- matrix background --
        "matrix.enabled": True,
        "matrix.opacity": 0.28,
        "matrix.density": 1.0,
        "matrix.speed": 1.0,
        "matrix.color": "#00ff41",
        "matrix.font_size": 14,

        # -- appearance (extended) --
        "appearance.tab_position": "top",
        "appearance.row_height": 22,
        "appearance.show_tooltips": True,
        "appearance.confirm_on_quit": False,
        "appearance.compact_mode": False,

        # -- protocols --
        "protocols.enabled": {p: True for p in PROTOCOLS},
        "protocols.colors": dict(_DEFAULT_PROTO_COLORS),
        "protocols.log_events": {p: True for p in PROTOCOLS},
        "protocols.flow_tracking": True,

        # -- capture --
        "capture.interface": "",
        "capture.deep": False,
        "capture.snaplen": 0,
        "capture.buffer": 500,
        "capture.promiscuous": True,
        "capture.autostart": False,
        "capture.packet_limit": 0,
        "capture.refresh_ms": 2000,
        "capture.ignore_own_traffic": False,
        "capture.stop_after_packets": 0,
        "capture.auto_save_pcap": False,
        "capture.auto_save_path": "",
        "capture.bpf_presets": {
            "Discovery only": "",
            "Web (TLS/HTTP)": "tcp port 80 or tcp port 443",
            "DNS only": "udp port 53",
        },

        # -- dns --
        "dns.reverse_lookup": False,
        "dns.resolver": "",
        "dns.top_n": 60,
        "dns.tunnel_entropy": 3.5,
        "dns.tunnel_minlen": 30,
        "dns.blocklist": [],
        "dns.show_query_type": True,
        "dns.highlight_suspicious": True,
        "dns.cache_size": 4096,

        # -- security detectors --
        "security.detectors": {d: True for d in DETECTORS},
        "security.scan_ports": 15,
        "security.scan_hosts": 10,
        "security.scan_window": 10,

        # -- risk scoring --
        "risk.enabled": True,
        "risk.weights": dict(_DEFAULT_RISK_WEIGHTS),
        "risk.threshold_warn": 40,
        "risk.threshold_crit": 70,

        # -- alerts / notifications --
        "alerts.toast": True,
        "alerts.toast_ms": 4200,
        "alerts.sound": False,
        "alerts.critical_only_sound": True,
        "alerts.retention_hours": 0,
        "alerts.desktop_notifications": False,
        "alerts.auto_acknowledge": False,
        "alerts.max_per_min": 0,

        # -- graph / network map --
        "graph.repulsion": 5000.0,
        "graph.attraction": 0.01,
        "graph.damping": 0.85,
        "graph.gravity": 0.01,
        "graph.fps": 25,
        "graph.settle_energy": 0.05,
        "graph.node_size": 20,
        "graph.label_len": 24,
        "graph.show_labels": True,
        "graph.show_edges": True,
        "graph.edge_scale": 1.0,
        "graph.edge_opacity": 1.0,
        "graph.highlight_routers": True,
        "graph.color_by": "risk",
        "graph.freeze_when_hidden": True,

        # -- live packets --
        "live.max_rows": 200,
        "live.autoscroll": True,
        "live.hex_per_line": 16,
        "live.follow_selection": True,
        "live.columns": {c: True for c in ["Time", "Proto", "Len", "Summary"]},
        "live.colorize_rows": True,

        # -- device table / L2 --
        "devices.mac_format": "colon-lower",
        "devices.show_broadcast": False,
        "devices.show_multicast": True,
        "devices.show_local": True,
        "devices.show_ipv6": True,
        "devices.highlight_watchlist": True,
        "devices.double_click_action": "details",
        "devices.columns": {c: True for c in DEVICE_COLUMNS},

        # -- storage --
        "storage.retention_hours": 0,
        "storage.autoprune": False,
        "storage.autoprune_hours": 24,
        "storage.export_dir": "",
        "storage.export_format": "html",
        "storage.anonymize_export": False,
        "storage.wal_mode": True,
        "storage.vacuum_on_close": False,

        # -- localization --
        "locale.language": "en",
        "locale.date_format": "%Y-%m-%d",
        "locale.time_format": "%H:%M:%S",
        "locale.byte_units": "IEC",

        # -- hotkeys --
        "hotkeys.search": "Ctrl+K",
        "hotkeys.pause": "Space",
        "hotkeys.export": "Ctrl+E",
        "hotkeys.open_pcap": "Ctrl+O",
        "hotkeys.start": "Ctrl+R",
        "hotkeys.stop": "Ctrl+.",

        # -- privacy --
        "privacy.anonymize_mac": False,
        "privacy.redact_hostnames": False,
        "privacy.no_persist": False,

        # -- window geometry (persisted automatically) --
        "window.geometry": "",
        "window.last_tab": 0,

        # -- system network module (opt-in, non-passive) --
        "netconfig.enabled": False,
    }


class Settings(QObject):
    """JSON-backed, signal-emitting settings store."""

    changed = pyqtSignal(str)  # emits the dotted key that changed

    def __init__(self, path: str = "ghostwire_settings.json"):
        super().__init__()
        self._path = path
        self._lock = threading.Lock()
        self._data = _defaults()
        self._load()

    # -- persistence --------------------------------------------------------
    def _load(self):
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                stored = json.load(fh)
            for k, v in stored.items():
                if k in self._data:
                    # Merge dict group values so new default members survive.
                    if isinstance(self._data[k], dict) and isinstance(v, dict):
                        merged = copy.deepcopy(self._data[k])
                        merged.update(v)
                        self._data[k] = merged
                    else:
                        self._data[k] = v
        except FileNotFoundError:
            self.save()
        except Exception:
            pass

    def save(self):
        try:
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2)
            os.replace(tmp, self._path)
        except Exception:
            pass

    # -- accessors ----------------------------------------------------------
    def get(self, key: str, fallback=None):
        with self._lock:
            if key in self._data:
                val = self._data[key]
                return copy.deepcopy(val) if isinstance(val, (dict, list)) else val
        return fallback

    def set(self, key: str, value, save: bool = True):
        with self._lock:
            if self._data.get(key) == value:
                return
            self._data[key] = value
        if save:
            self.save()
        self.changed.emit(key)

    def reset(self, key: str):
        defaults = _defaults()
        if key in defaults:
            self.set(key, defaults[key])

    def reset_all(self):
        with self._lock:
            self._data = _defaults()
        self.save()
        self.changed.emit("*")

    def all_keys(self):
        return list(self._data.keys())


# Module-level singleton -----------------------------------------------------
_INSTANCE = None


def get_settings(path: str = None) -> Settings:
    """Return the process-wide Settings singleton (created on first call)."""
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = Settings(path or "ghostwire_settings.json")
    return _INSTANCE
