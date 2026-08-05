"""
Device manager: central hub that processes parse results and maintains device state.
"""
import time
import threading
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from core.database import Database
from core.parsers import ParseResult
from core.analytics import AnalyticsEngine
from utils.oui_lookup import lookup_vendor, get_device_type_hint
from utils.fingerprint import (
    p0f_guess, guess_os_from_ttl, is_locally_administered,
)


@dataclass
class Device:
    """In-memory representation of a discovered device."""
    mac: str
    ip: str = ""
    ipv6: str = ""
    hostname: str = ""
    vendor: str = ""
    os_guess: str = ""
    device_type: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    packet_count: int = 0
    services: list = field(default_factory=list)
    protocols_seen: set = field(default_factory=set)
    metadata: dict = field(default_factory=dict)
    risk_score: int = 0
    randomized_mac: bool = False
    alias: str = ""
    tags: str = ""
    note: str = ""
    watchlist: bool = False


class DeviceManager:
    def __init__(self, db: Database, settings=None):
        self.db = db
        self.settings = settings
        self._devices: Dict[str, Device] = {}
        self._lock = threading.Lock()
        self._callbacks = []
        self._alert_callbacks = []
        self.analytics = AnalyticsEngine(db, alert_callback=self._notify_alert)
        self._load_from_db()
        self._load_tags()

    def _proto_enabled(self, proto: str) -> bool:
        if not self.settings:
            return True
        return self.settings.get("protocols.enabled", {}).get(proto, True)

    def _proto_logged(self, proto: str) -> bool:
        if not self.settings:
            return True
        return self.settings.get("protocols.log_events", {}).get(proto, True)

    def _load_from_db(self):
        """Load existing devices from database on startup."""
        for row in self.db.get_all_devices():
            dev = Device(
                mac=row["mac"],
                ip=row.get("ip", ""),
                ipv6=row.get("ipv6", ""),
                hostname=row.get("hostname", ""),
                vendor=row.get("vendor", ""),
                os_guess=row.get("os_guess", ""),
                device_type=row.get("device_type", ""),
                first_seen=row.get("first_seen", 0),
                last_seen=row.get("last_seen", 0),
                packet_count=row.get("packet_count", 0),
            )
            self._devices[dev.mac] = dev

    def _load_tags(self):
        """Load persisted aliases / notes / watchlist / risk onto devices."""
        try:
            tags = self.db.get_all_tags()
        except Exception:
            tags = {}
        watch = set()
        for mac, t in tags.items():
            dev = self._devices.get(mac)
            if dev:
                dev.alias = t.get("alias", "") or ""
                dev.tags = t.get("tags", "") or ""
                dev.note = t.get("note", "") or ""
                dev.watchlist = bool(t.get("watchlist", 0))
                dev.risk_score = int(t.get("risk_score", 0) or 0)
            if t.get("watchlist"):
                watch.add(mac)
        self.analytics.set_watchlist(watch)

    def on_device_update(self, callback):
        """Register callback for device updates: callback(device, is_new)."""
        self._callbacks.append(callback)

    def on_alert(self, callback):
        """Register callback for anomaly alerts: callback(alert_dict)."""
        self._alert_callbacks.append(callback)

    def _notify(self, device: Device, is_new: bool):
        for cb in self._callbacks:
            try:
                cb(device, is_new)
            except Exception:
                pass

    def _notify_alert(self, alert: dict):
        for cb in self._alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def process_result(self, result: ParseResult, packet=None):
        """Process a ParseResult and update device state."""
        if not result.source_mac or result.source_mac == "ff:ff:ff:ff:ff:ff":
            return
        # Respect per-protocol enable toggle (Settings › Protocols).
        if not self._proto_enabled(result.protocol):
            return

        mac = result.source_mac.lower()
        now = time.time()

        with self._lock:
            is_new = mac not in self._devices
            if is_new:
                dev = Device(mac=mac, first_seen=now)
                self._devices[mac] = dev
            else:
                dev = self._devices[mac]

            dev.last_seen = now
            dev.packet_count += 1
            dev.protocols_seen.add(result.protocol)

            # Update fields if we got new info
            if result.source_ip and result.source_ip != "0.0.0.0":
                dev.ip = result.source_ip
            if result.hostname and (not dev.hostname or result.protocol in ("DHCP", "mDNS", "NetBIOS")):
                dev.hostname = result.hostname
            if result.os_guess and (not dev.os_guess or result.protocol in ("DHCP", "SSDP", "LLDP")):
                dev.os_guess = result.os_guess
            if result.device_type:
                dev.device_type = result.device_type

            # Vendor from OUI
            if not dev.vendor or dev.vendor == "Unknown":
                dev.vendor = lookup_vendor(mac)

            # Device type hinting
            if not dev.device_type or dev.device_type == "Unknown":
                service_names = [s.get("service_type", "") for s in dev.services]
                dev.device_type = get_device_type_hint(dev.vendor, dev.hostname, service_names)

            # Merge metadata
            dev.metadata.update(result.metadata)

            # IPv6
            if result.protocol == "IPv6-ND":
                if result.source_ip and ":" in result.source_ip:
                    dev.ipv6 = result.source_ip

            # Services
            for svc in result.services:
                svc_key = (svc.get("service_name", ""), svc.get("port", 0))
                existing = [s for s in dev.services
                            if (s.get("service_name"), s.get("port", 0)) == svc_key]
                if not existing:
                    dev.services.append(svc)

            # MAC randomization (locally-administered bit)
            if is_new:
                dev.randomized_mac = is_locally_administered(mac)
                if dev.randomized_mac:
                    dev.metadata["mac_type"] = "randomized/local"

            # Passive OS fingerprint from IP TTL + TCP window (p0f-style)
            if packet is not None and (not dev.os_guess):
                os_fp = _os_from_packet(packet)
                if os_fp:
                    dev.os_guess = os_fp
                    dev.metadata["os_source"] = "passive-ttl"

        # Persist fingerprints (JA3, OS) outside the lock.
        ja3 = result.metadata.get("ja3")
        if ja3:
            self.db.add_fingerprint(mac, "ja3", ja3,
                                    result.metadata.get("ja3_client", ""))
        if dev.os_guess:
            self.db.add_fingerprint(mac, "os", dev.os_guess, result.protocol)

        # Persist to DB
        self.db.upsert_device(
            mac,
            ip=dev.ip,
            ipv6=dev.ipv6,
            hostname=dev.hostname,
            vendor=dev.vendor,
            os_guess=dev.os_guess,
            device_type=dev.device_type,
            metadata=result.metadata,
        )

        # Log services
        for svc in result.services:
            self.db.add_service(
                mac,
                protocol=result.protocol,
                service_name=svc.get("service_name"),
                service_type=svc.get("service_type"),
                port=svc.get("port"),
                details=svc.get("details", {}),
            )

        # Log event (unless this protocol's event logging is disabled)
        if self._proto_logged(result.protocol):
            self.db.add_event(
                event_type="discovery" if is_new else "update",
                protocol=result.protocol,
                source_mac=result.source_mac,
                dest_mac=result.dest_mac,
                source_ip=result.source_ip,
                dest_ip=result.dest_ip,
                summary=result.summary,
            )

        # DNS queries
        if result.protocol == "DNS" and result.metadata.get("queries"):
            for q in result.metadata["queries"]:
                self.db.add_dns_query(
                    source_mac=result.source_mac,
                    source_ip=result.source_ip,
                    query_name=q.get("name", ""),
                    query_type=q.get("type", ""),
                )

        # Anomaly / security analytics + risk scoring.
        try:
            self.analytics.process(result, is_new=is_new)
            if not dev.vendor or dev.vendor == "Unknown":
                self.analytics._add_risk(mac, "unknown_vendor")
            if dev.randomized_mac:
                self.analytics._add_risk(mac, "randomized_mac")
            new_risk = self.analytics.get_risk(mac)
            if new_risk != dev.risk_score:
                dev.risk_score = new_risk
                self.db.set_device_tag(mac, risk_score=new_risk)
        except Exception:
            pass

        self._notify(dev, is_new)

    def record_flow(self, flow: dict):
        """Persist a transport flow and feed it to the analytics engine."""
        try:
            self.db.upsert_flow(
                flow.get("src_mac"), flow.get("dst_mac"),
                flow.get("src_ip"), flow.get("dst_ip"),
                flow.get("src_port"), flow.get("dst_port"),
                flow.get("proto"), size=flow.get("size", 0),
                flags=flow.get("flags", ""),
            )
        except Exception:
            pass
        try:
            self.analytics.process_flow(flow)
        except Exception:
            pass

    # -- tags / watchlist / notes ------------------------------------------
    def set_tag(self, mac: str, **kwargs):
        mac = mac.lower()
        self.db.set_device_tag(mac, **kwargs)
        dev = self._devices.get(mac)
        if dev:
            if "alias" in kwargs and kwargs["alias"] is not None:
                dev.alias = kwargs["alias"]
            if "tags" in kwargs and kwargs["tags"] is not None:
                dev.tags = kwargs["tags"]
            if "note" in kwargs and kwargs["note"] is not None:
                dev.note = kwargs["note"]
            if "watchlist" in kwargs and kwargs["watchlist"] is not None:
                dev.watchlist = bool(kwargs["watchlist"])
        # Refresh analytics watchlist snapshot.
        watch = {m for m, d in self._devices.items() if d.watchlist}
        self.analytics.set_watchlist(watch)

    def toggle_watchlist(self, mac: str) -> bool:
        dev = self._devices.get(mac.lower())
        new_val = not (dev.watchlist if dev else False)
        self.set_tag(mac, watchlist=int(new_val))
        return new_val

    def get_devices(self) -> List[Device]:
        with self._lock:
            return list(self._devices.values())

    def get_device(self, mac: str) -> Optional[Device]:
        with self._lock:
            return self._devices.get(mac.lower())

    def get_device_count(self) -> int:
        with self._lock:
            return len(self._devices)

    def get_active_devices(self, seconds: int = 300) -> List[Device]:
        cutoff = time.time() - seconds
        with self._lock:
            return [d for d in self._devices.values() if d.last_seen > cutoff]


def _os_from_packet(packet) -> str:
    """Best-effort passive OS guess from IP TTL and TCP window size."""
    try:
        from scapy.layers.inet import IP, TCP
        try:
            from scapy.layers.inet6 import IPv6
        except Exception:
            IPv6 = None
        ttl = None
        if packet.haslayer(IP):
            ttl = int(packet[IP].ttl)
        elif IPv6 is not None and packet.haslayer(IPv6):
            ttl = int(packet[IPv6].hlim)
        if ttl is None:
            return ""
        window = int(packet[TCP].window) if packet.haslayer(TCP) else 0
        return p0f_guess(ttl, window)
    except Exception:
        return ""
