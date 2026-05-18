"""
Device manager: central hub that processes parse results and maintains device state.
"""
import time
import threading
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from core.database import Database
from core.parsers import ParseResult
from utils.oui_lookup import lookup_vendor, get_device_type_hint


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


class DeviceManager:
    def __init__(self, db: Database):
        self.db = db
        self._devices: Dict[str, Device] = {}
        self._lock = threading.Lock()
        self._callbacks = []
        self._load_from_db()

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

    def on_device_update(self, callback):
        """Register callback for device updates: callback(device, is_new)."""
        self._callbacks.append(callback)

    def _notify(self, device: Device, is_new: bool):
        for cb in self._callbacks:
            try:
                cb(device, is_new)
            except Exception:
                pass

    def process_result(self, result: ParseResult):
        """Process a ParseResult and update device state."""
        if not result.source_mac or result.source_mac == "ff:ff:ff:ff:ff:ff":
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

        # Log event
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

        self._notify(dev, is_new)

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
