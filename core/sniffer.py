"""
Packet sniffer engine: captures packets using Scapy and feeds them to parsers.

Strictly passive: only a ``prn=`` read callback is registered on Scapy's
``sniff()``. There is no ``send``/``sendp``/``sr*`` anywhere.
"""
import threading
import time
from collections import deque
from typing import Optional

from scapy.all import sniff, get_if_list, wrpcap
from core.parsers import parse_packet, extract_flow
from core.device_manager import DeviceManager

# Discovery-only filter (default, low-noise) — same set as the original tool.
DISCOVERY_FILTER = (
    "arp or "
    "udp port 67 or udp port 68 or "        # DHCP
    "udp port 546 or udp port 547 or "        # DHCPv6
    "udp port 5353 or "                        # mDNS
    "udp port 1900 or "                        # SSDP
    "udp port 137 or "                         # NetBIOS
    "udp port 5355 or "                        # LLMNR
    "udp port 53 or "                          # DNS
    "udp port 3702 or "                        # WS-Discovery
    "udp port 161 or udp port 162 or "         # SNMP
    "udp port 123 or "                         # NTP
    "ether proto 0x88cc or "                   # LLDP
    "icmp or icmp6 or igmp"                     # ICMP / IGMP / IPv6-ND
)

# Deep mode captures everything routable + L2 discovery so the dissectors
# (TLS, HTTP, QUIC, flows …) have data to work with. Heavier, opt-in.
DEEP_FILTER = None  # None => no BPF => capture all frames


class Sniffer:
    """Passive packet capture engine."""

    RING_SIZE = 500

    def __init__(self, device_manager: DeviceManager, interface: str = None, settings=None):
        self.device_manager = device_manager
        self.settings = settings
        self.interface = interface
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._paused = False
        self._deep = False
        self._packet_count = 0
        self._byte_count = 0
        self._start_time = 0.0
        self._callbacks = []       # raw packet callbacks for live log
        self._flow_callbacks = []  # 5-tuple flow callbacks
        self._error = None
        self._ring = deque(maxlen=self.RING_SIZE)
        self._ring_lock = threading.Lock()

    # -- interface helpers ---------------------------------------------------
    @staticmethod
    def get_interfaces() -> list:
        try:
            return get_if_list()
        except Exception:
            return []

    # -- callback registration ----------------------------------------------
    def on_packet(self, callback):
        """Register callback for each captured packet: callback(pkt, results)."""
        self._callbacks.append(callback)

    def on_flow(self, callback):
        """Register callback for each transport flow record: callback(flow_dict)."""
        self._flow_callbacks.append(callback)

    # -- configuration -------------------------------------------------------
    @property
    def deep(self) -> bool:
        return self._deep

    @deep.setter
    def deep(self, value: bool):
        self._deep = bool(value)

    def set_deep(self, value: bool):
        self._deep = bool(value)

    # -- control -------------------------------------------------------------
    def start(self, interface: str = None, bpf_filter: str = None, deep: bool = None):
        """Start capturing packets in a background thread."""
        if self._running:
            return
        if interface:
            self.interface = interface
        if deep is not None:
            self._deep = bool(deep)

        # Apply capture-related settings at start time.
        if self.settings:
            buf = int(self.settings.get("capture.buffer", self.RING_SIZE))
            if buf != self._ring.maxlen:
                self._ring = deque(self._ring, maxlen=buf)
            try:
                from scapy.all import conf
                conf.sniff_promisc = 1 if self.settings.get("capture.promiscuous", True) else 0
            except Exception:
                pass

        self._running = True
        self._paused = False
        self._start_time = time.time()
        self._error = None

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(bpf_filter,),
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    def pause(self):
        self._paused = True

    def resume(self):
        self._paused = False

    @property
    def is_paused(self) -> bool:
        return self._paused

    # -- offline analysis ----------------------------------------------------
    def read_pcap(self, path: str):
        """Load and dissect a saved capture file (no root needed)."""
        from scapy.all import PcapReader
        self._start_time = time.time()
        self._error = None
        try:
            with PcapReader(path) as reader:
                for pkt in reader:
                    self._process_packet(pkt)
        except FileNotFoundError:
            self._error = f"PCAP not found: {path}"
        except Exception as e:
            self._error = f"PCAP read error: {e}"

    def save_pcap(self, path: str):
        """Write the in-memory ring buffer to a .pcap file."""
        with self._ring_lock:
            pkts = [entry["pkt"] for entry in self._ring if entry.get("pkt") is not None]
        if not pkts:
            raise ValueError("No packets captured yet to save.")
        wrpcap(path, pkts)
        return len(pkts)

    def get_ring(self) -> list:
        """Snapshot of recent packets (newest last)."""
        with self._ring_lock:
            return list(self._ring)

    # -- capture loop --------------------------------------------------------
    def _capture_loop(self, bpf_filter: str = None):
        try:
            kwargs = {
                "prn": self._process_packet,
                "store": False,
                "stop_filter": lambda _: not self._running,
            }
            if self.interface:
                kwargs["iface"] = self.interface
            if self.settings:
                limit = int(self.settings.get("capture.stop_after_packets", 0))
                if limit > 0:
                    kwargs["count"] = limit

            if bpf_filter:
                kwargs["filter"] = bpf_filter
            elif self._deep:
                if DEEP_FILTER:
                    kwargs["filter"] = DEEP_FILTER
                # else: no filter => capture everything
            else:
                kwargs["filter"] = DISCOVERY_FILTER

            sniff(**kwargs)

        except PermissionError:
            self._error = ("Permission denied. Run with sudo/root:\n"
                           "  sudo python main.py")
            self._running = False
        except OSError as e:
            self._error = f"Interface error: {e}"
            self._running = False
        except Exception as e:
            self._error = f"Capture error: {e}"
            self._running = False

    def _process_packet(self, pkt):
        if self._paused:
            return

        self._packet_count += 1
        try:
            self._byte_count += len(pkt)
        except Exception:
            pass

        # Protocol parsers -> device manager events.
        results = parse_packet(pkt)
        for result in results:
            self.device_manager.process_result(result, packet=pkt)

        # Transport flow record (conversations / port stats).
        flow_on = (not self.settings) or self.settings.get("protocols.flow_tracking", True)
        try:
            flow = extract_flow(pkt) if flow_on else None
            if flow:
                for cb in self._flow_callbacks:
                    try:
                        cb(flow)
                    except Exception:
                        pass
        except Exception:
            pass

        # Ring buffer for the live packet detail view.
        try:
            summary = pkt.summary()
        except Exception:
            summary = ""
        with self._ring_lock:
            self._ring.append({
                "ts": time.time(),
                "pkt": pkt,
                "summary": summary,
                "protocol": results[0].protocol if results else "",
                "length": len(pkt) if hasattr(pkt, "__len__") else 0,
            })

        # Raw packet listeners.
        for cb in self._callbacks:
            try:
                cb(pkt, results)
            except Exception:
                pass

    # -- stats ---------------------------------------------------------------
    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def byte_count(self) -> int:
        return self._byte_count

    @property
    def uptime(self) -> float:
        if self._start_time and self._running:
            return time.time() - self._start_time
        return 0.0

    @property
    def error(self) -> Optional[str]:
        return self._error

    @property
    def packets_per_second(self) -> float:
        elapsed = self.uptime
        if elapsed > 0:
            return self._packet_count / elapsed
        return 0.0

    @property
    def bytes_per_second(self) -> float:
        elapsed = self.uptime
        if elapsed > 0:
            return self._byte_count / elapsed
        return 0.0
