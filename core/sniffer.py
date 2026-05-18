"""
Packet sniffer engine: captures packets using Scapy and feeds them to parsers.
"""
import threading
import time
from typing import Optional

from scapy.all import sniff, get_if_list, conf
from core.parsers import parse_packet
from core.device_manager import DeviceManager


class Sniffer:
    """Passive packet capture engine."""

    def __init__(self, device_manager: DeviceManager, interface: str = None):
        self.device_manager = device_manager
        self.interface = interface
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._packet_count = 0
        self._start_time = 0.0
        self._callbacks = []  # raw packet callbacks for live log
        self._error = None

    @staticmethod
    def get_interfaces() -> list:
        """List available network interfaces."""
        try:
            return get_if_list()
        except Exception:
            return []

    def on_packet(self, callback):
        """Register callback for each captured packet: callback(pkt, results)."""
        self._callbacks.append(callback)

    def start(self, interface: str = None, bpf_filter: str = None):
        """Start capturing packets in a background thread."""
        if self._running:
            return

        if interface:
            self.interface = interface

        self._running = True
        self._start_time = time.time()
        self._error = None

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(bpf_filter,),
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        """Stop capturing."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    def _capture_loop(self, bpf_filter: str = None):
        """Main capture loop running in background thread."""
        try:
            # Build Scapy sniff kwargs
            kwargs = {
                "prn": self._process_packet,
                "store": False,
                "stop_filter": lambda _: not self._running,
            }

            if self.interface:
                kwargs["iface"] = self.interface

            if bpf_filter:
                kwargs["filter"] = bpf_filter
            else:
                # Default BPF filter to capture discovery protocols
                kwargs["filter"] = (
                    "arp or "
                    "udp port 67 or udp port 68 or "      # DHCP
                    "udp port 5353 or "                      # mDNS
                    "udp port 1900 or "                      # SSDP
                    "udp port 137 or "                       # NetBIOS
                    "udp port 5355 or "                      # LLMNR
                    "udp port 53 or "                        # DNS
                    "ether proto 0x88cc or "                  # LLDP
                    "icmp6"                                   # IPv6 ND
                )

            sniff(**kwargs)

        except PermissionError:
            self._error = (
                "Permission denied. Run with sudo/root:\n"
                "  sudo python main.py"
            )
            self._running = False
        except OSError as e:
            self._error = f"Interface error: {e}"
            self._running = False
        except Exception as e:
            self._error = f"Capture error: {e}"
            self._running = False

    def _process_packet(self, pkt):
        """Process a single captured packet."""
        self._packet_count += 1

        # Parse with all protocol parsers
        results = parse_packet(pkt)

        # Feed results to device manager
        for result in results:
            self.device_manager.process_result(result)

        # Notify listeners
        for cb in self._callbacks:
            try:
                cb(pkt, results)
            except Exception:
                pass

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def packet_count(self) -> int:
        return self._packet_count

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
