"""Passive anomaly / security analytics engine.

Consumes :class:`~core.parsers.ParseResult` objects and transport flow records,
maintains lightweight cross-device state, and raises de-duplicated alerts into
the database.  Everything is inference from observed traffic — nothing is sent.
"""
import time
import threading
from collections import defaultdict

from utils.fingerprint import shannon_entropy

# Alert severities
INFO, WARN, CRITICAL = "info", "warn", "critical"

# Risk-score weights
_RISK = {
    "randomized_mac": 8,
    "unknown_vendor": 5,
    "plaintext_http_auth": 22,
    "weak_snmp": 16,
    "open_port": 3,          # per distinct listening port (capped)
    "arp_spoof": 40,
    "rogue_dhcp": 35,
    "port_scan": 45,
    "dns_tunnel": 30,
    "watchlist": 25,
    "new_device": 4,
}


class AnalyticsEngine:
    def __init__(self, db, alert_callback=None):
        self.db = db
        self._alert_cb = alert_callback
        self._lock = threading.Lock()

        # Cross-device state
        self._ip_to_mac = {}                 # ip -> mac (first claimant)
        self._gateway_macs = {}              # gateway ip -> mac
        self._dhcp_servers = set()           # macs seen offering DHCP
        self._seen_alerts = set()            # dedup keys
        self._syn_targets = defaultdict(dict)  # src_ip -> {(dst_ip,dport): ts}
        self._open_ports = defaultdict(set)  # ip -> {ports observed as dst}
        self._risk = defaultdict(int)        # mac -> risk score
        self._risk_reasons = defaultdict(set)
        self._watchlist = set()

        # Live-tunable config (bound from Settings via apply_settings)
        self._detectors = {d: True for d in (
            "arp-spoof", "duplicate-ip", "rogue-dhcp", "router-advert",
            "new-device", "port-scan", "dns-tunnel", "plaintext-auth",
            "weak-snmp", "watchlist")}
        self._weights = dict(_RISK)
        self._risk_enabled = True
        self._scan_ports = 15
        self._scan_hosts = 10
        self._scan_window = 10
        self._dns_entropy = 3.5
        self._dns_minlen = 30

    # ------------------------------------------------------------------ #
    def apply_settings(self, s):
        """Bind detector toggles, thresholds and risk weights from Settings."""
        dets = s.get("security.detectors", None)
        if isinstance(dets, dict):
            self._detectors.update(dets)
        self._scan_ports = int(s.get("security.scan_ports", self._scan_ports))
        self._scan_hosts = int(s.get("security.scan_hosts", self._scan_hosts))
        self._scan_window = int(s.get("security.scan_window", self._scan_window))
        self._dns_entropy = float(s.get("dns.tunnel_entropy", self._dns_entropy))
        self._dns_minlen = int(s.get("dns.tunnel_minlen", self._dns_minlen))
        self._risk_enabled = bool(s.get("risk.enabled", True))
        w = s.get("risk.weights", None)
        if isinstance(w, dict):
            self._weights.update(w)

    def _detector_on(self, category: str) -> bool:
        return self._detectors.get(category, True)

    def set_watchlist(self, macs):
        self._watchlist = {m.lower() for m in macs}

    def set_alert_callback(self, cb):
        self._alert_cb = cb

    # ------------------------------------------------------------------ #
    def _raise(self, severity, category, title, detail="", mac=None, ip=None, dedup_key=None):
        if not self._detector_on(category):
            return
        key = dedup_key or f"{category}:{mac or ip}:{title}"
        with self._lock:
            if key in self._seen_alerts:
                return
            self._seen_alerts.add(key)
        try:
            self.db.add_alert(severity, category, title, detail, mac=mac, ip=ip)
        except Exception:
            pass
        if self._alert_cb:
            try:
                self._alert_cb({
                    "severity": severity, "category": category, "title": title,
                    "detail": detail, "mac": mac, "ip": ip, "timestamp": time.time(),
                })
            except Exception:
                pass

    def _add_risk(self, mac, reason, amount=None):
        if not mac or not self._risk_enabled:
            return
        mac = mac.lower()
        if reason in self._risk_reasons[mac]:
            return
        self._risk_reasons[mac].add(reason)
        add = amount if amount is not None else self._weights.get(reason, 0)
        self._risk[mac] = min(100, self._risk[mac] + add)

    def get_risk(self, mac: str) -> int:
        return self._risk.get((mac or "").lower(), 0)

    def get_risk_reasons(self, mac: str) -> list:
        return sorted(self._risk_reasons.get((mac or "").lower(), set()))

    # ------------------------------------------------------------------ #
    def process(self, result, is_new=False):
        """Inspect a ParseResult for anomalies."""
        mac = (result.source_mac or "").lower()
        ip = result.source_ip or ""
        proto = result.protocol
        meta = result.metadata or {}

        # --- Watchlist ---
        if mac and mac in self._watchlist:
            self._raise(WARN, "watchlist", f"Watchlisted device active: {mac}",
                        f"{mac} ({ip}) seen on the network", mac=mac, ip=ip,
                        dedup_key=f"watch:{mac}")
            self._add_risk(mac, "watchlist")

        # --- New device ---
        if is_new and mac:
            self._raise(INFO, "new-device", f"New device discovered: {mac}",
                        f"first seen via {proto} ({ip})", mac=mac, ip=ip,
                        dedup_key=f"new:{mac}")
            self._add_risk(mac, "new_device")

        # --- ARP: spoofing / duplicate IP / gateway takeover ---
        if proto == "ARP" and ip and mac:
            prev = self._ip_to_mac.get(ip)
            if prev and prev != mac:
                self._raise(CRITICAL, "arp-spoof",
                            f"ARP conflict on {ip}",
                            f"IP {ip} now claimed by {mac} (was {prev}) — possible ARP spoofing.",
                            mac=mac, ip=ip, dedup_key=f"arp:{ip}:{mac}")
                self._add_risk(mac, "arp_spoof")
            else:
                self._ip_to_mac[ip] = mac

        # --- DHCP server tracking (rogue DHCP) ---
        if proto == "DHCP" and meta.get("dhcp_type") in ("Offer", "ACK"):
            if mac:
                if self._dhcp_servers and mac not in self._dhcp_servers:
                    self._raise(CRITICAL, "rogue-dhcp",
                                f"Possible rogue DHCP server: {mac}",
                                f"A second DHCP server ({mac}, {ip}) is handing out leases.",
                                mac=mac, ip=ip, dedup_key=f"dhcp:{mac}")
                    self._add_risk(mac, "rogue_dhcp")
                self._dhcp_servers.add(mac)

        # --- Rogue/router advertisement ---
        if proto == "IPv6-ND" and meta.get("nd_type") == "Router Advertisement":
            key = f"ra:{mac}"
            self._raise(WARN, "router-advert",
                        f"IPv6 Router Advertisement from {mac}",
                        "New IPv6 router announced — verify it is authorised.",
                        mac=mac, ip=ip, dedup_key=key)

        # --- Plaintext credentials ---
        if proto == "HTTP" and meta.get("plaintext_auth"):
            self._raise(WARN, "plaintext-auth",
                        f"Plaintext HTTP Basic auth from {ip}",
                        "Credentials sent without TLS.", mac=mac, ip=ip,
                        dedup_key=f"auth:{mac}")
            self._add_risk(mac, "plaintext_http_auth")

        # --- Weak SNMP community ---
        if proto == "SNMP" and meta.get("weak_community"):
            self._raise(WARN, "weak-snmp",
                        f"Default SNMP community on {ip}",
                        f"community='{meta.get('community')}'", mac=mac, ip=ip,
                        dedup_key=f"snmp:{mac}")
            self._add_risk(mac, "weak_snmp")

        # --- DNS tunneling heuristic ---
        if proto == "DNS":
            for q in meta.get("queries", []):
                name = q.get("name", "")
                label = name.split(".")[0] if name else ""
                if len(label) >= self._dns_minlen and shannon_entropy(label) > self._dns_entropy:
                    self._raise(WARN, "dns-tunnel",
                                f"Possible DNS tunneling from {ip}",
                                f"High-entropy query: {name[:60]}", mac=mac, ip=ip,
                                dedup_key=f"dnstun:{mac}:{label[:12]}")
                    self._add_risk(mac, "dns_tunnel")

    def process_flow(self, flow):
        """SYN-scan / open-port inference from transport flows."""
        proto = flow.get("proto")
        dst_ip = flow.get("dst_ip")
        dport = flow.get("dst_port")
        src_ip = flow.get("src_ip")
        src_mac = (flow.get("src_mac") or "").lower()
        flags = flow.get("flags", "")

        # Track distinct destinations/ports for scan detection (TCP SYN only).
        if proto == "TCP" and "S" in flags and "A" not in flags:
            now = time.time()
            targets = self._syn_targets[src_ip]
            targets[(dst_ip, dport)] = now
            # prune old (outside the configured window)
            for k in [k for k, t in targets.items() if now - t > self._scan_window]:
                targets.pop(k, None)
            distinct_ports = len({p for (_, p) in targets})
            distinct_hosts = len({h for (h, _) in targets})
            if distinct_ports >= self._scan_ports or distinct_hosts >= self._scan_hosts:
                self._raise(CRITICAL, "port-scan",
                            f"Port/host scan from {src_ip}",
                            f"{distinct_ports} ports / {distinct_hosts} hosts probed in <10s.",
                            mac=src_mac, ip=src_ip, dedup_key=f"scan:{src_ip}")
                self._add_risk(src_mac, "port_scan")

        # Passive open-port inference: SYN-ACK means dst is listening on src_port.
        if proto == "TCP" and "S" in flags and "A" in flags:
            self._open_ports[src_ip].add(flow.get("src_port"))

    # ------------------------------------------------------------------ #
    def open_ports_for(self, ip: str) -> set:
        return self._open_ports.get(ip, set())

    def recompute_open_port_risk(self, mac, ip):
        n = len(self._open_ports.get(ip, set()))
        if n:
            self._add_risk(mac, "open_ports", min(20, n * _RISK["open_port"]))
