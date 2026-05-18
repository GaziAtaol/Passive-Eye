"""
Protocol parsers for passive network discovery.
Each parser extracts device information from specific protocol traffic.
"""
import struct
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParseResult:
    """Standardized result from any protocol parser."""
    protocol: str
    source_mac: str = ""
    dest_mac: str = ""
    source_ip: str = ""
    dest_ip: str = ""
    hostname: str = ""
    os_guess: str = ""
    device_type: str = ""
    services: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    summary: str = ""


def parse_arp(pkt) -> Optional[ParseResult]:
    """Parse ARP requests/replies to map MAC <-> IP."""
    from scapy.layers.l2 import ARP
    if not pkt.haslayer(ARP):
        return None

    arp = pkt[ARP]
    op = "request" if arp.op == 1 else "reply"
    result = ParseResult(
        protocol="ARP",
        source_mac=arp.hwsrc,
        source_ip=arp.psrc,
        dest_mac=arp.hwdst if arp.op == 2 else "ff:ff:ff:ff:ff:ff",
        dest_ip=arp.pdst,
        summary=f"ARP {op}: {arp.psrc} ({arp.hwsrc}) -> {arp.pdst}",
    )
    if arp.op == 2:
        result.metadata["arp_type"] = "reply"
    else:
        result.metadata["arp_type"] = "request"
    return result


def parse_dhcp(pkt) -> Optional[ParseResult]:
    """Parse DHCP Discover/Request/Ack for hostname, vendor class, IP."""
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.layers.l2 import Ether
    if not pkt.haslayer(DHCP):
        return None

    bootp = pkt[BOOTP]
    dhcp = pkt[DHCP]

    # Prefer the Ethernet source MAC; fall back to the BOOTP client hw addr.
    if pkt.haslayer(Ether):
        mac_str = pkt[Ether].src
    else:
        mac_str = ":".join(f"{b:02x}" for b in bootp.chaddr[:6])

    result = ParseResult(protocol="DHCP", source_mac=mac_str)

    # Parse DHCP options
    options = {}
    for opt in dhcp.options:
        if isinstance(opt, tuple) and len(opt) >= 2:
            options[opt[0]] = opt[1]

    # Message type
    msg_types = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
                 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
    msg_type = msg_types.get(options.get("message-type", 0), "Unknown")
    result.metadata["dhcp_type"] = msg_type

    # Hostname
    if "hostname" in options:
        hostname = options["hostname"]
        if isinstance(hostname, bytes):
            hostname = hostname.decode("utf-8", errors="ignore")
        result.hostname = hostname

    # Vendor class (reveals OS/device)
    if "vendor_class_id" in options:
        vendor = options["vendor_class_id"]
        if isinstance(vendor, bytes):
            vendor = vendor.decode("utf-8", errors="ignore")
        result.metadata["vendor_class"] = vendor
        result.os_guess = _guess_os_from_dhcp_vendor(vendor)

    # Requested IP
    if "requested_addr" in options:
        result.source_ip = options["requested_addr"]
    elif bootp.ciaddr and bootp.ciaddr != "0.0.0.0":
        result.source_ip = bootp.ciaddr

    # Assigned IP (from ACK)
    if bootp.yiaddr and bootp.yiaddr != "0.0.0.0":
        result.metadata["assigned_ip"] = bootp.yiaddr
        if msg_type in ("ACK", "Offer"):
            result.source_ip = bootp.yiaddr

    # Parameter request list (OS fingerprinting)
    if "param_req_list" in options:
        prl = options["param_req_list"]
        if isinstance(prl, bytes):
            prl = list(prl)
        result.metadata["param_request_list"] = prl
        os_from_prl = _guess_os_from_dhcp_prl(prl)
        if os_from_prl and not result.os_guess:
            result.os_guess = os_from_prl

    result.summary = f"DHCP {msg_type}: {result.hostname or mac_str} ({result.source_ip})"
    return result


def _guess_os_from_dhcp_vendor(vendor: str) -> str:
    vendor_lower = vendor.lower()
    if "msft" in vendor_lower or "microsoft" in vendor_lower:
        return "Windows"
    if "android" in vendor_lower:
        return "Android"
    if "dhcpcd" in vendor_lower:
        return "Linux"
    if "udhcp" in vendor_lower:
        return "Embedded Linux"
    if "iphone" in vendor_lower or "ipad" in vendor_lower:
        return "iOS"
    return ""


def _guess_os_from_dhcp_prl(prl: list) -> str:
    """Fingerprint OS based on DHCP parameter request list ordering."""
    if not prl:
        return ""
    prl_set = set(prl)
    # Windows typically requests params 1,3,6,15,31,33,43,44,46,47,119,121,249,252
    if 252 in prl_set and 249 in prl_set:
        return "Windows"
    # Android
    if prl[:3] == [1, 33, 3]:
        return "Android"
    # macOS / iOS
    if 95 in prl_set and 44 not in prl_set:
        return "macOS/iOS"
    # Linux
    if prl[:3] == [1, 28, 2]:
        return "Linux"
    return ""


def parse_mdns(pkt) -> Optional[ParseResult]:
    """Parse mDNS (Multicast DNS) for service discovery and hostnames."""
    from scapy.layers.inet import UDP, IP
    from scapy.layers.dns import DNS, DNSRR, DNSQR
    from scapy.layers.l2 import Ether

    if not pkt.haslayer(UDP) or not pkt.haslayer(DNS):
        return None

    udp = pkt[UDP]
    if udp.dport != 5353 and udp.sport != 5353:
        return None

    dns = pkt[DNS]
    result = ParseResult(protocol="mDNS")

    if pkt.haslayer(Ether):
        result.source_mac = pkt[Ether].src
        result.dest_mac = pkt[Ether].dst
    if pkt.haslayer(IP):
        result.source_ip = pkt[IP].src
        result.dest_ip = pkt[IP].dst

    # Parse answers (responses)
    services = []
    hostnames = []

    for i in range(dns.ancount):
        try:
            rr = dns.an[i] if hasattr(dns, "an") and dns.an else None
            if rr is None:
                break
            name = rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname)
            name = name.rstrip(".")

            # PTR - service type pointer
            if rr.type == 12:  # PTR
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode("utf-8", errors="ignore")
                rdata = str(rdata).rstrip(".")
                services.append({
                    "service_name": rdata,
                    "service_type": name,
                    "protocol": "mDNS",
                })

            # A record
            elif rr.type == 1:  # A
                if ".local" in name:
                    hostnames.append(name.replace(".local", ""))
                result.metadata["mdns_a"] = str(rr.rdata)

            # AAAA record
            elif rr.type == 28:  # AAAA
                if ".local" in name:
                    hostnames.append(name.replace(".local", ""))
                result.metadata["mdns_aaaa"] = str(rr.rdata)

            # SRV record
            elif rr.type == 33:  # SRV
                try:
                    port = rr.port
                    target = rr.target
                    if isinstance(target, bytes):
                        target = target.decode("utf-8", errors="ignore")
                    target = str(target).rstrip(".")
                    services.append({
                        "service_name": name,
                        "service_type": "SRV",
                        "port": port,
                        "protocol": "mDNS",
                        "details": {"target": target},
                    })
                except Exception:
                    pass

            # TXT record (metadata)
            elif rr.type == 16:  # TXT
                try:
                    rdata = rr.rdata
                    if isinstance(rdata, list):
                        txt_entries = [d.decode("utf-8", errors="ignore")
                                       if isinstance(d, bytes) else str(d) for d in rdata]
                    elif isinstance(rdata, bytes):
                        txt_entries = [rdata.decode("utf-8", errors="ignore")]
                    else:
                        txt_entries = [str(rdata)]

                    txt_dict = {}
                    for entry in txt_entries:
                        if "=" in entry:
                            k, v = entry.split("=", 1)
                            txt_dict[k] = v

                    if txt_dict:
                        result.metadata["mdns_txt"] = txt_dict
                        if "model" in txt_dict:
                            result.metadata["model"] = txt_dict["model"]
                        if "osxvers" in txt_dict:
                            result.os_guess = f"macOS {txt_dict['osxvers']}"
                except Exception:
                    pass
        except Exception:
            continue

    # Parse queries
    for i in range(dns.qdcount):
        try:
            qr = dns.qd[i] if hasattr(dns, "qd") and dns.qd else None
            if qr is None:
                break
            qname = qr.qname.decode() if isinstance(qr.qname, bytes) else str(qr.qname)
            qname = qname.rstrip(".")
            result.metadata.setdefault("mdns_queries", []).append(qname)
        except Exception:
            continue

    if hostnames:
        result.hostname = hostnames[0]
    result.services = services

    parts = []
    if result.hostname:
        parts.append(result.hostname)
    if services:
        svc_names = [s["service_type"] for s in services[:3]]
        parts.append(f"services: {', '.join(svc_names)}")
    result.summary = f"mDNS: {' | '.join(parts)}" if parts else "mDNS query"

    return result


def parse_ssdp(pkt) -> Optional[ParseResult]:
    """Parse SSDP (Simple Service Discovery Protocol) for UPnP devices."""
    from scapy.layers.inet import UDP, IP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    if not pkt.haslayer(UDP):
        return None

    udp = pkt[UDP]
    if udp.dport != 1900 and udp.sport != 1900:
        return None

    if not pkt.haslayer(Raw):
        return None

    try:
        payload = pkt[Raw].load.decode("utf-8", errors="ignore")
    except Exception:
        return None

    result = ParseResult(protocol="SSDP")

    if pkt.haslayer(Ether):
        result.source_mac = pkt[Ether].src
        result.dest_mac = pkt[Ether].dst
    if pkt.haslayer(IP):
        result.source_ip = pkt[IP].src
        result.dest_ip = pkt[IP].dst

    # Parse headers
    headers = {}
    for line in payload.split("\r\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().upper()] = value.strip()

    is_notify = payload.startswith("NOTIFY")
    is_search = payload.startswith("M-SEARCH")
    is_response = payload.startswith("HTTP/")

    if "SERVER" in headers:
        result.metadata["server"] = headers["SERVER"]
        result.os_guess = _guess_os_from_ssdp_server(headers["SERVER"])

    if "USN" in headers:
        result.metadata["usn"] = headers["USN"]

    if "ST" in headers:
        result.metadata["search_target"] = headers["ST"]

    if "NT" in headers:
        result.metadata["notification_type"] = headers["NT"]

    if "LOCATION" in headers:
        result.metadata["location"] = headers["LOCATION"]
        result.services.append({
            "service_name": headers.get("NT", headers.get("ST", "UPnP")),
            "service_type": "SSDP/UPnP",
            "protocol": "SSDP",
            "details": {"location": headers["LOCATION"]},
        })

    if is_notify:
        result.summary = f"SSDP NOTIFY: {headers.get('NT', 'unknown')} from {result.source_ip}"
    elif is_search:
        result.summary = f"SSDP M-SEARCH: {headers.get('ST', '*')} from {result.source_ip}"
    elif is_response:
        result.summary = f"SSDP Response: {headers.get('ST', '')} from {result.source_ip}"
    else:
        result.summary = f"SSDP: {result.source_ip}"

    return result


def _guess_os_from_ssdp_server(server: str) -> str:
    s = server.lower()
    if "windows" in s:
        return "Windows"
    if "linux" in s:
        return "Linux"
    if "darwin" in s or "macos" in s:
        return "macOS"
    if "android" in s:
        return "Android"
    if "freebsd" in s:
        return "FreeBSD"
    return ""


def parse_nbns(pkt) -> Optional[ParseResult]:
    """Parse NetBIOS Name Service for Windows machine names."""
    from scapy.layers.inet import UDP, IP
    from scapy.layers.l2 import Ether
    from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse

    if not pkt.haslayer(UDP):
        return None

    udp = pkt[UDP]
    if udp.dport != 137 and udp.sport != 137:
        return None

    result = ParseResult(protocol="NetBIOS")

    if pkt.haslayer(Ether):
        result.source_mac = pkt[Ether].src
    if pkt.haslayer(IP):
        result.source_ip = pkt[IP].src

    if pkt.haslayer(NBNSQueryRequest):
        nbns = pkt[NBNSQueryRequest]
        name = _decode_netbios_name(nbns)
        if name:
            result.hostname = name
            result.os_guess = "Windows"
            result.summary = f"NetBIOS Name Query: {name} from {result.source_ip}"
            return result

    if pkt.haslayer(NBNSQueryResponse):
        nbns = pkt[NBNSQueryResponse]
        name = _decode_netbios_name(nbns)
        if name:
            result.hostname = name
            result.os_guess = "Windows"
            result.summary = f"NetBIOS Name Response: {name} ({result.source_ip})"
            return result

    # Fallback: try to decode from raw UDP payload
    from scapy.packet import Raw
    if pkt.haslayer(Raw):
        try:
            payload = bytes(pkt[Raw].load)
            if len(payload) >= 12:
                name = _decode_netbios_name_raw(payload)
                if name:
                    result.hostname = name
                    result.os_guess = "Windows"
                    result.summary = f"NetBIOS: {name} ({result.source_ip})"
                    return result
        except Exception:
            pass

    return None


def _decode_netbios_name(nbns_layer) -> str:
    """Extract name from NetBIOS layer."""
    try:
        name = ""
        if hasattr(nbns_layer, "QUESTION_NAME"):
            name = nbns_layer.QUESTION_NAME
        elif hasattr(nbns_layer, "RR_NAME"):
            name = nbns_layer.RR_NAME
        elif hasattr(nbns_layer, "NAME_TRN_ID"):
            return ""

        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="ignore")
        return name.strip().rstrip(".")
    except Exception:
        return ""


def _decode_netbios_name_raw(data: bytes) -> str:
    """Decode NetBIOS name from raw bytes (half-ASCII encoding)."""
    try:
        if len(data) < 13:
            return ""
        # Skip header (12 bytes) and length byte
        offset = 12
        if offset >= len(data):
            return ""
        name_len = data[offset]
        offset += 1
        if name_len != 32 or offset + 32 > len(data):
            return ""
        encoded = data[offset:offset + 32]
        decoded = ""
        for i in range(0, 32, 2):
            ch = ((encoded[i] - 0x41) << 4) | (encoded[i + 1] - 0x41)
            if 0x20 <= ch <= 0x7E:
                decoded += chr(ch)
        return decoded.strip()
    except Exception:
        return ""


def parse_llmnr(pkt) -> Optional[ParseResult]:
    """Parse LLMNR (Link-Local Multicast Name Resolution)."""
    from scapy.layers.inet import UDP, IP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.l2 import Ether

    if not pkt.haslayer(UDP) or not pkt.haslayer(DNS):
        return None

    udp = pkt[UDP]
    if udp.dport != 5355 and udp.sport != 5355:
        return None

    dns = pkt[DNS]
    result = ParseResult(protocol="LLMNR")

    if pkt.haslayer(Ether):
        result.source_mac = pkt[Ether].src
    if pkt.haslayer(IP):
        result.source_ip = pkt[IP].src

    result.os_guess = "Windows"

    # Parse query
    if dns.qdcount > 0 and hasattr(dns, "qd") and dns.qd:
        try:
            qname = dns.qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore")
            qname = qname.rstrip(".")
            result.hostname = qname
            result.summary = f"LLMNR Query: {qname} from {result.source_ip}"
        except Exception:
            result.summary = f"LLMNR Query from {result.source_ip}"
    else:
        result.summary = f"LLMNR from {result.source_ip}"

    return result


def parse_dns(pkt) -> Optional[ParseResult]:
    """Parse DNS queries and responses."""
    from scapy.layers.inet import UDP, IP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.l2 import Ether

    if not pkt.haslayer(DNS) or not pkt.haslayer(UDP):
        return None

    udp = pkt[UDP]
    # Skip mDNS and LLMNR
    if udp.dport in (5353, 5355) or udp.sport in (5353, 5355):
        return None

    dns = pkt[DNS]
    result = ParseResult(protocol="DNS")

    if pkt.haslayer(Ether):
        result.source_mac = pkt[Ether].src
        result.dest_mac = pkt[Ether].dst
    if pkt.haslayer(IP):
        result.source_ip = pkt[IP].src
        result.dest_ip = pkt[IP].dst

    queries = []
    answers = []

    # Parse queries
    if dns.qdcount > 0 and hasattr(dns, "qd") and dns.qd:
        for i in range(dns.qdcount):
            try:
                qr = dns.qd[i] if dns.qdcount > 1 else dns.qd
                qname = qr.qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="ignore")
                qname = qname.rstrip(".")
                qtype_map = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR",
                             15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
                qtype = qtype_map.get(qr.qtype, str(qr.qtype))
                queries.append({"name": qname, "type": qtype})
                if dns.qdcount == 1:
                    break
            except Exception:
                break

    # Parse answers
    if dns.ancount > 0 and hasattr(dns, "an") and dns.an:
        for i in range(dns.ancount):
            try:
                rr = dns.an[i] if dns.ancount > 1 else dns.an
                rname = rr.rrname
                if isinstance(rname, bytes):
                    rname = rname.decode("utf-8", errors="ignore")
                rname = rname.rstrip(".")
                if rr.type == 1:  # A
                    answers.append({"name": rname, "type": "A", "data": rr.rdata})
                elif rr.type == 28:  # AAAA
                    answers.append({"name": rname, "type": "AAAA", "data": rr.rdata})
                elif rr.type == 5:  # CNAME
                    cname = rr.rdata
                    if isinstance(cname, bytes):
                        cname = cname.decode("utf-8", errors="ignore")
                    answers.append({"name": rname, "type": "CNAME", "data": str(cname).rstrip(".")})
                if dns.ancount == 1:
                    break
            except Exception:
                break

    result.metadata["queries"] = queries
    result.metadata["answers"] = answers

    if queries:
        qnames = [q["name"] for q in queries[:3]]
        result.summary = f"DNS Query: {', '.join(qnames)}"
    elif answers:
        result.summary = f"DNS Response: {answers[0].get('name', '')}"
    else:
        result.summary = f"DNS from {result.source_ip}"

    return result


def parse_ipv6_nd(pkt) -> Optional[ParseResult]:
    """Parse IPv6 Neighbor Discovery (Router Adv, Neighbor Sol/Adv)."""
    from scapy.layers.inet6 import (
        IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA, ICMPv6ND_RS,
        ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr,
        ICMPv6NDOptPrefixInfo, ICMPv6NDOptRDNSS,
    )
    from scapy.layers.l2 import Ether

    if not pkt.haslayer(IPv6):
        return None

    result = ParseResult(protocol="IPv6-ND")

    if pkt.haslayer(Ether):
        result.source_mac = pkt[Ether].src
        result.dest_mac = pkt[Ether].dst

    ipv6 = pkt[IPv6]
    result.source_ip = ipv6.src
    result.dest_ip = ipv6.dst

    # Router Advertisement
    if pkt.haslayer(ICMPv6ND_RA):
        ra = pkt[ICMPv6ND_RA]
        result.device_type = "Router"
        result.metadata["router_lifetime"] = ra.routerlifetime
        result.metadata["nd_type"] = "Router Advertisement"

        # Prefix info
        if pkt.haslayer(ICMPv6NDOptPrefixInfo):
            prefix = pkt[ICMPv6NDOptPrefixInfo]
            result.metadata["prefix"] = f"{prefix.prefix}/{prefix.prefixlen}"

        # RDNSS
        if pkt.haslayer(ICMPv6NDOptRDNSS):
            rdnss = pkt[ICMPv6NDOptRDNSS]
            if hasattr(rdnss, "dns"):
                result.metadata["dns_servers"] = rdnss.dns

        result.summary = f"IPv6 Router Advertisement from {result.source_ip}"
        return result

    # Router Solicitation
    if pkt.haslayer(ICMPv6ND_RS):
        result.metadata["nd_type"] = "Router Solicitation"
        result.summary = f"IPv6 Router Solicitation from {result.source_mac}"
        return result

    # Neighbor Solicitation
    if pkt.haslayer(ICMPv6ND_NS):
        ns = pkt[ICMPv6ND_NS]
        result.metadata["nd_type"] = "Neighbor Solicitation"
        result.metadata["target"] = ns.tgt
        if pkt.haslayer(ICMPv6NDOptSrcLLAddr):
            result.source_mac = pkt[ICMPv6NDOptSrcLLAddr].lladdr
        result.summary = f"IPv6 NS: who has {ns.tgt}?"
        return result

    # Neighbor Advertisement
    if pkt.haslayer(ICMPv6ND_NA):
        na = pkt[ICMPv6ND_NA]
        result.metadata["nd_type"] = "Neighbor Advertisement"
        result.metadata["target"] = na.tgt
        if pkt.haslayer(ICMPv6NDOptDstLLAddr):
            result.metadata["target_mac"] = pkt[ICMPv6NDOptDstLLAddr].lladdr
        result.summary = f"IPv6 NA: {na.tgt} is at {result.source_mac}"
        return result

    return None


def parse_lldp(pkt) -> Optional[ParseResult]:
    """Parse LLDP (Link Layer Discovery Protocol) for network device info."""
    from scapy.layers.l2 import Ether

    if not pkt.haslayer(Ether):
        return None

    eth = pkt[Ether]
    # LLDP ethertype is 0x88cc
    if eth.type != 0x88CC:
        return None

    result = ParseResult(
        protocol="LLDP",
        source_mac=eth.src,
        dest_mac=eth.dst,
    )

    try:
        payload = bytes(eth.payload)
        offset = 0
        while offset < len(payload) - 2:
            type_len = struct.unpack("!H", payload[offset:offset + 2])[0]
            tlv_type = (type_len >> 9) & 0x7F
            tlv_len = type_len & 0x01FF
            offset += 2

            if tlv_type == 0:  # End
                break
            if offset + tlv_len > len(payload):
                break

            tlv_data = payload[offset:offset + tlv_len]
            offset += tlv_len

            if tlv_type == 1:  # Chassis ID
                if tlv_len > 1:
                    subtype = tlv_data[0]
                    if subtype == 4:  # MAC
                        mac = ":".join(f"{b:02x}" for b in tlv_data[1:7])
                        result.metadata["chassis_mac"] = mac
                    elif subtype == 7:  # Locally assigned
                        result.metadata["chassis_id"] = tlv_data[1:].decode("utf-8", errors="ignore")

            elif tlv_type == 2:  # Port ID
                if tlv_len > 1:
                    subtype = tlv_data[0]
                    port_id = tlv_data[1:].decode("utf-8", errors="ignore")
                    result.metadata["port_id"] = port_id

            elif tlv_type == 3:  # TTL
                if tlv_len >= 2:
                    result.metadata["ttl"] = struct.unpack("!H", tlv_data[:2])[0]

            elif tlv_type == 4:  # Port Description
                result.metadata["port_desc"] = tlv_data.decode("utf-8", errors="ignore")

            elif tlv_type == 5:  # System Name
                result.hostname = tlv_data.decode("utf-8", errors="ignore")

            elif tlv_type == 6:  # System Description
                desc = tlv_data.decode("utf-8", errors="ignore")
                result.metadata["system_desc"] = desc
                result.os_guess = _guess_os_from_lldp_desc(desc)

            elif tlv_type == 7:  # System Capabilities
                if tlv_len >= 4:
                    caps = struct.unpack("!HH", tlv_data[:4])
                    result.metadata["capabilities"] = _decode_lldp_caps(caps[0])
                    result.metadata["enabled_caps"] = _decode_lldp_caps(caps[1])

            elif tlv_type == 8:  # Management Address
                if tlv_len > 2:
                    addr_len = tlv_data[0]
                    addr_subtype = tlv_data[1]
                    if addr_subtype == 1 and addr_len >= 5:  # IPv4
                        ip = ".".join(str(b) for b in tlv_data[2:6])
                        result.source_ip = ip

            elif tlv_type == 127:  # Organization-specific
                if tlv_len >= 4:
                    oui = tlv_data[:3]
                    subtype = tlv_data[3]
                    # IEEE 802.1 VLAN
                    if oui == b"\x00\x80\xc2" and subtype == 3:
                        if tlv_len >= 6:
                            vlan_id = struct.unpack("!H", tlv_data[4:6])[0]
                            result.metadata["vlan_id"] = vlan_id

        result.device_type = "Network Device"
        result.summary = f"LLDP: {result.hostname or result.source_mac}"
        if result.metadata.get("system_desc"):
            result.summary += f" ({result.metadata['system_desc'][:40]})"

    except Exception:
        result.summary = f"LLDP from {result.source_mac}"

    return result


def _guess_os_from_lldp_desc(desc: str) -> str:
    d = desc.lower()
    if "cisco" in d:
        return "Cisco IOS"
    if "juniper" in d or "junos" in d:
        return "JunOS"
    if "linux" in d:
        return "Linux"
    if "windows" in d:
        return "Windows"
    if "ubiquiti" in d or "edgeos" in d or "unifi" in d:
        return "Ubiquiti"
    if "mikrotik" in d or "routeros" in d:
        return "MikroTik RouterOS"
    return ""


def _decode_lldp_caps(caps: int) -> list:
    cap_names = []
    cap_map = {
        0: "Other", 1: "Repeater", 2: "Bridge",
        3: "WLAN AP", 4: "Router", 5: "Telephone",
        6: "DOCSIS", 7: "Station",
    }
    for bit, name in cap_map.items():
        if caps & (1 << bit):
            cap_names.append(name)
    return cap_names


# Registry of all parsers in priority order
ALL_PARSERS = [
    ("ARP", parse_arp),
    ("DHCP", parse_dhcp),
    ("mDNS", parse_mdns),
    ("SSDP", parse_ssdp),
    ("NetBIOS", parse_nbns),
    ("LLMNR", parse_llmnr),
    ("LLDP", parse_lldp),
    ("IPv6-ND", parse_ipv6_nd),
    ("DNS", parse_dns),
]


def parse_packet(pkt) -> list:
    """Run all parsers on a packet, return list of ParseResults."""
    results = []
    for name, parser in ALL_PARSERS:
        try:
            result = parser(pkt)
            if result:
                results.append(result)
        except Exception:
            continue
    return results
