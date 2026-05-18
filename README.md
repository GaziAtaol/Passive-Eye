# PassiveEye Passive Network Scanner

A desktop application that discovers and maps every device on your network by
**listening only**. No active probing, no ARP scans, no port scans just
silent observation of the broadcast, multicast, and overheard unicast traffic
that networked devices emit constantly, even when they appear idle.

Visually it borrows the look of Florence Nightingale's 1858 *Diagram of the
Causes of Mortality in the Army in the East* parchment paper, sepia ink,
Times New Roman, and a rose / coxcomb diagram for the protocol breakdown.

---

## 1. Task Requirements

This project was written for the CyberSec Club Week 2 assignment, which asked
for a passive network scanner judged on three axes:

| Axis | What was asked | How PassiveEye answers it |
|---|---|---|
| **Style** | "How good looking is your program. A cool GUI? A fancy TUI? Maybe it draws a graph?" | PyQt5 desktop GUI with a Nightingale-inspired parchment theme, an interactive force-directed network graph, and a coxcomb / rose diagram of the protocol distribution. |
| **Substance** | "How well it works, how many protocols does it understand, and other features. Maybe it can be distributed, having multiple clients working together?" | 9 discovery protocols parsed (see list below), OS fingerprinting, MAC-vendor lookup with a 600+ entry OUI table, device-type hinting, service discovery, JSON export, and SQLite persistence across sessions. |
| **Statistics** | "How well does it handle large amounts of data, store it, and handle it. What can you learn with the data, that you will intercept?" | SQLite (WAL mode, thread-safe) backs every event, service, DNS query, and device. Live stat cards, protocol distribution bar, rose diagram, device-type and vendor breakdown, top-N DNS queries, per-device packet counts. |

---

## 2. Protocols Captured

PassiveEye uses a single Scapy BPF filter to grab only discovery traffic, then
runs each packet through every parser. The nine protocols understood:

| # | Protocol | Layer / Port | What it reveals |
|---|---|---|---|
| 1 | **ARP**     | L2 (0x0806)      | MAC ↔ IPv4 mappings; who is on the segment. |
| 2 | **DHCP**    | UDP 67 / 68      | Hostname, vendor class ID, requested/assigned IP, parameter-request-list OS fingerprint (Windows / Linux / Android / macOS / iOS). |
| 3 | **mDNS**    | UDP 5353         | `.local` hostnames, Bonjour/Avahi service discovery (AirPlay, printers, Chromecast, SMB, HTTP…), TXT-record metadata (model, OS version). |
| 4 | **SSDP**    | UDP 1900         | UPnP devices, `SERVER:` header OS guessing, `LOCATION` URLs, search targets. |
| 5 | **NetBIOS** | UDP 137          | Windows machine names via half-ASCII decoding (covers both Scapy's parser and a raw-bytes fallback). |
| 6 | **LLMNR**   | UDP 5355         | Windows link-local name resolution queries strong Windows indicator. |
| 7 | **DNS**     | UDP 53           | Query/response logging, top-queried domains, per-device DNS analytics. |
| 8 | **LLDP**    | L2 (0x88CC)      | Network-device TLVs chassis ID, port ID, system name, system description, capabilities, management address, IEEE 802.1 VLAN ID. |
| 9 | **IPv6-ND** | ICMPv6           | Router advertisements (prefix, RDNSS, router lifetime), router solicitations, neighbor solicitations / advertisements. |

The scanner never sends a packet. Everything above is gathered from traffic
that already exists on the wire.

### What you can learn

From a few minutes of passive listening on a typical home/office network:

- Every device's MAC address, IP, and vendor.
- Most devices' hostnames (DHCP / mDNS / NetBIOS).
- Many devices' operating systems (DHCP fingerprint, SSDP `SERVER:`, mDNS TXT
  `osxvers`, LLDP system description).
- Service inventory per device what AirPlay/Bonjour services they advertise,
  what UPnP they expose, what printers exist.
- Which devices are routers / access points (LLDP capabilities, IPv6 RAs,
  vendor heuristics).
- The aggregate DNS curiosity of the network top queried domains.

---

## 3. Skills / Things Demonstrated

- **Raw packet capture** via Scapy with a single combined BPF filter.
- **Threaded packet processing** capture runs on a background thread, the
  GUI uses Qt signals to receive updates without blocking.
- **Protocol parsing** in pure Python, including manual binary parsing for
  LLDP TLVs and NetBIOS half ASCII names.
- **OS fingerprinting** by three independent heuristics (DHCP vendor class,
  DHCP parameter request list ordering, SSDP server string).
- **Persistent storage** SQLite in WAL mode with thread-local connections,
  indexed for time/protocol/DNS lookups.
- **GUI engineering** Qt stylesheet theme, custom-painted widgets
  (`ProtocolBarWidget`, `CoxcombWidget`, `NetworkGraphWidget`), a
  force-directed graph layout, search/filter, JSON export.
- **Data visualization** a rose / coxcomb diagram with area-proportional
  wedges (`radius = √(count / max)`), exactly the construction Nightingale
  used in 1858.

---

## 4. Setup

### Requirements

- Python 3.8 or newer (3.10 or 3.13 work cleanly; 3.14 also works if your distro
  ships Scapy and PyQt5 wheels for it).
- Linux, macOS, or Windows.
- On Linux/macOS: nothing extra — raw sockets are built in, just run as root.
- On Windows: install **Npcap** from https://npcap.com/ (tick the WinPcap API
  compatibility option during installation). Then run your shell as
  Administrator.

### Install

```bash
tar xzf PassiveEye.tar.gz
cd passive-scanner
pip install -r requirements.txt
```

`requirements.txt` pulls in Scapy and PyQt5.

---

## 5. Running the project

### Linux / macOS

```bash
sudo python3 main.py
```

If you used a virtualenv:

```bash
sudo ./.venv/bin/python main.py
```

### Windows

Right-click PowerShell or `cmd` → **Run as administrator**, then:

```powershell
cd C:\path\to\passive-scanner
python main.py
```

### Optional flags

```bash
python main.py -i "Wi-Fi"          # capture on a specific interface
python main.py --db custom.db      # use a non-default SQLite file
python main.py -h                  # show help
```

---

## 6. Using the GUI

1. Pick an interface from the **Interface** dropdown (or leave "All Interfaces").
2. Click **Start Capture**.
3. Wait. Discovery traffic is bursty give it 30 seconds to a few minutes.
   ARP/mDNS/SSDP arrive fastest; DHCP only on lease renewal.
4. Tabs:
   - **Devices** live table of every device heard. Click a row for a full
     parchment detail card showing MAC, IPs, vendor, OS guess, services,
     metadata.
   - **Network Map** interactive force-directed graph. Drag nodes, scroll
     to zoom, hover for a margin-note tooltip. Routers are coral, the rest
     parchment.
   - **Event Log** chronological feed of every parsed event.
   - **DNS Analytics** top queried domains across the network.
   - **Statistics** the rose / coxcomb diagram + protocol, device-type,
     and vendor distribution tables.
5. **Stop** halts capture cleanly. **Export…** writes the whole database to
   a JSON file.

Data persists in `passive_scanner.db` across runs, so each session enriches
the same picture.

---

## 7. Project layout

```
passive-scanner/
├── main.py                  # Entry point + privilege check
├── requirements.txt
├── README.md
├── core/
│   ├── database.py          # SQLite (WAL, thread-local connections)
│   ├── parsers.py           # 9 protocol parsers → ParseResult
│   ├── device_manager.py    # Central device state + enrichment
│   └── sniffer.py           # Scapy capture engine (background thread)
├── gui/
│   ├── theme.py             # Nightingale parchment QSS + palette
│   ├── network_graph.py     # Force-directed graph widget
│   └── main_window.py       # Main window, stat cards, coxcomb, tabs
└── utils/
    └── oui_lookup.py        # 600+ OUI prefixes (Apple, Samsung, Cisco…)
```

---

## 8. Safety

The scanner is **strictly passive** — `core/sniffer.py` only registers a
`prn=` callback on Scapy's `sniff()`. There is no `send`, `sendp`, or `sr*`
call anywhere in the codebase. Everything is gathered from traffic that is
already on the wire.

Two ordinary caveats:

1. Raw socket capture requires root / Administrator on every OS.
2. Only run it on networks you own or have permission to monitor.

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| `Permission denied` / `Operation not permitted` | Use `sudo` (Linux/macOS) or run the shell as Administrator (Windows). |
| Windows: `No libpcap provider available` | Install Npcap, reboot. |
| `ModuleNotFoundError: scapy` / `PyQt5` | `pip install -r requirements.txt` (and make sure your venv is activated). |
| GUI starts but device table stays empty | Wrong interface, or a wired link with little broadcast traffic try Wi-Fi or "All Interfaces". |
| Capture error popup right after **Start** | The selected interface is wrong; pick "All Interfaces" instead. |

---

## License

Educational use CyberSec Club 2026.
