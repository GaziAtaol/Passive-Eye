# GhostWire — Passive Network Scanner

> Formerly *PassiveEye*. A desktop tool that maps every device on your network by
> **listening only** — no active probing, no ARP scans, no port scans. It silently
> dissects the broadcast, multicast, and overheard traffic that devices emit
> constantly, then turns it into device intelligence, security alerts, and live
> statistics behind a hacker/terminal-style GUI (matrix rain, neon-green console
> aesthetic, animated widgets).

The **capture engine never transmits a packet**. There is no `send`, `sendp`, or
`sr*` call in the sniffing path — everything is inferred from traffic already on
the wire. (The optional *System Network* admin module described below is separate
and explicitly not passive.)

---

## Highlights

- **200+ configurable settings** — a searchable, categorized **Preferences**
  dialog (appearance, matrix background, per-protocol toggles & colors, capture,
  DNS, security detectors & thresholds, risk weights, alerts, network-map physics,
  live packets, device/L2, storage, hotkeys, localization, privacy). Everything
  is JSON-persisted and most settings apply **live**.
- **Localization (EN + TR)** — full UI translation with an instant language
  switch; locale-aware byte units (IEC/SI) and date/time formats.
- **Pixel-font accents** — a bundled OFL pixel font (Silkscreen) styles the
  title, group headers, stat labels and menu; body text stays monospace for
  readability.
- **Smooth network map** — the force-directed graph freezes once it settles and
  pauses when its tab is hidden, so it no longer spins the CPU or stutters.

- **22 protocol dissectors** — ARP, DHCP, DHCPv6, mDNS, SSDP, NetBIOS, LLMNR,
  DNS, LLDP, CDP, STP, WS-Discovery, SNMP, NTP, IPv6-ND, IGMP, ICMP, **TLS
  (SNI + JA3)**, **HTTP**, **QUIC**, plus TCP/UDP flow tracking.
- **Passive fingerprinting** — JA3 TLS client hashes, p0f-style OS guessing from
  IP TTL + TCP window, DHCP parameter-list OS fingerprint, MAC-randomization
  (locally-administered bit) detection, MAC-vendor OUI lookup.
- **Security analytics (all passive)** — ARP-spoofing / duplicate-IP detection,
  rogue-DHCP and rogue-router detection, passive port-scan detection,
  DNS-tunneling heuristic, plaintext-auth and weak-SNMP warnings, per-device
  **risk scoring (0–100)**, and a colour-coded **Alerts** center with toasts.
- **Wireshark-style views** — Live Packets pane with a layered dissection tree +
  hex/ASCII dump, Conversations/flows table, Top Talkers, IO Graph (pps/Bps),
  Protocol Hierarchy tree, protocol-chatter rose diagram.
- **Device management** — aliases, notes, tags, a watchlist, right-click actions,
  and global search/filter.
- **Persistence & export** — SQLite (WAL, thread-safe) backs devices, events,
  DNS, flows, alerts and fingerprints; export to **JSON / CSV / HTML report** and
  save the capture buffer to **PCAP**.
- **Offline analysis** — open a saved `.pcap`/`.pcapng` with **no root required**.
- **Hacker GUI** — boot splash with a typing sequence, ambient matrix-rain
  background, neon monospace theme, glow button hovers, count-up stat cards with
  sparklines, and risk-coloured network graph nodes.

---

## Install

```bash
git clone https://github.com/GaziAtaol/Passive-Eye.git
cd Passive-Eye
pip install -r requirements.txt      # scapy + PyQt5
```

- Python 3.8+ (tested on 3.11). Linux, macOS, or Windows.
- Live capture needs root/Administrator raw-socket access.
- On Windows install **Npcap** (https://npcap.com/, tick WinPcap API compat).
- *(optional)* Point `GHOSTWIRE_OUI` at a Wireshark `manuf` / IEEE OUI file, or
  drop it at `utils/oui.txt`, to extend the built-in vendor table.

---

## Running

```bash
# live capture (needs root)
sudo python3 main.py
sudo python3 main.py -i "Wi-Fi"        # specific interface
sudo python3 main.py --deep            # Deep Capture Mode (dissect all TCP/UDP)

# offline analysis of a capture file — NO root required
python3 main.py --pcap capture.pcap

# other flags
python3 main.py --db custom.db         # alternate SQLite file
python3 main.py --no-splash            # skip the boot animation
python3 main.py -h                     # help
```

### Capture modes

- **Discovery mode (default)** — a tight BPF filter grabs only discovery/control
  traffic. Low noise, low CPU.
- **Deep Capture Mode** (`--deep` or the *Deep* toggle) — captures all frames so
  the TLS/HTTP/QUIC dissectors and the conversations/flows analytics have data to
  work with. Heavier, opt-in. You can also type a custom BPF filter in the top bar.

### Keyboard shortcuts

`Ctrl+K` focus search · `Space` pause/resume · `Ctrl+O` open PCAP · `Ctrl+E` export HTML.

---

## GUI tour

| Tab | What it shows |
|---|---|
| **Devices** | Live device table with type, vendor, OS, **risk score**, protocols; click for a full dossier (fingerprints, services, risk factors). Right-click to alias / note / watchlist. |
| **Network Map** | Force-directed graph; node ring colour = risk, edge width = traffic. Drag, zoom, hover. |
| **Live Packets** | Scrolling packet feed + Wireshark-style layer dissection tree + hex/ASCII pane. |
| **Alerts** | Colour-coded security alerts (info/warn/critical). |
| **Conversations** | 5-tuple flow table (endpoints, ports, packets, bytes). |
| **Event Log** | Chronological parsed-event feed. |
| **DNS** | Top queried domains. |
| **IO Graph** | Live pps/Bps chart + Top Talkers. |
| **Protocol Tree** | Protocol-hierarchy breakdown by layer. |
| **Statistics** | Protocol rose diagram + protocol / device-type / vendor distributions. |

---

## Project layout

```
Passive-Eye/
├── main.py                  # Entry point, splash, --pcap/--deep flags
├── core/
│   ├── database.py          # SQLite: devices, events, DNS, alerts, flows, fingerprints, exports
│   ├── parsers.py           # 24 protocol dissectors + flow extraction + layer dissection
│   ├── device_manager.py    # Device state, risk scoring, tags/watchlist, fingerprints
│   ├── sniffer.py           # Scapy engine: deep mode, PCAP read/write, pause, counters, ring buffer
│   └── analytics.py         # Passive anomaly/security engine (ARP spoof, port scan, DNS tunnel, ...)
├── core/
│   ├── settings.py          # JSON-persisted, live-applying settings (200+ keys)
│   ├── i18n.py              # EN/TR translations + tr()
│   └── netconfig.py         # Optional System Network module (macOS, opt-in, NOT passive)
├── gui/
│   ├── theme.py             # Neon hacker QSS + colour schemes + pixel accents
│   ├── matrix_bg.py         # Matrix digital-rain background (settings-driven)
│   ├── splash.py            # Boot splash with typing animation
│   ├── widgets.py           # GlowButton, AnimatedStatCard, Sparkline, PacketDetailTree, HexView, Toast
│   ├── network_graph.py     # Force-directed, risk-coloured graph (settle + visibility gating)
│   ├── settings_dialog.py   # Schema-driven Preferences dialog
│   ├── netconfig_panel.py   # Guarded System Network UI
│   └── main_window.py       # Main window, tabs, stat cards, menu, settings wiring
├── assets/fonts/            # Bundled OFL pixel fonts (Silkscreen, VT323)
└── utils/
    ├── oui_lookup.py        # OUI vendor table (+ optional external file loading)
    └── fingerprint.py       # JA3, p0f-style OS, MAC randomization, entropy
```

---

## Preferences

Open **Settings › Preferences…** (or the *Settings* menu) for 200+ options across
18 categories, with a search box and live apply. Highlights: colour schemes,
matrix-rain tuning, per-protocol enable/colour, capture buffer & filters, DNS &
tunneling thresholds, per-detector security toggles, risk-weight sliders,
network-map physics, MAC format, byte units, hotkeys, language, and privacy
(MAC anonymisation, hostname redaction). Settings live in `ghostwire_settings.json`.

## System Network module (optional, **not passive**)

Under **Preferences › System Network ⚠** you can change the *operating system's*
DNS servers, web proxy, interface MTU, and service state (macOS, via
`networksetup`). This is a deliberate, separate admin tool — it is **disabled by
default**, requires **root/Administrator**, **confirms** every change, **backs up**
the previous value to `ghostwire_netbackup.json`, offers one-click **Revert**, and
logs each action to the Alerts feed. It is **not** part of the passive guarantee,
which applies to the capture engine only.

---

## Safety & scope

- **Passive capture** — the sniffer registers only a `prn=` read callback on
  Scapy's `sniff()`; nothing is transmitted on the wire.
- The optional System Network module is the sole component that mutates state, and
  it does so on the local OS (not the network) only when you explicitly enable and
  apply it as root.
- Raw-socket capture requires root/Administrator (offline `--pcap` does not).
- Only run it on networks you own or are authorised to monitor.

## License

Educational use — CyberSec Club 2026.
