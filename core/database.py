"""
SQLite database for persistent storage of discovered devices and events.
"""
import sqlite3
import json
import time
import threading
from pathlib import Path


class Database:
    def __init__(self, db_path: str = "passive_scanner.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                ipv6 TEXT,
                hostname TEXT,
                vendor TEXT,
                os_guess TEXT,
                device_type TEXT,
                first_seen REAL,
                last_seen REAL,
                packet_count INTEGER DEFAULT 0,
                metadata TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                protocol TEXT NOT NULL,
                service_name TEXT,
                service_type TEXT,
                port INTEGER,
                details TEXT DEFAULT '{}',
                first_seen REAL,
                last_seen REAL,
                FOREIGN KEY (mac) REFERENCES devices(mac),
                UNIQUE(mac, protocol, service_name, port)
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                event_type TEXT NOT NULL,
                source_mac TEXT,
                dest_mac TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                summary TEXT,
                raw_data TEXT
            );

            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                source_mac TEXT,
                source_ip TEXT,
                query_name TEXT,
                query_type TEXT,
                response_ip TEXT
            );

            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                stat_type TEXT NOT NULL,
                key TEXT,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                mac TEXT,
                ip TEXT,
                title TEXT,
                detail TEXT,
                acknowledged INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS device_tags (
                mac TEXT PRIMARY KEY,
                alias TEXT,
                tags TEXT DEFAULT '',
                note TEXT DEFAULT '',
                watchlist INTEGER DEFAULT 0,
                risk_score INTEGER DEFAULT 0,
                updated REAL
            );

            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_mac TEXT,
                dst_mac TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                packets INTEGER DEFAULT 0,
                bytes INTEGER DEFAULT 0,
                first_seen REAL,
                last_seen REAL,
                flags TEXT DEFAULT '',
                UNIQUE(src_ip, dst_ip, src_port, dst_port, proto)
            );

            CREATE TABLE IF NOT EXISTS fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT,
                kind TEXT,
                value TEXT,
                detail TEXT,
                first_seen REAL,
                UNIQUE(mac, kind, value)
            );

            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_proto ON events(protocol);
            CREATE INDEX IF NOT EXISTS idx_dns_query ON dns_queries(query_name);
            CREATE INDEX IF NOT EXISTS idx_devices_last ON devices(last_seen);
            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_flows_tuple ON flows(src_ip, dst_ip, dst_port, proto);
            CREATE INDEX IF NOT EXISTS idx_fp_mac ON fingerprints(mac);
        """)
        conn.commit()

    def upsert_device(self, mac: str, **kwargs):
        conn = self._get_conn()
        now = time.time()
        existing = conn.execute(
            "SELECT * FROM devices WHERE mac = ?", (mac,)
        ).fetchone()

        if existing:
            updates = []
            params = []
            for key in ("ip", "ipv6", "hostname", "vendor", "os_guess", "device_type"):
                if key in kwargs and kwargs[key]:
                    updates.append(f"{key} = ?")
                    params.append(kwargs[key])
            updates.append("last_seen = ?")
            params.append(now)
            updates.append("packet_count = packet_count + 1")

            if "metadata" in kwargs:
                old_meta = json.loads(existing["metadata"] or "{}")
                old_meta.update(kwargs["metadata"])
                updates.append("metadata = ?")
                params.append(json.dumps(old_meta))

            params.append(mac)
            conn.execute(
                f"UPDATE devices SET {', '.join(updates)} WHERE mac = ?",
                params,
            )
        else:
            meta = json.dumps(kwargs.get("metadata", {}))
            conn.execute(
                """INSERT INTO devices
                   (mac, ip, ipv6, hostname, vendor, os_guess, device_type,
                    first_seen, last_seen, packet_count, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
                (
                    mac,
                    kwargs.get("ip"),
                    kwargs.get("ipv6"),
                    kwargs.get("hostname"),
                    kwargs.get("vendor"),
                    kwargs.get("os_guess"),
                    kwargs.get("device_type"),
                    now,
                    now,
                    meta,
                ),
            )
        conn.commit()

    def add_service(self, mac: str, protocol: str, **kwargs):
        conn = self._get_conn()
        now = time.time()
        try:
            conn.execute(
                """INSERT INTO services
                   (mac, protocol, service_name, service_type, port, details, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(mac, protocol, service_name, port)
                   DO UPDATE SET last_seen = ?, details = ?""",
                (
                    mac, protocol,
                    kwargs.get("service_name"),
                    kwargs.get("service_type"),
                    kwargs.get("port"),
                    json.dumps(kwargs.get("details", {})),
                    now, now,
                    now,
                    json.dumps(kwargs.get("details", {})),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass

    def add_event(self, event_type: str, protocol: str, **kwargs):
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO events
               (timestamp, event_type, source_mac, dest_mac,
                source_ip, dest_ip, protocol, summary, raw_data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                time.time(), event_type,
                kwargs.get("source_mac"),
                kwargs.get("dest_mac"),
                kwargs.get("source_ip"),
                kwargs.get("dest_ip"),
                protocol,
                kwargs.get("summary"),
                kwargs.get("raw_data"),
            ),
        )
        conn.commit()

    def add_dns_query(self, source_mac: str, source_ip: str,
                      query_name: str, query_type: str, response_ip: str = None):
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO dns_queries
               (timestamp, source_mac, source_ip, query_name, query_type, response_ip)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (time.time(), source_mac, source_ip, query_name, query_type, response_ip),
        )
        conn.commit()

    def get_all_devices(self) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_device_services(self, mac: str) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM services WHERE mac = ? ORDER BY protocol", (mac,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_recent_events(self, limit: int = 200) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_protocol_stats(self) -> dict:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT protocol, COUNT(*) as cnt FROM events GROUP BY protocol ORDER BY cnt DESC"
        ).fetchall()
        return {r["protocol"]: r["cnt"] for r in rows}

    def get_top_dns_queries(self, limit: int = 20) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT query_name, COUNT(*) as cnt
               FROM dns_queries GROUP BY query_name
               ORDER BY cnt DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_device_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as c FROM devices").fetchone()
        return row["c"]

    def get_event_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()
        return row["c"]

    def get_connections(self) -> list:
        """Get unique MAC-to-MAC communication pairs for network graph."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT source_mac, dest_mac, COUNT(*) as weight
               FROM events
               WHERE source_mac IS NOT NULL AND dest_mac IS NOT NULL
                 AND source_mac != dest_mac
               GROUP BY source_mac, dest_mac"""
        ).fetchall()
        return [dict(r) for r in rows]

    def get_timeline_data(self, hours: int = 1) -> list:
        conn = self._get_conn()
        cutoff = time.time() - (hours * 3600)
        rows = conn.execute(
            """SELECT CAST((timestamp - ?) / 60 AS INTEGER) as minute,
                      COUNT(*) as cnt
               FROM events WHERE timestamp > ?
               GROUP BY minute ORDER BY minute""",
            (cutoff, cutoff),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    #  Alerts                                                             #
    # ------------------------------------------------------------------ #
    def add_alert(self, severity: str, category: str, title: str,
                  detail: str = "", mac: str = None, ip: str = None):
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO alerts
               (timestamp, severity, category, mac, ip, title, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (time.time(), severity, category, mac, ip, title, detail),
        )
        conn.commit()

    def get_alerts(self, limit: int = 300, severity: str = None) -> list:
        conn = self._get_conn()
        if severity:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC LIMIT ?",
                (severity, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_alert_counts(self) -> dict:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
        ).fetchall()
        return {r["severity"]: r["cnt"] for r in rows}

    # ------------------------------------------------------------------ #
    #  Device tags / notes / watchlist / risk                            #
    # ------------------------------------------------------------------ #
    def set_device_tag(self, mac: str, **kwargs):
        conn = self._get_conn()
        mac = mac.lower()
        existing = conn.execute(
            "SELECT mac FROM device_tags WHERE mac = ?", (mac,)
        ).fetchone()
        fields = ("alias", "tags", "note", "watchlist", "risk_score")
        if existing:
            updates, params = [], []
            for k in fields:
                if k in kwargs and kwargs[k] is not None:
                    updates.append(f"{k} = ?")
                    params.append(kwargs[k])
            if not updates:
                return
            updates.append("updated = ?")
            params.append(time.time())
            params.append(mac)
            conn.execute(f"UPDATE device_tags SET {', '.join(updates)} WHERE mac = ?", params)
        else:
            conn.execute(
                """INSERT INTO device_tags (mac, alias, tags, note, watchlist, risk_score, updated)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (mac, kwargs.get("alias", ""), kwargs.get("tags", ""),
                 kwargs.get("note", ""), int(kwargs.get("watchlist", 0)),
                 int(kwargs.get("risk_score", 0)), time.time()),
            )
        conn.commit()

    def get_device_tag(self, mac: str) -> dict:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM device_tags WHERE mac = ?", (mac.lower(),)
        ).fetchone()
        return dict(row) if row else {}

    def get_all_tags(self) -> dict:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM device_tags").fetchall()
        return {r["mac"]: dict(r) for r in rows}

    def get_watchlist(self) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM device_tags WHERE watchlist = 1"
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    #  Flows / conversations                                             #
    # ------------------------------------------------------------------ #
    def upsert_flow(self, src_mac, dst_mac, src_ip, dst_ip,
                    src_port, dst_port, proto, size=0, flags=""):
        conn = self._get_conn()
        now = time.time()
        conn.execute(
            """INSERT INTO flows
               (src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, proto,
                packets, bytes, first_seen, last_seen, flags)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
               ON CONFLICT(src_ip, dst_ip, src_port, dst_port, proto)
               DO UPDATE SET packets = packets + 1,
                             bytes = bytes + ?,
                             last_seen = ?,
                             flags = flags || ?""",
            (src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, proto,
             size, now, now, flags, size, now, flags),
        )
        conn.commit()

    def get_conversations(self, limit: int = 500) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT src_ip, dst_ip, src_port, dst_port, proto,
                      SUM(packets) as packets, SUM(bytes) as bytes,
                      MIN(first_seen) as first_seen, MAX(last_seen) as last_seen
               FROM flows
               GROUP BY src_ip, dst_ip, src_port, dst_port, proto
               ORDER BY bytes DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_top_talkers(self, limit: int = 15) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT src_ip as ip, SUM(packets) as packets, SUM(bytes) as bytes
               FROM flows WHERE src_ip IS NOT NULL AND src_ip != ''
               GROUP BY src_ip ORDER BY bytes DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_port_stats(self, limit: int = 25) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT dst_port as port, proto, SUM(packets) as packets
               FROM flows WHERE dst_port IS NOT NULL AND dst_port > 0
               GROUP BY dst_port, proto ORDER BY packets DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    #  Fingerprints (JA3 / p0f / ...)                                    #
    # ------------------------------------------------------------------ #
    def add_fingerprint(self, mac: str, kind: str, value: str, detail: str = ""):
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR IGNORE INTO fingerprints (mac, kind, value, detail, first_seen)
                   VALUES (?, ?, ?, ?, ?)""",
                (mac.lower() if mac else mac, kind, value, detail, time.time()),
            )
            conn.commit()
        except sqlite3.Error:
            pass

    def get_fingerprints(self, mac: str = None) -> list:
        conn = self._get_conn()
        if mac:
            rows = conn.execute(
                "SELECT * FROM fingerprints WHERE mac = ? ORDER BY kind", (mac.lower(),)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM fingerprints ORDER BY kind").fetchall()
        return [dict(r) for r in rows]

    def get_db_stats(self) -> dict:
        conn = self._get_conn()

        def _count(table):
            return conn.execute(f"SELECT COUNT(*) as c FROM {table}").fetchone()["c"]

        return {
            "devices": _count("devices"),
            "events": _count("events"),
            "dns_queries": _count("dns_queries"),
            "services": _count("services"),
            "alerts": _count("alerts"),
            "flows": _count("flows"),
            "fingerprints": _count("fingerprints"),
        }

    def prune_events(self, keep_seconds: int = 86400):
        """Delete events/dns/flows older than ``keep_seconds``."""
        conn = self._get_conn()
        cutoff = time.time() - keep_seconds
        conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM dns_queries WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM flows WHERE last_seen < ?", (cutoff,))
        conn.commit()

    # ------------------------------------------------------------------ #
    #  Exports                                                           #
    # ------------------------------------------------------------------ #
    def export_json(self, path: str):
        data = {
            "tool": "GhostWire",
            "devices": self.get_all_devices(),
            "protocol_stats": self.get_protocol_stats(),
            "top_dns": self.get_top_dns_queries(),
            "alerts": self.get_alerts(1000),
            "conversations": self.get_conversations(1000),
            "fingerprints": self.get_fingerprints(),
            "tags": self.get_all_tags(),
            "exported_at": time.time(),
        }
        for dev in data["devices"]:
            dev["services"] = self.get_device_services(dev["mac"])
        Path(path).write_text(json.dumps(data, indent=2, default=str))

    def export_csv(self, path: str):
        import csv
        devices = self.get_all_devices()
        cols = ["mac", "ip", "ipv6", "hostname", "vendor", "os_guess",
                "device_type", "first_seen", "last_seen", "packet_count"]
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            writer.writeheader()
            for dev in devices:
                writer.writerow(dev)

    def export_html(self, path: str):
        """Dark-themed self-contained HTML report."""
        devices = self.get_all_devices()
        protos = self.get_protocol_stats()
        alerts = self.get_alerts(200)
        dns = self.get_top_dns_queries(30)
        gen = time.strftime("%Y-%m-%d %H:%M:%S")

        def esc(v):
            return (str(v) if v is not None else "-").replace("&", "&amp;").replace("<", "&lt;")

        def rows(items, keys):
            out = []
            for it in items:
                cells = "".join(f"<td>{esc(it.get(k))}</td>" for k in keys)
                out.append(f"<tr>{cells}</tr>")
            return "".join(out)

        proto_rows = "".join(
            f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
            for k, v in sorted(protos.items(), key=lambda x: -x[1])
        )
        html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>GhostWire Report</title><style>
body{{background:#0a0e14;color:#00ff41;font-family:'JetBrains Mono',Consolas,monospace;margin:24px;}}
h1{{letter-spacing:3px;text-shadow:0 0 8px #00ff41;}}
h2{{color:#00e5ff;border-bottom:1px solid #213026;padding-bottom:4px;}}
table{{border-collapse:collapse;width:100%;margin:10px 0 26px;}}
th,td{{border:1px solid #213026;padding:5px 8px;text-align:left;font-size:13px;}}
th{{background:#111722;color:#00e5ff;}}
tr:nth-child(even){{background:#0d1117;}}
.sev-critical{{color:#ff3b3b;}} .sev-warn{{color:#ffb000;}} .sev-info{{color:#00e5ff;}}
.meta{{color:#4a7a5a;}}
</style></head><body>
<h1>GhostWire // Passive Recon Report</h1>
<p class="meta">generated {gen} &nbsp;·&nbsp; {len(devices)} devices &nbsp;·&nbsp; {len(alerts)} alerts</p>
<h2>Devices</h2>
<table><tr><th>Type</th><th>MAC</th><th>IP</th><th>Hostname</th><th>Vendor</th><th>OS</th><th>Pkts</th></tr>
{rows(devices, ['device_type','mac','ip','hostname','vendor','os_guess','packet_count'])}</table>
<h2>Protocol Distribution</h2>
<table><tr><th>Protocol</th><th>Events</th></tr>{proto_rows}</table>
<h2>Security Alerts</h2>
<table><tr><th>Severity</th><th>Category</th><th>Title</th><th>Device</th></tr>
{"".join(f'<tr><td class="sev-{esc(a.get("severity"))}">{esc(a.get("severity"))}</td><td>{esc(a.get("category"))}</td><td>{esc(a.get("title"))}</td><td>{esc(a.get("mac") or a.get("ip"))}</td></tr>' for a in alerts)}</table>
<h2>Top DNS Queries</h2>
<table><tr><th>Domain</th><th>Count</th></tr>{rows(dns, ['query_name','cnt'])}</table>
</body></html>"""
        Path(path).write_text(html)

    def close(self):
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
