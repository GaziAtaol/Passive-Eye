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

            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_proto ON events(protocol);
            CREATE INDEX IF NOT EXISTS idx_dns_query ON dns_queries(query_name);
            CREATE INDEX IF NOT EXISTS idx_devices_last ON devices(last_seen);
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

    def export_json(self, path: str):
        data = {
            "devices": self.get_all_devices(),
            "protocol_stats": self.get_protocol_stats(),
            "top_dns": self.get_top_dns_queries(),
            "exported_at": time.time(),
        }
        for dev in data["devices"]:
            dev["services"] = self.get_device_services(dev["mac"])
        Path(path).write_text(json.dumps(data, indent=2))

    def close(self):
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
