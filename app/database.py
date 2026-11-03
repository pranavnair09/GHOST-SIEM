import json
import os
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.getenv("GHOST_SIEM_DB", str(DATA_DIR / "ghost_siem.db")))

def get_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn

def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                computer TEXT,
                channel TEXT,
                provider TEXT,
                event_id INTEGER,
                record_id INTEGER,
                level TEXT,
                message TEXT,
                source TEXT NOT NULL DEFAULT 'windows',
                raw_json TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_channel ON events(channel)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_level ON events(level)")

def insert_events(events):
    inserted = 0
    with get_connection() as conn:
        for event in events:
            event_key = event.get("event_key")
            if not event_key:
                identity = "|".join(str(event.get(k, "")) for k in
                    ("computer", "channel", "record_id", "event_id", "timestamp"))
                event_key = str(abs(hash(identity)))
            cur = conn.execute("""
                INSERT OR IGNORE INTO events
                (event_key, timestamp, computer, channel, provider, event_id,
                 record_id, level, message, source, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_key, event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                event.get("computer", "unknown"), event.get("channel", "unknown"),
                event.get("provider", "unknown"), event.get("event_id"),
                event.get("record_id"), event.get("level", "Information"),
                (event.get("message") or "")[:12000], event.get("source", "windows"),
                json.dumps(event, ensure_ascii=False, default=str)
            ))
            inserted += cur.rowcount
    return inserted

def fetch_events(limit=250):
    limit = max(1, min(int(limit), 5000))
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]

def fetch_stats():
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM events WHERE lower(level) IN ('critical','error')"
        ).fetchone()[0]
        warnings = conn.execute(
            "SELECT COUNT(*) FROM events WHERE lower(level) IN ('warning','warn')"
        ).fetchone()[0]
        channels = conn.execute(
            "SELECT channel, COUNT(*) AS count FROM events GROUP BY channel ORDER BY count DESC"
        ).fetchall()
        levels = conn.execute(
            "SELECT level, COUNT(*) AS count FROM events GROUP BY level ORDER BY count DESC"
        ).fetchall()
        latest = conn.execute("SELECT MAX(timestamp) FROM events").fetchone()[0]
        sources = conn.execute(
            "SELECT source, COUNT(*) AS count FROM events GROUP BY source"
        ).fetchall()
    return {
        "total": total, "critical_error": critical, "warnings": warnings,
        "latest": latest, "channels": [dict(x) for x in channels],
        "levels": [dict(x) for x in levels], "sources": [dict(x) for x in sources]
    }

def fetch_timeline():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT substr(timestamp, 1, 16) AS minute, COUNT(*) AS count
            FROM events
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY minute ORDER BY minute
        """).fetchall()
    return [dict(x) for x in rows]
