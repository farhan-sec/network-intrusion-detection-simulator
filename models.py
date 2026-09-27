import sqlite3
import datetime

DB_NAME = "alerts.db"


def _connect():
    """
    Open a connection tuned for multiple processes writing at once
    (server.py, detector.py and simulator.py can all be running at the
    same time and all touch this database).

    BUGFIX: the previous version used sqlite3.connect(DB_NAME) with no
    timeout and no WAL journal mode. Under concurrent writes from more
    than one process that reliably raises "database is locked" errors.
    """
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = _connect()
    c = conn.cursor()

    # Alerts table
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            type TEXT,
            severity TEXT,
            detail TEXT
        )
    """)

    # Devices table
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            last_seen TEXT,
            alert_count INTEGER DEFAULT 0
        )
    """)

    # Lightweight migration for people upgrading an existing alerts.db
    # that predates the severity / alert_count columns.
    existing_alert_cols = {row[1] for row in c.execute("PRAGMA table_info(alerts)")}
    if "severity" not in existing_alert_cols:
        c.execute("ALTER TABLE alerts ADD COLUMN severity TEXT DEFAULT 'MEDIUM'")

    existing_device_cols = {row[1] for row in c.execute("PRAGMA table_info(devices)")}
    if "alert_count" not in existing_device_cols:
        c.execute("ALTER TABLE devices ADD COLUMN alert_count INTEGER DEFAULT 0")

    conn.commit()
    conn.close()


def clear_alerts():
    """Clears all previous alerts from the database"""
    conn = _connect()
    c = conn.cursor()
    c.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()


def log_alert(src_ip, alert_type, detail, severity="MEDIUM"):
    conn = _connect()
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO alerts (timestamp, src_ip, type, severity, detail) VALUES (?, ?, ?, ?, ?)",
        (timestamp, src_ip, alert_type, severity, detail)
    )
    conn.commit()
    conn.close()


def get_last_alerts(limit=20):
    conn = _connect()
    c = conn.cursor()
    c.execute(
        "SELECT timestamp, src_ip, type, severity, detail FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = c.fetchall()
    conn.close()

    alerts = []
    for row in rows:
        alerts.append({
            "timestamp": row[0],
            "src_ip": row[1],
            "type": row[2],
            "severity": row[3],
            "detail": row[4]
        })
    return alerts


def get_alert_stats():
    """New: counts of alerts by severity, used by the dashboard summary bar."""
    conn = _connect()
    c = conn.cursor()
    c.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    rows = c.fetchall()
    conn.close()
    return {severity: count for severity, count in rows}


def update_device(ip):
    conn = _connect()
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute("SELECT id, alert_count FROM devices WHERE ip = ?", (ip,))
    result = c.fetchone()

    if result:
        c.execute("UPDATE devices SET last_seen = ? WHERE ip = ?", (timestamp, ip))
    else:
        c.execute("INSERT INTO devices (ip, last_seen, alert_count) VALUES (?, ?, 0)", (ip, timestamp))

    conn.commit()
    conn.close()


def increment_device_alert_count(ip):
    conn = _connect()
    c = conn.cursor()
    c.execute("UPDATE devices SET alert_count = alert_count + 1 WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()


def get_devices():
    conn = _connect()
    c = conn.cursor()
    c.execute("SELECT ip, last_seen, alert_count FROM devices ORDER BY last_seen DESC")
    rows = c.fetchall()
    conn.close()

    devices = []
    for row in rows:
        devices.append({
            "ip": row[0],
            "last_seen": row[1],
            "alert_count": row[2]
        })
    return devices
