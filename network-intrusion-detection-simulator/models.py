import sqlite3
import datetime

DB_NAME = "alerts.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # Alerts table
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            type TEXT,
            detail TEXT
        )
    """)

    # Devices table
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            last_seen TEXT
        )
    """)

    conn.commit()
    conn.close()

def clear_alerts():
    """Clears all previous alerts from the database"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()

def log_alert(src_ip, alert_type, detail):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO alerts (timestamp, src_ip, type, detail) VALUES (?, ?, ?, ?)",
        (timestamp, src_ip, alert_type, detail)
    )
    conn.commit()
    conn.close()

def get_last_alerts(limit=20):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(
        "SELECT timestamp, src_ip, type, detail FROM alerts ORDER BY id DESC LIMIT ?",
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
            "detail": row[3]
        })
    return alerts

def update_device(ip):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute("SELECT id FROM devices WHERE ip = ?", (ip,))
    result = c.fetchone()

    if result:
        c.execute("UPDATE devices SET last_seen = ? WHERE ip = ?", (timestamp, ip))
    else:
        c.execute("INSERT INTO devices (ip, last_seen) VALUES (?, ?)", (ip, timestamp))

    conn.commit()
    conn.close()

def get_devices():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT ip, last_seen FROM devices ORDER BY last_seen DESC")
    rows = c.fetchall()
    conn.close()

    devices = []
    for row in rows:
        devices.append({
            "ip": row[0],
            "last_seen": row[1]
        })
    return devices
