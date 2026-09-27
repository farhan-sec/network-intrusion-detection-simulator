"""
simulator.py

Generates safe, synthetic IDS alerts so you can see the dashboard working
without needing admin/root privileges or real network traffic. Great for
demos and for testing the frontend.

Run the dashboard first, then run this in a separate terminal:

    python server.py
    python simulator.py
"""

import time
from random import choice, randint

import socketio

SERVER_URL = "http://localhost:5000"

ips = ["192.168.0.5", "192.168.0.12", "10.0.0.7", "203.0.113.42", "198.51.100.23"]

# (alert_type, severity, detail_template) - kept in sync with the kinds of
# alerts detector.py can genuinely raise, including the previously-missing
# BRUTE_FORCE and SUSPICIOUS_PAYLOAD types.
ALERT_TEMPLATES = [
    ("PORT_SCAN", "MEDIUM", lambda: f"{randint(5, 20)} distinct ports scanned in 60s"),
    ("SYN_FLOOD", "CRITICAL", lambda: f"{randint(20, 500)} SYN packets in 10s"),
    ("BRUTE_FORCE", "HIGH", lambda: f"{randint(5, 15)} connection attempts to port {choice([22, 3389, 21])} in 300s"),
    ("SUSPICIOUS_PAYLOAD", "HIGH", lambda: f"Payload contained suspicious pattern: {choice(['DROP TABLE', '<script>', '../../../'])!r}"),
    ("SQL_INJECTION", "HIGH", lambda: "Detected SQL injection attempt in request payload"),
    ("XSS_ATTACK", "MEDIUM", lambda: "Detected reflected XSS attempt in query string"),
]

# BUGFIX (architecture): this used to do `from server import
# receive_new_alert`, which imports and re-runs server.py in *this*
# process, creating a second, disconnected Flask/SocketIO app. Alerts
# emitted that way never reached a browser connected to the real
# `python server.py` process. It now connects as a genuine Socket.IO
# client over the network, exactly like a real remote sensor would.
sio = socketio.Client()


def run():
    print(f"[Simulator] Connecting to dashboard at {SERVER_URL} ...")
    sio.connect(SERVER_URL)
    print("[Simulator] Connected. Generating synthetic alerts every ~2s. Ctrl+C to stop.")

    try:
        while True:
            source_ip = choice(ips)
            alert_type, severity, detail_fn = choice(ALERT_TEMPLATES)

            sio.emit("submit_alert", {
                "src_ip": source_ip,
                "type": alert_type,
                "detail": detail_fn(),
                "severity": severity,
            })

            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[Simulator] Stopping.")
    finally:
        sio.disconnect()


if __name__ == "__main__":
    run()
