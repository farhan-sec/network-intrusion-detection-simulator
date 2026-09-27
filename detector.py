"""
detector.py

Live packet sniffer for the IDS dashboard. Needs to run with admin/root
privileges since it uses raw sockets via scapy.

Run the dashboard first, then run this in a separate terminal:

    python server.py
    sudo python detector.py        # Linux/macOS
    (run as Administrator) python detector.py   # Windows
"""

import time
from collections import defaultdict, deque

import socketio
from scapy.all import sniff, TCP, IP, Raw

from detection_rules import DETECTION_RULES

SERVER_URL = "http://localhost:5000"

# BUGFIX: this file used to hardcode its own thresholds (PORT_WINDOW=10,
# PORT_THRESHOLD=8, ...) which quietly disagreed with the numbers declared
# in detection_rules.py (ports_threshold=5, time_window=60). Now there is
# a single source of truth.
PORT_RULE = DETECTION_RULES["port_scan"]
BRUTE_FORCE_RULE = DETECTION_RULES["brute_force"]
DDOS_RULE = DETECTION_RULES["ddos_detection"]
PAYLOAD_RULE = DETECTION_RULES["suspicious_payloads"]

# Ports commonly targeted by credential brute-forcing tools
AUTH_PORTS = {21, 22, 23, 25, 110, 143, 445, 3389, 3306, 5432}

# Memory storage for detection logic
port_history = defaultdict(deque)
auth_attempt_history = defaultdict(deque)
syn_history = defaultdict(deque)

# Socket.IO CLIENT - connects out to the running dashboard process instead
# of importing server.py's Flask app directly (see server.py's
# handle_submit_alert() docstring for why the old approach was broken).
sio = socketio.Client()


def send_alert(ip_address, alert_type, detail, severity="MEDIUM"):
    print(f"[Detector] ALERT {severity} {alert_type} from {ip_address}: {detail}")
    if sio.connected:
        sio.emit("submit_alert", {
            "src_ip": ip_address,
            "type": alert_type,
            "detail": detail,
            "severity": severity,
        })


def check_port_scan(ip_address, port):
    if not PORT_RULE.get("enabled", True):
        return

    window = PORT_RULE["time_window"]
    threshold = PORT_RULE["ports_threshold"]
    now = time.time()

    port_history[ip_address].append((now, port))

    while port_history[ip_address] and now - port_history[ip_address][0][0] > window:
        port_history[ip_address].popleft()

    ports_accessed = {p for _, p in port_history[ip_address]}

    if len(ports_accessed) >= threshold:
        send_alert(
            ip_address, "PORT_SCAN",
            f"{len(ports_accessed)} distinct ports scanned in {window}s",
            PORT_RULE.get("severity", "MEDIUM"),
        )


def check_syn_flood(ip_address):
    if not DDOS_RULE.get("enabled", True):
        return

    window = 10
    threshold = 20
    now = time.time()

    syn_history[ip_address].append(now)

    while syn_history[ip_address] and now - syn_history[ip_address][0] > window:
        syn_history[ip_address].popleft()

    if len(syn_history[ip_address]) >= threshold:
        send_alert(
            ip_address, "SYN_FLOOD",
            f"{len(syn_history[ip_address])} SYN packets in {window}s",
            DDOS_RULE.get("severity", "CRITICAL"),
        )


def check_brute_force(ip_address, dport):
    """
    NEW: this rule existed in detection_rules.py (failed_attempts /
    time_window / severity) but had no matching logic anywhere in the
    codebase. Flags repeated connection attempts to a common
    authentication port (SSH, RDP, FTP, DB ports, ...) from the same
    source within the configured window - a classic brute-force pattern.
    """
    if not BRUTE_FORCE_RULE.get("enabled", True) or dport not in AUTH_PORTS:
        return

    window = BRUTE_FORCE_RULE["time_window"]
    threshold = BRUTE_FORCE_RULE["failed_attempts"]
    now = time.time()

    key = (ip_address, dport)
    auth_attempt_history[key].append(now)

    while auth_attempt_history[key] and now - auth_attempt_history[key][0] > window:
        auth_attempt_history[key].popleft()

    if len(auth_attempt_history[key]) >= threshold:
        send_alert(
            ip_address, "BRUTE_FORCE",
            f"{len(auth_attempt_history[key])} connection attempts to port {dport} in {window}s",
            BRUTE_FORCE_RULE.get("severity", "HIGH"),
        )
        auth_attempt_history[key].clear()


def check_suspicious_payload(ip_address, packet):
    """
    NEW: also previously declared in detection_rules.py's "patterns" list
    (SQLi/path traversal/XSS/eval markers) with no code path that ever
    inspected packet contents. Does a lightweight substring scan of the
    raw TCP payload for those markers.
    """
    if not PAYLOAD_RULE.get("enabled", True) or Raw not in packet:
        return

    try:
        payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore")
    except Exception:
        return

    for pattern in PAYLOAD_RULE.get("patterns", []):
        if pattern.lower() in payload.lower():
            send_alert(
                ip_address, "SUSPICIOUS_PAYLOAD",
                f"Payload contained suspicious pattern: {pattern!r}",
                PAYLOAD_RULE.get("severity", "HIGH"),
            )
            break  # one alert per packet is enough


def process_packet(packet):
    if IP not in packet:
        return

    ip_address = packet[IP].src

    if TCP in packet:
        tcp = packet[TCP]

        check_port_scan(ip_address, tcp.dport)
        check_brute_force(ip_address, tcp.dport)
        check_suspicious_payload(ip_address, packet)

        # SYN flag set, ACK not set => new connection attempt (SYN flood check)
        if tcp.flags & 0x02 and not tcp.flags & 0x10:
            check_syn_flood(ip_address)


def start():
    print(f"[Detector] Connecting to dashboard at {SERVER_URL} ...")
    try:
        sio.connect(SERVER_URL)
    except Exception as e:
        print(f"[Detector] Could not connect to dashboard ({e}). "
              f"Alerts will only print locally - make sure server.py is running.")

    print("[Detector] Running IDS packet capture... (requires admin/root privileges)")
    try:
        sniff(prn=process_packet, store=False)
    except PermissionError:
        print("[Detector] Permission denied. Re-run this script as root/Administrator.")
    finally:
        if sio.connected:
            sio.disconnect()


if __name__ == "__main__":
    start()
