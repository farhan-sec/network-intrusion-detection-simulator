from scapy.all import sniff, TCP, IP
from collections import defaultdict, deque
import time

import models
from server import receive_new_alert

# Detection thresholds
PORT_WINDOW = 10
PORT_THRESHOLD = 8

SYN_WINDOW = 10
SYN_THRESHOLD = 20

# Memory storage for detection logic
port_history = defaultdict(deque)
syn_history = defaultdict(deque)

models.init_db()


def check_port_scan(ip_address, port):
    now = time.time()

    port_history[ip_address].append((now, port))

    # Remove old entries outside time window
    while port_history[ip_address] and now - port_history[ip_address][0][0] > PORT_WINDOW:
        port_history[ip_address].popleft()

    ports_accessed = {p for _, p in port_history[ip_address]}

    if len(ports_accessed) >= PORT_THRESHOLD:
        receive_new_alert(
            ip_address,
            "PORT_SCAN",
            f"{len(ports_accessed)} ports scanned in {PORT_WINDOW}s"
        )


def check_syn_flood(ip_address):
    now = time.time()

    syn_history[ip_address].append(now)

    # Remove old SYN records
    while syn_history[ip_address] and now - syn_history[ip_address][0] > SYN_WINDOW:
        syn_history[ip_address].popleft()

    if len(syn_history[ip_address]) >= SYN_THRESHOLD:
        receive_new_alert(
            ip_address,
            "SYN_FLOOD",
            f"{len(syn_history[ip_address])} SYN packets in {SYN_WINDOW}s"
        )


def process_packet(packet):
    if IP not in packet:
        return

    ip_address = packet[IP].src
    models.update_device(ip_address)

    if TCP in packet:
        tcp = packet[TCP]

        # Port scan detection
        check_port_scan(ip_address, tcp.dport)

        # SYN flood detection
        if tcp.flags & 0x02:
            check_syn_flood(ip_address)


def start():
    print("[Detector] Running IDS simulation... (requires admin/root privileges)")
    sniff(prn=process_packet, store=False)


if __name__ == "__main__":
    start()
