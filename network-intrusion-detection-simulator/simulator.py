import time
from random import choice
from server import receive_new_alert

ips = ["192.168.0.5", "192.168.0.12", "10.0.0.7", "127.0.0.1"]
alerts = ["PORT_SCAN", "SYN_FLOOD", "SQL_INJECTION", "XSS_ATTACK"]

print("[Simulator] Running...")

while True:
    source_ip = choice(ips)
    alert_type = choice(alerts)

    receive_new_alert(
        source_ip,
        alert_type,
        f"Simulated {alert_type} detected"
    )

    time.sleep(2)
