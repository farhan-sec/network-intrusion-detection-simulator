# Advanced detection rules for network intrusion detection

DETECTION_RULES = {
    "port_scan": {
        "enabled": True,
        "ports_threshold": 5,
        "time_window": 60,
        "severity": "MEDIUM"
    },
    "brute_force": {
        "enabled": True,
        "failed_attempts": 5,
        "time_window": 300,
        "severity": "HIGH"
    },
    "ddos_detection": {
        "enabled": True,
        "packet_threshold": 1000,
        "time_window": 10,
        "severity": "CRITICAL"
    },
    "suspicious_payloads": {
        "enabled": True,
        "patterns": [
            "DROP TABLE",
            "../../../",
            "<script>",
            "eval(",
            "exec("
        ],
        "severity": "HIGH"
    },
    "encrypted_traffic_analysis": {
        "enabled": True,
        "monitor_tls_handshakes": True,
        "certificate_validation": True,
        "severity": "MEDIUM"
    }
}

# Real-time alerts configuration
ALERT_CONFIG = {
    "send_immediate_alert": True,
    "log_to_database": True,
    "generate_pcap": True,
    "retention_days": 30,
    "dashboard_update_interval": 5
}