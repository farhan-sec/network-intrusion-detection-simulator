# 🕵️ Network Intrusion Detection System (Simulator)

A real-time network intrusion detection dashboard. Watch simulated (or genuinely sniffed) network attacks — port scans, SYN floods, brute-force attempts, and suspicious payloads — appear live on a web dashboard.

## ✨ Features

- **Live dashboard** (Flask + Socket.IO) showing alerts and known devices in real time
- **Two data sources**, runnable independently or together:
  - `simulator.py` — safe, synthetic demo traffic (no special privileges needed)
  - `detector.py` — real packet capture via Scapy (needs admin/root)
- **Detection rules** (`detection_rules.py`) now actually drive detection logic:
  - Port scan detection
  - SYN flood / DDoS detection
  - **Brute-force detection** (new) — flags repeated connection attempts to common auth ports (SSH, RDP, FTP, DB ports, ...)
  - **Suspicious payload detection** (new) — scans raw TCP payloads for markers like `DROP TABLE`, `<script>`, `../../../`
- **Severity-aware UI** — color-coded rows and a live stats bar (Critical / High / Medium / Low counts)
- **REST API** — `/api/alerts`, `/api/devices`, `/api/stats` for pulling data into other tools

## 🐛 Fixed in this update

- **Alerts never reached the dashboard (architecture bug)** — `detector.py` and `simulator.py` used to do `from server import receive_new_alert`, which re-imports and re-runs `server.py` inside their *own* process. That creates a second, disconnected Flask/SocketIO app — any alert they "emitted" vanished into an app nobody was looking at. They now connect to the running dashboard as genuine **Socket.IO clients** and emit a `submit_alert` event over the network, exactly like a real remote sensor would.
- **XSS in the dashboard** — alert fields (`src_ip`, `type`, `detail`) were inserted via `innerHTML` template strings with no escaping. Since these values originate from network traffic, an attacker could embed HTML/JS that would execute in the dashboard. Rows are now built with `textContent`.
- **`detection_rules.py` was dead code with inconsistent duplicates** — `detector.py` hardcoded its own thresholds that didn't match the numbers declared in `detection_rules.py`. There is now a single source of truth.
- **Two rules were declared but never implemented** — `brute_force` and `suspicious_payloads` existed in the config but had no matching detection logic anywhere. Both are now implemented.
- **SQLite locking under concurrent writes** — `server.py`, `detector.py`, and `simulator.py` can all write to `alerts.db` at once. The database connection now uses WAL mode and a busy timeout instead of the default (which throws "database is locked" under load).

## 📦 Installation

```bash
git clone https://github.com/farhan-sec/network-intrusion-detection-simulator.git
cd network-intrusion-detection-simulator
pip install -r requirements.txt
```

## 🚀 Usage

**1. Start the dashboard:**

```bash
python server.py
```

Open **http://localhost:5000** in your browser.

**2. Feed it data** — pick one (or run both):

```bash
# Safe synthetic demo data, no special privileges required
python simulator.py

# Real packet capture (needs admin/root)
sudo python detector.py          # Linux/macOS
python detector.py               # Windows, run terminal as Administrator
```

**3. (Optional) Pull data programmatically:**

```bash
curl http://localhost:5000/api/alerts?limit=10
curl http://localhost:5000/api/devices
curl http://localhost:5000/api/stats
```

## 🗂️ Project structure

```
network-intrusion-detection-simulator/
├── server.py            # Flask + Socket.IO dashboard, single source of truth
├── detector.py          # Live packet sniffer (Socket.IO client)
├── simulator.py         # Synthetic demo traffic generator (Socket.IO client)
├── models.py            # SQLite persistence (alerts, devices)
├── detection_rules.py   # Thresholds/severities used by detector.py
├── requirements.txt
├── static/style.css
└── templates/index.html
```

## 🧭 Roadmap

- [ ] Configurable alert retention / auto-purge (per `ALERT_CONFIG["retention_days"]`)
- [ ] PCAP export for flagged traffic (per `ALERT_CONFIG["generate_pcap"]`)
- [ ] Per-IP block-list suggestions after repeated CRITICAL alerts
- [ ] WebSocket auth so the dashboard isn't wide open on shared networks

## ⚠️ Disclaimer

`detector.py` performs real, passive packet sniffing on the interface it's run on. Only run it on networks you own or have explicit permission to monitor.

## 📄 License

MIT
