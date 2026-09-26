# 🌐 Network Intrusion Detection Simulator

> Real-time network monitoring and threat detection system with live web dashboard.

## What Problem Does This Solve?

Network security teams need to detect threats in real-time. But most intrusion detection systems (IDS) show raw logs and confusing alerts.

**This tool shows you:**
- What's happening on your network *right now*
- When something suspicious occurs *immediately*
- Why it's suspicious (not just an alert code)

It's built for learning how real IDS systems work, and for seeing threats the way security professionals see them.

---

## Features

✨ **Real-Time Network Analysis**
- Captures and analyzes live packet data
- Detects suspicious patterns and anomalies
- Classifies threat types automatically

✨ **Live Web Dashboard**
- See network events as they happen
- Filter by threat level, type, source
- Visual representation of network activity

✨ **Event-Based Alerting**
- Alerts trigger when threats are detected
- Not just alarms—actionable intelligence
- Understand what triggered each alert

✨ **Packet Analysis**
- Deep inspection of network protocols
- Identifies attack signatures
- Tracks connections and flows

---

## Getting Started

### Installation

```bash
git clone https://github.com/farhan-sec/network-intrusion-detection-simulator.git
cd network-intrusion-detection-simulator

pip install -r requirements.txt
python app.py
```

### Running

```bash
# Start the IDS
python ids.py

# In another terminal, start the web dashboard
python dashboard.py

# Open browser to http://localhost:5000
```

---

## How It Works

```
Network Traffic
    ↓
Packet Capture (Scapy)
    ↓
Protocol Analysis
    ↓
Pattern Matching & Anomaly Detection
    ↓
Threat Classification
    ↓
Web Dashboard (Real-time visualization)
```

---

## Detection Capabilities

The system detects:

- **Port Scanning** - Multiple connection attempts to different ports
- **Brute Force Attempts** - Repeated failed authentication
- **Unusual Protocols** - Unexpected services on unusual ports
- **DDoS Patterns** - Traffic spikes from single source
- **Malicious Payloads** - Known attack signatures
- **Reconnaissance** - Probing and information gathering

---

## Example Output

```
[ALERT] Port Scan Detected
Source: 192.168.1.50
Target Ports: 22, 80, 443, 3306, 5432
Threat Level: MEDIUM
Details: Sequential port connections suggest reconnaissance activity
```

---

## Technical Architecture

**Components:**

1. **Packet Sniffer** (Scapy)
   - Captures network packets
   - Extracts protocols, ports, payloads

2. **Analysis Engine**
   - Applies detection rules
   - Identifies anomalies
   - Classifies threats

3. **Web Dashboard** (Flask + Socket.IO)
   - Real-time event streaming
   - Historical analysis
   - Threat visualization

4. **Alert System**
   - Event-driven notifications
   - Severity classification
   - Actionable intelligence

---

## What I Learned

**About Network Security:**
- Understanding packet structure is key to threat detection
- Real attacks often look like innocent traffic at first glance
- False positives are the biggest challenge in IDS work

**About System Design:**
- Real-time processing needs efficient filtering
- Live dashboards are complex but essential
- Security tools need explainability (why is this an alert?)

**About Python & Networking:**
- Scapy is incredibly powerful for packet manipulation
- Socket.IO makes real-time dashboards possible
- Threat detection is as much art as science

---

## Limitations & Future Work

**Current Limitations:**
- Signature-based detection (not machine learning... yet)
- Limited to local network capture
- Requires root/admin privileges

**Planned Improvements:**
- Machine learning for anomaly detection
- Integration with threat intelligence feeds
- Support for encrypted traffic analysis
- Distributed monitoring for larger networks

---

## Use Cases

- **Learning** - Understand how IDS systems actually work
- **Security Practice** - Test your threat detection skills
- **Lab Environment** - Simulate network attacks safely
- **Interview Prep** - Learn IDS concepts before job interviews

---

## Technical Stack

- **Language:** Python 3.7+
- **Packet Analysis:** Scapy
- **Web Framework:** Flask
- **Real-time Communication:** Socket.IO
- **Database:** SQLite (for event logging)

---

## License

MIT - Use and modify freely

---

## Questions?

- 📧 Email: qitpo01official@gmail.com
- 🔗 LinkedIn: [Farhan Ali Khan](https://linkedin.com/in/farhan-ali-khan-14b4872b5)

---

Built for people learning how to protect networks.