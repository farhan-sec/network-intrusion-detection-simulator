# Network Intrusion Detection System (NIDS) Simulation

## Overview

This project is a real-time Network Intrusion Detection System (NIDS) simulation built for educational purposes and a science exhibition.

It demonstrates how basic cybersecurity monitoring systems work by simulating network traffic, detecting suspicious behavior, and displaying alerts in a live web dashboard.

The system focuses on:
- Packet-based anomaly detection
- Port scan detection
- SYN flood detection
- Real-time alert visualization
- Device activity tracking

---

## Features

- Real-time attack simulation
- Port scan detection using sliding time window
- SYN flood detection using packet rate analysis
- Live web dashboard for monitoring alerts
- Device tracking with last-seen timestamps
- SQLite-based logging system
- Event-driven communication using WebSockets

---

## System Architecture

Simulator → Detector → Flask Server → Web Dashboard
↓
SQLite Database


---

## Tech Stack

- Python
- Flask
- Flask-SocketIO
- Scapy
- SQLite
- HTML, CSS, JavaScript

---

## Project Structure

network-intrusion-detection-simulator/
│
├── server.py
├── detector.py
├── simulator.py
├── models.py
├── requirements.txt
├── README.md
│
├── templates/
│ └── index.html
│
├── static/
│ └── style.css
│
└── screenshots/
└── dashboard.png


---

## How to Run

### 1. Install dependencies

pip install -r requirements.txt


---

### 2. Start the server

python server.py


---

### 3. Start the detector (requires admin/root privileges)

python detector.py


---

### 5. Open dashboard

http://localhost:5000


---

## How It Works

### Simulator
Generates fake network traffic patterns such as port scans and attack attempts.

### Detector
Analyzes incoming network packets using:
- Time-window analysis
- Threshold-based anomaly detection

### Server
Handles:
- Event processing
- Database storage
- Real-time communication with the dashboard

### Dashboard
Displays:
- Live security alerts
- Device activity
- Real-time updates without refreshing

---

## Disclaimer

This project is a simulation created for educational purposes only. It does not perform real-world attacks and should not be used maliciously.

---

## Learning Outcomes

This project demonstrates:
- Basics of intrusion detection systems
- Network packet analysis
- Real-time system design
- Event-driven backend architecture
- Full-stack Python development

---

## Author

Farhan Ali Khan  
Student | IT and Cybersecurity Enthusiast  
Pakistan

---

## Future Improvements

- Add severity scoring system (Low / Medium / High)
- Add attack statistics dashboard
- Export logs to CSV
- Improve detection accuracy
- Add authentication system for dashboard