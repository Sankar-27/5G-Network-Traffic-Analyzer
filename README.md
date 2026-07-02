# 5G Network Traffic Analyzer

> Real-time packet capture + 5G network slicing simulation  
> Theme: Matrix green terminal | Stack: Flask + Scapy + Chart.js  
> Layout: Multi-tab dashboard (Overview / Traffic / Packets / Anomalies / 5G Slices)

## Quick Start

### Windows
```
1. Double-click install.bat   (first time only)
2. Double-click run.bat
3. Open http://127.0.0.1:5000
```

### Linux / Mac
```bash
pip3 install flask scapy
python3 app.py
# Open http://127.0.0.1:5000
```

## 🛠 Two Capture Modes

| Mode | Requirements | Notes |
|------|-------------|-------|
| **Simulated** | Just Python + Flask | Realistic traffic, works without admin, default |
| **Real Capture** | Admin + Scapy + Npcap | Captures actual NIC packets |


**Windows real capture**: Install [Npcap](https://npcap.com) first, then run as Administrator.

## Dashboard Tabs

| Tab | What you see |
|-----|-------------|
| **OVERVIEW** | KPIs, live throughput, protocol/category/encryption charts |
| **TRAFFIC** | Top IPs, top ports, Edge vs Cloud latency graph |
| **PACKETS** | Live scrolling packet table with filter controls |
| **ANOMALIES** | Threat log, detection rules, severity breakdown |
| **5G SLICES** | eMBB/URLLC/mMTC classification, MEC vs Cloud latency |


##  5G Concepts Simulated

- **Network Slicing**: Traffic auto-classified into eMBB / URLLC / mMTC per 3GPP specs
- **MEC (Multi-access Edge Computing)**: Edge vs cloud latency comparison
- **QoS Metrics**: Throughput, packet rate, latency approximation
- **Anomaly Detection**: DoS patterns, rate spikes, suspicious ports (C2 indicators)

##  Project Structure
```
5g_analyzer/
├── app.py              ← Flask backend + Scapy capture + API routes
├── templates/
│   └── index.html      ← Full dashboard UI (Matrix green theme)
├── requirements.txt
├── install.bat         ← Windows: install deps
├── run.bat             ← Windows: launch
└── run_linux.sh        ← Linux/Mac: launch
```
