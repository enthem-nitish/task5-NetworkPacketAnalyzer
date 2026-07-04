<div align="center">

# 🕸️ Comillas Negras
### *Network Packet Analyzer*

**A powerful, educational Python tool for real-time network traffic capture & analysis**

![Python](https://img.shields.io/badge/Python-3.6%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Built%20with-Scapy-00599C?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-orange?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge)

</div>

---

## ⚠️ Disclaimer

> **THIS TOOL IS STRICTLY FOR EDUCATIONAL PURPOSES ONLY**

| ✅ Do | ❌ Don't |
|---|---|
| Use on networks you own | Sniff networks without permission |
| Get explicit written consent first | Ignore local cyber laws |
| Respect privacy laws (GDPR, etc.) | Use for malicious surveillance |

The developer assumes **no responsibility** for misuse. Unauthorized packet sniffing is illegal in many jurisdictions — always comply with local laws.

---

## 📡 Overview

**Comillas Negras** captures live network traffic, analyzes packets in real-time, and provides deep insight into what's flowing across a network — protocols, connections, payloads, and potential security red flags — all from a clean CLI.

---

## 🚀 Features

<table>
<tr>
<td width="50%" valign="top">

### 🔍 Core Capabilities
- Live packet capture in real-time
- Multi-protocol support — `TCP` `UDP` `ICMP` `ARP` `DNS` `HTTP` `IPv6`
- Detailed source/destination IP & port analysis
- HTTP request/header/URI reconstruction
- DNS query & response monitoring
- Suspicious port & port-scan detection
- Filter by IP address or port

</td>
<td width="50%" valign="top">

### 🎨 Interface & Data
- Interactive CLI shell mode
- Verbose / quiet output modes
- Color-coded terminal output
- Live protocol distribution stats
- JSON export for offline analysis
- Rolling history of up to 1000 packets

</td>
</tr>
</table>

---

## 📦 Installation

### Prerequisites
```bash
python3 --version   # Requires Python 3.6+
```

### 🐧 Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install python3-scapy python3-pip libpcap-dev
pip3 install colorama
```

### 🍎 macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install libpcap
brew install libpcap

# Install Python packages
pip3 install scapy colorama
```

### 🪟 Windows
```powershell
# Install Npcap (required for packet capture): https://npcap.com/

pip install scapy colorama
```

---

## 🎯 Usage Guide

### 💬 Interactive Mode *(recommended for beginners)*
```bash
python packet_analyzer.py
```

| Command | Description |
|---|---|
| `start [count]` | Begin packet capture |
| `stop` | Stop capture |
| `filter [expr]` | Set packet filter |
| `stats` | Show statistics |
| `export` | Export to JSON |
| `clear` | Clear captured data |
| `help` | Show help |
| `quit` | Exit program |

### ⌨️ Command Line Mode

```bash
# Capture all packets on default interface
sudo python packet_analyzer.py

# Capture a specific number of packets
sudo python packet_analyzer.py -c 100

# Capture on a specific network interface
sudo python packet_analyzer.py -i eth0

# Filter by IP address
sudo python packet_analyzer.py -f "192.168.1.1"

# Filter by port
sudo python packet_analyzer.py -f "80"

# Capture with a timeout (seconds)
sudo python packet_analyzer.py -t 30

# Export captured packets to JSON
sudo python packet_analyzer.py -c 50 --export capture.json

# Quiet mode (minimal output)
sudo python packet_analyzer.py --quiet

# Disable promiscuous mode
sudo python packet_analyzer.py --no-promisc
```

### 🔥 Advanced Examples
```bash
# Capture HTTP traffic only
sudo python packet_analyzer.py -f "80"

# Monitor DNS queries
sudo python packet_analyzer.py -f "53"

# Analyze traffic to/from a specific IP with export
sudo python packet_analyzer.py -f "192.168.1.100" -c 200 --export analysis.json
```

---

## 📊 Understanding the Output

### 📦 Packet Display Format
```
--------------------------------------------------------------------------------
Packet #123 - 2024-01-15T14:30:25.123456
  Protocol: TCP
  Size: 1520 bytes
  MAC: 00:11:22:33:44:55 -> 66:77:88:99:AA:BB
  Source: 192.168.1.100:54321
  Destination: 93.184.216.34:443 (HTTPS)
  TTL: 64
  Flags: PA
  Payload: GET /index.html HTTP/1.1...
--------------------------------------------------------------------------------
```

### 🚨 Security Alerts
The tool automatically flags:
- **Suspicious Ports** — SSH (22), Telnet (23), RDP (3389), VNC (5900), SMB (445)
- **Potential Port Scanning** — more than 20 connections to the same host

### 📈 Statistics Output
```
=== Capture Statistics ===
  Total packets captured: 1000
  Duration: 30.45 seconds
  Packets per second: 32.84

  Protocol Distribution:
    TCP: 650 (65.0%) ████████████████████████████████
    UDP: 250 (25.0%) ████████████
    DNS: 80 (8.0%)   ████
    ARP: 20 (2.0%)   █

  Top Connections:
    192.168.1.100->8.8.8.8: 450 packets
    192.168.1.100->93.184.216.34: 200 packets
```

---

## 🛠️ How It Works

### Architecture
1. **Packet Capture** — Uses Scapy's `sniff()` with libpcap/Npcap
2. **Protocol Parsing** — Analyzes each packet layer (Ethernet, IP, TCP/UDP, etc.)
3. **Data Extraction** — Pulls relevant fields from every layer
4. **HTTP/DNS Detection** — Identifies and parses application-layer protocols
5. **Alert System** — Checks for suspicious patterns
6. **Statistics Engine** — Tracks protocol distribution & top connections

### 🔄 Packet Analysis Flow
```
Packet Received
      ↓
Ethernet Layer  →  MAC Addresses
      ↓
IP Layer        →  Source/Destination IP, TTL
      ↓
Transport Layer →  Ports, Flags (TCP), Service Detection
      ↓
Application Layer → HTTP / DNS / Payload
      ↓
Security Check  →  Alerts Generation
      ↓
Display / Export → Formatted Output
```

### 🌐 Supported Protocols

| Protocol | Detection | Information Extracted |
|---|---|---|
| **TCP** | Port-based | Source/Destination Ports, Flags, Payload |
| **UDP** | Port-based | Source/Destination Ports, Payload |
| **ICMP** | Type/Code | Type, Code, Payload |
| **ARP** | Operation | Source/Destination IPs, MACs |
| **DNS** | Port 53 | Queries, Responses, Types |
| **HTTP** | Port 80/8080 | Method, URI, Host, User-Agent |
| **IPv6** | Next Header | Source/Destination IPs |

---

## 🔧 Configuration

### Default Settings

| Setting | Value |
|---|---|
| Max Packets Stored | 1000 |
| Promiscuous Mode | Enabled |
| Verbose Mode | Enabled |
| Suspicious Ports | 22, 23, 3389, 5900, 5800, 445, 139 |
| Scanning Threshold | 20 connections |

### 🎛️ Customization
You can modify the `PacketAnalyzer` class to:
- Change the suspicious ports list
- Adjust the scanning detection threshold
- Modify max packet storage
- Add custom protocol detection
- Change the output format

---

## 📝 JSON Export Format

```json
{
  "capture_info": {
    "start_time": "2024-01-15T14:30:25.123456",
    "end_time": "2024-01-15T14:31:55.123456",
    "total_packets": 1000
  },
  "packets": [
    {
      "timestamp": "2024-01-15T14:30:25.123456",
      "src_ip": "192.168.1.100",
      "dst_ip": "93.184.216.34",
      "src_port": 54321,
      "dst_port": 443,
      "protocol": "TCP",
      "size": 1520,
      "payload": "GET /index.html...",
      "flags": "PA",
      "ttl": 64,
      "service": "HTTPS"
    }
  ],
  "statistics": {
    "protocols": {
      "TCP": 650,
      "UDP": 250
    },
    "connections": {
      "192.168.1.100->8.8.8.8": 450
    }
  }
}
```

---

## 📥 Required Packages

```bash
pip install scapy colorama
```

---

<div align="center">

### 🕶️ *Built for learning how networks really talk to each other.*

</div>
