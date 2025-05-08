# NexLog – Intelligent Network Flow Monitoring

**NexLog** is a lightweight, high-performance service that captures and analyzes network traffic flows at a deep level using raw socket inspection. It operates silently in the background, turning raw packet data into rich, structured, and actionable insights.

---

## 🚀 Features
- 📦 **Raw Socket Capture** – Directly inspects packets at the IP level with minimal overhead.
- 🔍 **Flow-Based Analysis** – Aggregates packets into flows, tracking:
  - Protocol types (TCP/UDP/ICMP)
  - TCP flag behavior (SYN, ACK, FIN, etc.)
  - Byte counts, durations, and inter-packet timing
  - DNS queries
  - Entropy-based payload characterization
- 🧠 **JSON Lines Logging** – Logs each flow as a timestamped JSON object for easy parsing and streaming.
- 🧰 **Configurable** – Output path, rotation policy, server sync, and logging level are fully customizable.
- ☁️ **Server Integration** – Optionally sends logs to a remote server for centralized analysis.
- 🔇 **Silent Operation** – No UI, no prompts — just quiet, continuous monitoring.
- 🔍 **Anomaly Detection** – Basic heuristic-based anomaly detection for suspicious network patterns.

---

## 🛠️ Installation

1. Download the source files (`nexlog.c` and `nexlog.h`).

2. Build (Windows):
   ```bash
   cl.exe /W3 /D_CRT_SECURE_NO_WARNINGS /Fenexlog.exe nexlog3.c /link ws2_32.lib iphlpapi.lib wininet.lib advapi32.lib
   ```
   
   Or with MinGW GCC:
   ```bash
   gcc -o nexlog.exe nexlog.c -lws2_32 -liphlpapi -lwininet -ladvapi32
   ```

3. Install as a Windows service:
   ```bash
   nexlog.exe -install
   ```

4. The default configuration file is created at the executable's location. Edit `nexlog.conf` to customize settings.

5. Start the service:
   ```bash
   nexlog.exe -start
   ```

---

## 📋 Command Reference

```
nexlog.exe [command]

Commands:
  -install   Install the service (requires Administrator privileges).
             Creates a default config file if not found.
  -remove    Remove the service (requires Administrator privileges).
             Stops the service if running before removing.
  -start     Start the installed service.
  -stop      Stop the running service.
  -test      Perform basic tests (WinSock init, socket creation, server ping/send).
             Reads config for server URL. Does not run capture.
  -capture   Run packet capture in console mode (for testing/debugging).
             Reads config file. Press Ctrl+C to stop.
  -help      Show this help message.
```

---

## ⚙️ Configuration Options

The service reads settings from `nexlog.conf`. Key options include:

```
# --- File Paths ---
output_file=C:\ProgramData\NetworkMonitor3\network_log3.json
log_file=C:\ProgramData\NetworkMonitor3\network_monitor3.log

# --- Logging & Rotation ---
log_level=2 # 1=ERROR, 2=INFO, 3=DEBUG
file_rotation_size=10 # Max size in MB before rotation
log_retention_hours=6 # Hours to keep rotated logs (0=disabled)

# --- Capture Settings ---
capture_interval=60 # Default interval for logging flow summary (seconds)
bind_interface=0.0.0.0 # IP of interface to bind to (0.0.0.0 for auto-detect)

# --- Data Transmission ---
send_enabled=1 # 1=Enable, 0=Disable sending data to server
server_url=http://34.173.42.188:3000/api/network_data
send_interval=30 # Interval to send data batch (seconds)
ping_interval=90 # Interval to ping server (seconds)

# --- Advanced Features ---
enable_advanced_stats=1 # 1=Enable KDD-style stats, 0=Disable
enable_anomaly_detection=1 # 1=Enable basic anomaly checks, 0=Disable
connection_window=2 # Time window for connection stats (seconds)
max_host_memory=5000 # Max hosts to track in memory
anomaly_threshold=0.90 # Threshold (0.0-1.0) for error/diff_srv rate anomalies
```

---

## 📄 Output Format

Each captured flow is logged as a JSON line with rich metadata:

```json
{
  "timestamp": "2025-05-08T12:34:56",
  "duration": 1.234,
  "protocol": "TCP",
  "src_ip": "192.168.1.10",
  "src_port": 4321,
  "dst_ip": "8.8.8.8",
  "dst_port": 53,
  "service": "domain",
  "packets": 5,
  "bytes": 520,
  "src_packets": 3,
  "dst_packets": 2,
  "src_bytes": 320,
  "dst_bytes": 200,
  "flags": "SA---F",
  "flag": "SF",
  "flag_code": 9,
  "land": 0,
  "wrong_fragment": 0,
  "urgent": 0,
  "entropy": 4.723,
  "count": 12,
  "srv_count": 8,
  "serror_rate": 0.0833,
  "srv_serror_rate": 0.1250,
  "rerror_rate": 0.0,
  "srv_rerror_rate": 0.0,
  "same_srv_rate": 0.6667,
  "diff_srv_rate": 0.3333,
  "dst_host_count": 5,
  "dst_host_srv_count": 3,
  "dst_host_same_srv_rate": 0.6000,
  "dst_host_diff_srv_rate": 0.4000,
  "dns_query": "example.com"
}
```

---

## 🔬 Data Analysis Capabilities

NexLog provides rich network flow data that enables:

- **Connection Tracking**: Maps interactions between hosts and tracks connection states.
- **Protocol Analysis**: Classifies traffic by protocol and service type.
- **TCP Flag Behavior**: Tracks flag patterns to identify connection anomalies.
- **Statistical Profiling**: Calculates connection rates and error rates to detect unusual patterns.
- **Payload Entropy**: Measures information content to identify encoded/encrypted traffic.
- **DNS Monitoring**: Extracts and logs DNS queries.
- **KDD-Style Features**: Includes features used in the KDD Cup dataset for intrusion detection.

---

## 📈 Use Cases

- Building feature-rich datasets for ML-based anomaly detection  
- Passive network intelligence gathering  
- Lightweight Network Intrusion Detection System (NIDS) foundations  
- Profiling normal vs abnormal traffic behavior  
- DNS monitoring and entropy-based payload flagging  
- Identifying unusual service access patterns and potential scanning activities

---

## ⚠️ Requirements

- Windows operating system
- Administrator privileges (required for raw socket capture)
- Visual C++ Redistributable (for MSVC builds)

---

## 🔭 Future Work

The structured flow data collected by NexLog is intended for deeper network security research, including:

- Training **Reinforcement Learning** and **Meta-Learning** models to detect anomalous behavior  
- Using **custom optimization algorithms** for fine-tuning detection accuracy  
- Building an **Insider Threat Detection System** using behavioral baselines  
- Extending NexLog to support real-time alerts and forensic flow reconstruction  

By combining low-level visibility with intelligent post-processing, NexLog is a data engine and a research enabler.

---

## 📜 License

MIT License. See `LICENSE` for details.
