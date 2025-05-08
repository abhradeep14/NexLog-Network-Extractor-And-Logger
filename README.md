# NexLog – Intelligent Network Flow Monitoring

**NexLog** is a lightweight, high-performance service that captures and analyzes network traffic flows at a deep level using raw socket inspection. It operates silently in the background, turning raw packet data into rich, structured, and actionable insights.

---

## 🚀 Features

- 📦 **Raw Socket Capture** – Directly inspects packets at the IP level with minimal overhead.
- 🔍 **Flow-Based Analysis** – Aggregates packets into flows, tracking:
  - Protocol types (TCP/UDP)
  - TCP flag behavior (SYN, ACK, FIN, etc.)
  - Byte counts, durations, and inter-packet timing
  - DNS queries
  - Entropy-based payload characterization
- 🧠 **JSON Lines Logging** – Logs each flow as a timestamped JSON object for easy parsing and streaming.
- 🧰 **Configurable** – Output path, rotation policy, server sync, and logging level are fully customizable.
- ☁️ **Server Integration** – Optionally sends logs to a remote server for centralized analysis.
- 🔇 **Silent Operation** – No UI, no prompts — just quiet, continuous monitoring.

---

## 🛠️ Installation

1. Clone the repo:

   ```bash
   git clone https://github.com/yourusername/NexLog.git
   cd NexLog
   ```

2. Build (Windows):

   ```bash
   cl /FeNexLog.exe /W4 /O2 network_monitor2.c ws2_32.lib wininet.lib
   ```

3. Edit `network_monitor.conf` to set paths and options.

4. Run NexLog as a service or background process.

---

## 📄 Output Format

Each captured flow is logged as a JSON line:

```json
{
  "flow_id": 1234,
  "timestamp": "2025-05-08 12:34:56",
  "src_ip": "192.168.1.10",
  "dst_ip": "8.8.8.8",
  "protocol": "TCP",
  "src_port": 4321,
  "dst_port": 53,
  "bytes": 300,
  "duration": 1.2,
  "flags": "SA---F",
  "entropy": 5.21,
  "dns_query": "example.com"
}
```

---

## 📈 Use Cases

- Building feature-rich datasets for ML-based anomaly detection  
- Passive network intelligence gathering  
- Lightweight NIDS foundations  
- Profiling normal vs abnormal traffic behavior  
- DNS monitoring and entropy-based payload flagging  

---

## 🔭 Future Work

The structured flow data collected by NexLog is intended for deeper network security research, including:

- Training **Reinforcement Learning** and **Meta-Learning** models to detect anomalous behavior  
- Using **custom optimization algorithms** (e.g., Golden Jackal) to fine-tune detection accuracy  
- Building an **Insider Threat Detection System** using behavioral baselines  
- Extending NexLog to support real-time alerts and forensic flow reconstruction  

By combining low-level visibility with intelligent post-processing, NexLog serves as both a data engine and a research enabler.

---

## 📜 License

MIT License. See `LICENSE` for details.

---

## 🧠 Author

**Abhradeep** – Network security researcher, system programmer, and builder of purposeful tools.
