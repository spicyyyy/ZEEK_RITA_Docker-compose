# 🔍 ZEEK + RITA — Network Threat Detection

Detect **beacons**, **C2 channels**, and **DNS tunneling** using Zeek + RITA v5.  
Supports **PCAP analysis** and **live interface monitoring**.  
Outputs to **CSV**, **terminal**, and a **web dashboard at http://localhost:8080**.

---

## ⚡ Quick Start

### PowerShell (Windows)
```powershell
.\analyze.ps1
```

### Bash (WSL / Linux)
```bash
chmod +x analyze.sh
./analyze.sh
```

Both scripts give you the same interactive menu — just pick what you want to do.

---

## 📁 Folder Structure

```
├── analyze.ps1          ← Run this on PowerShell (Windows)
├── analyze.sh           ← Run this on WSL/Linux
├── docker-compose.yml   ← All services
├── rita-config/
│   └── config.hjson     ← ⚠️ Edit your InternalSubnets here
├── pcaps/               ← Drop your .pcap files here
├── zeek-logs/           ← Zeek writes logs here (auto)
└── results/             ← CSV reports land here
```

---

## ⚙️ Before First Run — Edit Your Subnets

Open `rita-config/config.hjson` and set your network ranges:

```
InternalSubnets: [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16"
]
```

This tells RITA what's "internal" vs "external". **Wrong subnets = wrong results.**

---

## 🛠️ Services

| Service | What It Does |
|---|---|
| **zeek** | Converts PCAPs or live traffic into connection logs |
| **clickhouse** | Analytics database (RITA v5 backend) |
| **rita** | Detects beacons, C2, DNS tunneling |
| **rita-web** | Web dashboard at http://localhost:8080 |

---

## 🧹 Useful Commands

```bash
# Stop everything
docker compose down

# Wipe database and start fresh
docker compose down -v

# Check what's running
docker compose ps

# View logs
docker compose logs rita
docker compose logs zeek
```

---

## 📦 Stack

| Tool | Version |
|---|---|
| Zeek | Latest (activecm/docker-zeek) |
| RITA | v5.1.1 |
| ClickHouse | 24.3 |
