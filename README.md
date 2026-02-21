# 🔍 ZEEK + RITA v2 — Network Threat Detection

Detect **beacons**, **C2 channels**, **DNS tunneling**, and more.  
Supports **PCAP analysis** and **live interface monitoring**.  
Outputs to **CSV**, **terminal**, and a **web dashboard**.

---

## ⚡ Quick Start (3 Steps)

**Step 1** — Clone and enter the project
```bash
git clone https://github.com/spicyyyy/ZEEK_RITA_Docker-compose.git zeek-rita
cd zeek-rita
```

**Step 2** — Make the script executable
```bash
chmod +x analyze.sh
```

**Step 3** — Run it
```bash
./analyze.sh
```

The script will ask you what you want to do — just follow the prompts.

---

## 📁 Folder Structure

```
zeek-rita-v2/
├── analyze.sh          ← Main script — run this
├── docker-compose.yml  ← All services defined here
├── rita-config/
│   └── config.hjson   ← RITA settings (edit your subnets here)
├── pcaps/              ← Drop your .pcap files here
├── zeek-logs/          ← Zeek writes logs here (auto-generated)
└── results/            ← Your CSV beacon reports land here
```

---

## 🛠️ What Each Service Does

| Service | What It Does |
|---|---|
| **zeek** | Converts PCAP or live traffic into connection logs |
| **clickhouse** | High-performance database (stores all RITA data) |
| **rita** | Analyzes zeek logs — finds beacons, C2, DNS tunneling |
| **rita-web** | Web dashboard at http://localhost:8080 |

---

## 🎯 Use Cases

### Analyze a PCAP file
1. Copy your `.pcap` file into the `./pcaps/` folder
2. Run `./analyze.sh`
3. Choose option `[1]`
4. Type the filename and a dataset name
5. Get results in `./results/` and at http://localhost:8080

### Monitor live traffic
1. Run `./analyze.sh`
2. Choose option `[2]`
3. Enter your network interface (e.g. `eth0`)
4. Press `Ctrl+C` when done capturing
5. Results saved automatically

### Just open the dashboard
1. Run `./analyze.sh`
2. Choose option `[3]`
3. Open http://localhost:8080

---

## ⚙️ Configuration

Edit `rita-config/config.hjson` before your first run:

```
// Set your internal network ranges
InternalSubnets: [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16"
]
```

This tells RITA what counts as "internal" vs "external" traffic.  
**This is important** — wrong subnets = wrong analysis.

---

## 🧹 Useful Commands

```bash
# Stop everything
docker compose down

# Wipe the database and start fresh
docker compose down -v

# Check running containers
docker compose ps

# View RITA logs
docker compose logs rita

# View Zeek logs
docker compose logs zeek
```

---

## 📦 Stack Versions

| Tool | Version |
|---|---|
| Zeek | Latest (activecm/docker-zeek) |
| RITA | v5.1.1 |
| ClickHouse | 24.3 |

---

## 🔄 What Changed from v1

| Old (v1) | New (v2) |
|---|---|
| blacktop/zeek (Zeek 3, unmaintained) | activecm/docker-zeek (latest) |
| MongoDB | ClickHouse (faster, built for analytics) |
| RITA v4 (no web UI) | RITA v5 (includes web dashboard) |
| Broken volume mounts | Fixed and tested |
| Inconsistent script | Clean interactive menu |
| No live capture support | Full live interface support |
| Manual commands only | One script does everything |
