# ZEEK + RITA — Network Threat Detection

Detect **beacons**, **C2 channels**, **DNS tunneling**, and **long connections** using Zeek + RITA v5.
Supports **PCAP analysis** and **live interface monitoring**.
Outputs a **sortable HTML threat report** and a **CSV** — no web server required.

---

## Quick Start

### PowerShell (Windows)
```powershell
.\analyze.ps1
```

### Bash (WSL / Linux)
```bash
chmod +x analyze.sh
./analyze.sh
```

Both scripts give you an interactive menu. Pick a PCAP, and the rest is automatic — Zeek runs, RITA imports, and your report opens in the browser.

---

## What You Get

After each run, two files land in `results/`:

| File | Description |
|---|---|
| `<dataset>_report_<timestamp>.html` | Full interactive HTML threat report, auto-opens in browser |
| `<dataset>_beacons_<timestamp>.csv` | Raw CSV of all RITA results |

The HTML report includes:

- **Summary cards** — Beaconing / Threat Intel hits / Long Connections / Strobes / C2 over DNS, color-coded by severity
- **Beacon Analysis table** — every connection RITA analyzed, sortable and filterable, rows color-coded by threat score
- **Score Breakdown table** — per-connection breakdown of the four beacon score components (timestamp consistency, data size, duration, histogram shape)

---

## Folder Structure

```
├── analyze.ps1                      ← Run on Windows (PowerShell)
├── analyze.sh                       ← Run on WSL / Linux
├── docker-compose.yml               ← All services
├── rita-config/
│   ├── config.hjson                 ← Edit your internal subnets here
│   ├── clickhouse-users.xml         ← ClickHouse auth config
│   └── http_extensions_list.csv     ← MIME type reference for RITA
├── pcaps/                           ← Drop .pcap / .pcapng files here
├── zeek-logs/                       ← Zeek writes logs here (auto-cleared each run)
└── results/                         ← HTML reports and CSVs land here
```

---

## Before First Run — Set Your Subnets

Open `rita-config/config.hjson` and set your internal network ranges:

```hjson
filtering: {
  internal_subnets: [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
  ]
}
```

This tells RITA what counts as "internal" vs "external" traffic. **Wrong subnets = wrong results.**

---

## Services

| Service | What It Does |
|---|---|
| **zeek** | Converts PCAPs or live traffic into TSV connection logs |
| **clickhouse** | Analytics database backend for RITA v5 |
| **rita** | Detects beacons, C2 channels, DNS tunneling, long connections |

---

## Stack

| Tool | Version |
|---|---|
| Zeek | blacktop/zeek:latest |
| RITA | v5.1.1 |
| ClickHouse | 24.1 |

---

## Useful Commands

```bash
# Stop everything (keeps database)
docker compose down

# Wipe database and start completely fresh
docker compose down -v

# Check what's running
docker compose ps

# View RITA logs
docker compose logs rita
```

---

## Requirements

- Docker Desktop (Windows) or Docker Engine (Linux/WSL)
- PowerShell 5+ for `analyze.ps1`
- Internet access on first run (pulls Docker images, ~2 GB total)
