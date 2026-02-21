#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#   ZEEK + RITA  |  Threat Detection Script v2
#   Usage:  ./analyze.sh
# ═══════════════════════════════════════════════════════════════

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "═══════════════════════════════════════════════"
  echo "     ZEEK + RITA  |  Network Beacon Hunter     "
  echo "═══════════════════════════════════════════════"
  echo -e "${NC}"
}

check_docker() {
  if ! docker info &>/dev/null; then
    echo -e "${RED}[ERROR] Docker is not running. Start Docker first.${NC}"
    exit 1
  fi
}

start_db() {
  echo -e "${YELLOW}[*] Starting ClickHouse database...${NC}"
  docker compose up -d clickhouse
  echo -e "${YELLOW}[*] Waiting for ClickHouse to be ready...${NC}"
  docker compose up clickhouse --wait 2>/dev/null || sleep 15
  echo -e "${GREEN}[+] Database ready.${NC}"
}

mode_pcap() {
  echo ""
  echo -e "${CYAN}── PCAP MODE ─────────────────────────────────────${NC}"
  echo ""

  # List available PCAPs
  pcap_files=(./pcaps/*.pcap)
  if [ ${#pcap_files[@]} -eq 0 ] || [ ! -f "${pcap_files[0]}" ]; then
    echo -e "${RED}[ERROR] No .pcap files found in ./pcaps/${NC}"
    echo "  → Drop your PCAP files into the ./pcaps/ folder and re-run."
    exit 1
  fi

  echo "Available PCAP files:"
  for i in "${!pcap_files[@]}"; do
    echo "  [$i] $(basename ${pcap_files[$i]})"
  done

  echo ""
  read -p "Enter the PCAP filename (just the name, e.g. test.pcap): " pcap_name

  if [ ! -f "./pcaps/$pcap_name" ]; then
    echo -e "${RED}[ERROR] File not found: ./pcaps/$pcap_name${NC}"
    exit 1
  fi

  read -p "Enter a name for this dataset (letters/numbers/underscores only): " dataset_name

  if [[ ! "$dataset_name" =~ ^[a-zA-Z0-9_]+$ ]]; then
    echo -e "${RED}[ERROR] Dataset name can only contain letters, numbers, and underscores.${NC}"
    exit 1
  fi

  echo ""
  echo -e "${YELLOW}[*] Step 1/3 — Running Zeek on $pcap_name ...${NC}"
  # Clear old logs first to avoid mixing datasets
  rm -f ./zeek-logs/*.log ./zeek-logs/*.gz 2>/dev/null
  docker compose run --rm zeek zeek -C -r /pcaps/$pcap_name local
  echo -e "${GREEN}[+] Zeek logs written to ./zeek-logs/${NC}"

  echo ""
  echo -e "${YELLOW}[*] Step 2/3 — Importing logs into RITA ...${NC}"
  docker compose run --rm rita rita import --database="$dataset_name" --logs=/zeek-logs
  echo -e "${GREEN}[+] Import complete. Dataset: $dataset_name${NC}"

  echo ""
  echo -e "${YELLOW}[*] Step 3/3 — Exporting beacon results to CSV ...${NC}"
  output_file="./results/${dataset_name}_beacons_$(date +%Y%m%d_%H%M%S).csv"
  docker compose run --rm rita rita show-beacons "$dataset_name" > "$output_file"
  echo -e "${GREEN}[+] Results saved: $output_file${NC}"

  # Also show in terminal
  echo ""
  echo -e "${CYAN}── BEACON RESULTS (Terminal Preview) ─────────────${NC}"
  cat "$output_file"
  echo -e "${CYAN}───────────────────────────────────────────────────${NC}"

  echo ""
  echo -e "${GREEN}✔ Done! Results saved to: $output_file${NC}"
  echo -e "${CYAN}   Web Dashboard: http://localhost:8080${NC}"
}

mode_live() {
  echo ""
  echo -e "${CYAN}── LIVE CAPTURE MODE ─────────────────────────────${NC}"
  echo ""

  # List network interfaces
  echo "Available network interfaces:"
  ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  " $2}' | grep -v lo
  echo ""
  read -p "Enter the interface name (e.g. eth0, ens33): " iface

  if ! ip link show "$iface" &>/dev/null; then
    echo -e "${RED}[ERROR] Interface '$iface' not found.${NC}"
    exit 1
  fi

  echo ""
  echo -e "${YELLOW}[*] Starting Zeek on interface: $iface${NC}"
  echo -e "${YELLOW}    Press Ctrl+C to stop capture.${NC}"
  echo ""

  docker compose run --rm \
    -e ZEEK_INTERFACE="$iface" \
    zeek zeek -i "$iface" local

  echo ""
  echo -e "${GREEN}[+] Capture stopped. Logs written to ./zeek-logs/${NC}"
  echo ""

  read -p "Enter a name for this dataset (letters/numbers/underscores only): " dataset_name

  echo ""
  echo -e "${YELLOW}[*] Importing logs into RITA ...${NC}"
  docker compose run --rm rita rita import --database="$dataset_name" --logs=/zeek-logs

  echo ""
  echo -e "${YELLOW}[*] Exporting beacon results ...${NC}"
  output_file="./results/${dataset_name}_beacons_$(date +%Y%m%d_%H%M%S).csv"
  docker compose run --rm rita rita show-beacons "$dataset_name" > "$output_file"

  echo ""
  echo -e "${CYAN}── BEACON RESULTS ─────────────────────────────────${NC}"
  cat "$output_file"
  echo -e "${CYAN}───────────────────────────────────────────────────${NC}"
  echo ""
  echo -e "${GREEN}✔ Done! Results saved to: $output_file${NC}"
  echo -e "${CYAN}   Web Dashboard: http://localhost:8080${NC}"
}

start_dashboard() {
  echo -e "${YELLOW}[*] Starting RITA web dashboard...${NC}"
  docker compose up -d rita-web
  echo -e "${GREEN}[+] Dashboard is running at: http://localhost:8080${NC}"
}

main() {
  banner
  check_docker
  start_db

  echo "What do you want to do?"
  echo "  [1] Analyze a PCAP file"
  echo "  [2] Capture live traffic on an interface"
  echo "  [3] Just start the web dashboard"
  echo "  [4] Exit"
  echo ""
  read -p "Choice [1-4]: " choice

  case "$choice" in
    1) start_dashboard; mode_pcap ;;
    2) start_dashboard; mode_live ;;
    3) start_dashboard ;;
    4) echo "Bye!"; exit 0 ;;
    *) echo -e "${RED}Invalid choice.${NC}"; exit 1 ;;
  esac
}

main
