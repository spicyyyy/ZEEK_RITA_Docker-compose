#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#   ZEEK + RITA  |  Threat Detection Script
#   Run from WSL/Linux:  ./analyze.sh
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
    echo -e "${RED}[ERROR] Docker is not running. Start Docker Desktop first.${NC}"
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

start_dashboard() {
  echo -e "${YELLOW}[*] Starting RITA web dashboard...${NC}"
  docker compose up -d rita-web clickhouse
  echo -e "${GREEN}[+] Dashboard → http://localhost:8080${NC}"
}

mode_pcap() {
  echo -e "${CYAN}── PCAP MODE ──────────────────────────────────────${NC}"

  pcap_files=(./pcaps/*.pcap ./pcaps/*.pcapng)
  found=()
  for f in "${pcap_files[@]}"; do [ -f "$f" ] && found+=("$f"); done

  if [ ${#found[@]} -eq 0 ]; then
    echo -e "${RED}[ERROR] No .pcap files found in ./pcaps/${NC}"
    echo "  → Copy your PCAP into the ./pcaps/ folder then re-run."
    exit 1
  fi

  echo "Available PCAP files:"
  for i in "${!found[@]}"; do
    echo "  [$i] $(basename ${found[$i]})"
  done

  echo ""
  read -p "Enter the PCAP filename (e.g. test.pcap): " pcap_name
  [ ! -f "./pcaps/$pcap_name" ] && echo -e "${RED}[ERROR] Not found: ./pcaps/$pcap_name${NC}" && exit 1

  read -p "Enter a dataset name (letters/numbers/underscores): " dataset_name
  [[ ! "$dataset_name" =~ ^[a-zA-Z0-9_]+$ ]] && echo -e "${RED}[ERROR] Invalid name.${NC}" && exit 1

  echo ""
  echo -e "${YELLOW}[1/3] Running Zeek on $pcap_name ...${NC}"
  rm -f ./zeek-logs/*.log ./zeek-logs/*.gz 2>/dev/null
  docker compose run --rm zeek zeek -C -r /pcaps/$pcap_name local
  echo -e "${GREEN}[+] Zeek logs written to ./zeek-logs/${NC}"

  echo ""
  echo -e "${YELLOW}[2/3] Importing logs into RITA ...${NC}"
  docker compose run --rm rita rita import --database="$dataset_name" --logs=/zeek-logs
  echo -e "${GREEN}[+] Import complete. Dataset: $dataset_name${NC}"

  echo ""
  echo -e "${YELLOW}[3/3] Exporting beacon results to CSV ...${NC}"
  output_file="./results/${dataset_name}_beacons_$(date +%Y%m%d_%H%M%S).csv"
  docker compose run --rm rita rita show-beacons "$dataset_name" > "$output_file"

  echo ""
  echo -e "${CYAN}── BEACON RESULTS ─────────────────────────────────${NC}"
  cat "$output_file"
  echo -e "${CYAN}───────────────────────────────────────────────────${NC}"
  echo ""
  echo -e "${GREEN}✔ Done!${NC}"
  echo -e "   CSV  → $output_file"
  echo -e "   Web  → http://localhost:8080"
}

mode_live() {
  echo -e "${CYAN}── LIVE CAPTURE MODE ──────────────────────────────${NC}"

  echo "Available interfaces:"
  ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  " $2}' | grep -v lo
  echo ""
  read -p "Enter interface name (e.g. eth0): " iface
  ! ip link show "$iface" &>/dev/null && echo -e "${RED}[ERROR] Interface not found.${NC}" && exit 1

  echo ""
  echo -e "${YELLOW}[*] Starting Zeek on $iface — press Ctrl+C to stop.${NC}"
  docker compose run --rm -e ZEEK_INTERFACE="$iface" zeek zeek -i "$iface" local

  echo -e "${GREEN}[+] Capture stopped. Logs in ./zeek-logs/${NC}"

  read -p "Dataset name (letters/numbers/underscores): " dataset_name

  docker compose run --rm rita rita import --database="$dataset_name" --logs=/zeek-logs

  output_file="./results/${dataset_name}_beacons_$(date +%Y%m%d_%H%M%S).csv"
  docker compose run --rm rita rita show-beacons "$dataset_name" > "$output_file"

  echo ""
  echo -e "${CYAN}── BEACON RESULTS ─────────────────────────────────${NC}"
  cat "$output_file"
  echo -e "${CYAN}───────────────────────────────────────────────────${NC}"
  echo ""
  echo -e "${GREEN}✔ Done! CSV → $output_file  |  Web → http://localhost:8080${NC}"
}

mode_cleanup() {
  echo -e "${YELLOW}[*] Stopping all containers and wiping database...${NC}"
  docker compose down -v
  rm -f ./zeek-logs/*.log ./zeek-logs/*.gz 2>/dev/null
  echo -e "${GREEN}[+] Clean slate. Ready for a fresh run.${NC}"
}

main() {
  banner
  check_docker
  start_db

  echo "What do you want to do?"
  echo "  [1] Analyze a PCAP file"
  echo "  [2] Capture live traffic"
  echo "  [3] Start web dashboard only"
  echo "  [4] Clean up everything (wipe DB + logs)"
  echo "  [5] Exit"
  echo ""
  read -p "Choice [1-5]: " choice

  case "$choice" in
    1) start_dashboard; mode_pcap ;;
    2) start_dashboard; mode_live ;;
    3) start_dashboard ;;
    4) mode_cleanup ;;
    5) echo "Bye!"; exit 0 ;;
    *) echo -e "${RED}Invalid choice.${NC}"; exit 1 ;;
  esac
}

main
