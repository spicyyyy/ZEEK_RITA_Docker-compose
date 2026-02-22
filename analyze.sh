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
  echo -e "${YELLOW}[*] Ensuring ClickHouse is running...${NC}"
  docker compose up -d clickhouse
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
  read -p "Enter the number of the PCAP to analyze: " selection
  if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -ge "${#found[@]}" ]; then
    echo -e "${RED}[ERROR] Invalid selection.${NC}"
    exit 1
  fi
  pcap_name=$(basename "${found[$selection]}")

  # Auto-generate dataset name from PCAP filename + timestamp
  base="${pcap_name%.*}"
  sanitized=$(echo "$base" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '_' | sed 's/__*/_/g' | sed 's/^_//;s/_$//')
  [[ "$sanitized" =~ ^[0-9] ]] && sanitized="pcap_${sanitized}"
  sanitized="${sanitized:0:24}"; sanitized="${sanitized%_}"
  dataset_name="${sanitized}_$(date +%Y%m%d_%H%M%S)"
  echo -e "${CYAN}Dataset name: $dataset_name${NC}"

  echo ""
  echo -e "${YELLOW}[1/3] Running Zeek on $pcap_name ...${NC}"
  rm -f ./zeek-logs/*.log ./zeek-logs/*.gz 2>/dev/null
  docker compose run --rm zeek -C -r /pcaps/$pcap_name local
  echo -e "${GREEN}[+] Zeek logs written to ./zeek-logs/${NC}"

  echo ""
  echo -e "${YELLOW}[2/3] Importing logs into RITA ...${NC}"
  docker compose run --rm rita import --database "$dataset_name" --logs /zeek-logs
  echo -e "${GREEN}[+] Import complete. Dataset: $dataset_name${NC}"

  echo ""
  echo -e "${YELLOW}[3/3] Exporting beacon results to CSV ...${NC}"
  output_file="./results/${dataset_name}_beacons_$(date +%Y%m%d_%H%M%S).csv"
  curl -sS "http://localhost:8123/" \
    -d "SELECT beacon_threat_score, beacon_score, src, dst, fqdn, count, port_proto_service, beacon_type, long_conn_score, strobe_score, c2_over_dns_score, threat_intel, total_bytes, last_seen FROM ${dataset_name}.threat_mixtape ORDER BY beacon_threat_score DESC FORMAT CSVWithNames" \
    > "$output_file"

  echo ""
  echo -e "${CYAN}── BEACON RESULTS ─────────────────────────────────${NC}"
  cat "$output_file"
  echo -e "${CYAN}───────────────────────────────────────────────────${NC}"
  echo ""
  echo -e "${GREEN}✔ Done!${NC}"
  echo -e "   CSV  → $output_file"
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
  docker compose run --rm -e ZEEK_INTERFACE="$iface" zeek -i "$iface" local

  echo -e "${GREEN}[+] Capture stopped. Logs in ./zeek-logs/${NC}"

  # Auto-generate dataset name from interface + timestamp
  sanitized=$(echo "$iface" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '_' | sed 's/__*/_/g' | sed 's/^_//;s/_$//')
  dataset_name="live_${sanitized}_$(date +%Y%m%d_%H%M%S)"
  echo -e "${CYAN}Dataset name: $dataset_name${NC}"

  docker compose run --rm rita import --database "$dataset_name" --logs /zeek-logs

  output_file="./results/${dataset_name}_beacons_$(date +%Y%m%d_%H%M%S).csv"
  curl -sS "http://localhost:8123/" \
    -d "SELECT beacon_threat_score, beacon_score, src, dst, fqdn, count, port_proto_service, beacon_type, long_conn_score, strobe_score, c2_over_dns_score, threat_intel, total_bytes, last_seen FROM ${dataset_name}.threat_mixtape ORDER BY beacon_threat_score DESC FORMAT CSVWithNames" \
    > "$output_file"

  echo ""
  echo -e "${CYAN}── BEACON RESULTS ─────────────────────────────────${NC}"
  cat "$output_file"
  echo -e "${CYAN}───────────────────────────────────────────────────${NC}"
  echo ""
  echo -e "${GREEN}✔ Done! CSV → $output_file${NC}"
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
  echo "  [3] Clean up everything (wipe DB + logs)"
  echo "  [4] Exit"
  echo ""
  read -p "Choice [1-4]: " choice

  case "$choice" in
    1) start_dashboard; mode_pcap ;;
    2) start_dashboard; mode_live ;;
    3) mode_cleanup ;;
    4) echo "Bye!"; exit 0 ;;
    *) echo -e "${RED}Invalid choice.${NC}"; exit 1 ;;
  esac
}

main
