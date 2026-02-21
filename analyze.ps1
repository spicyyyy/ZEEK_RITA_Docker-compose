# ═══════════════════════════════════════════════════════════════
#   ZEEK + RITA  |  Threat Detection Script (PowerShell)
#   Run from PowerShell:  .\analyze.ps1
#   Requirements: Docker Desktop running
# ═══════════════════════════════════════════════════════════════

function Show-Banner {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "     ZEEK + RITA  |  Network Beacon Hunter     " -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Docker {
    $result = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Docker is not running. Start Docker Desktop first." -ForegroundColor Red
        exit 1
    }
}

function Start-Database {
    Write-Host "[*] Starting ClickHouse database..." -ForegroundColor Yellow
    docker compose up -d clickhouse
    Write-Host "[*] Waiting for ClickHouse to be ready..." -ForegroundColor Yellow
    Start-Sleep -Seconds 15
    Write-Host "[+] Database ready." -ForegroundColor Green
}

function Start-Dashboard {
    Write-Host "[*] Starting RITA web dashboard..." -ForegroundColor Yellow
    docker compose up -d rita-web clickhouse
    Write-Host "[+] Dashboard → http://localhost:8080" -ForegroundColor Green
}

function Invoke-PcapMode {
    Write-Host ""
    Write-Host "── PCAP MODE ──────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    # List available PCAPs
    $pcapFiles = Get-ChildItem -Path ".\pcaps\" -Include "*.pcap","*.pcapng" -ErrorAction SilentlyContinue
    if ($pcapFiles.Count -eq 0) {
        Write-Host "[ERROR] No .pcap files found in .\pcaps\" -ForegroundColor Red
        Write-Host "  → Copy your PCAP into the .\pcaps\ folder then re-run."
        return
    }

    Write-Host "Available PCAP files:"
    for ($i = 0; $i -lt $pcapFiles.Count; $i++) {
        Write-Host "  [$i] $($pcapFiles[$i].Name)"
    }

    Write-Host ""
    $pcapName = Read-Host "Enter the PCAP filename (e.g. test.pcap)"
    if (-not (Test-Path ".\pcaps\$pcapName")) {
        Write-Host "[ERROR] File not found: .\pcaps\$pcapName" -ForegroundColor Red
        return
    }

    $datasetName = Read-Host "Enter a dataset name (letters/numbers/underscores only)"
    if ($datasetName -notmatch '^[a-zA-Z0-9_]+$') {
        Write-Host "[ERROR] Invalid dataset name." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "[1/3] Running Zeek on $pcapName ..." -ForegroundColor Yellow
    # Clear old logs
    Remove-Item ".\zeek-logs\*.log" -ErrorAction SilentlyContinue
    Remove-Item ".\zeek-logs\*.gz"  -ErrorAction SilentlyContinue
    docker compose run --rm zeek zeek -C -r /pcaps/$pcapName local
    Write-Host "[+] Zeek logs written to .\zeek-logs\" -ForegroundColor Green

    Write-Host ""
    Write-Host "[2/3] Importing logs into RITA ..." -ForegroundColor Yellow
    docker compose run --rm rita rita import --database="$datasetName" --logs=/zeek-logs
    Write-Host "[+] Import complete. Dataset: $datasetName" -ForegroundColor Green

    Write-Host ""
    Write-Host "[3/3] Exporting beacon results to CSV ..." -ForegroundColor Yellow
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = ".\results\${datasetName}_beacons_${timestamp}.csv"
    docker compose run --rm rita rita show-beacons $datasetName | Out-File -FilePath $outputFile -Encoding utf8

    Write-Host ""
    Write-Host "── BEACON RESULTS ─────────────────────────────────" -ForegroundColor Cyan
    Get-Content $outputFile
    Write-Host "───────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[+] Done!" -ForegroundColor Green
    Write-Host "   CSV  → $outputFile"
    Write-Host "   Web  → http://localhost:8080" -ForegroundColor Cyan
}

function Invoke-LiveMode {
    Write-Host ""
    Write-Host "── LIVE CAPTURE MODE ──────────────────────────────" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Note: Live capture requires Docker Desktop with Linux containers." -ForegroundColor Yellow
    Write-Host ""

    # Show interfaces
    Write-Host "Available network interfaces:"
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
        Write-Host "  $($_.Name) — $($_.InterfaceDescription)"
    }

    Write-Host ""
    $iface = Read-Host "Enter the interface name (as shown above)"

    Write-Host ""
    Write-Host "[*] Starting Zeek on $iface — press Ctrl+C to stop." -ForegroundColor Yellow
    docker compose run --rm zeek zeek -i $iface local

    Write-Host "[+] Capture stopped. Logs in .\zeek-logs\" -ForegroundColor Green

    $datasetName = Read-Host "Enter a dataset name (letters/numbers/underscores)"

    docker compose run --rm rita rita import --database="$datasetName" --logs=/zeek-logs

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = ".\results\${datasetName}_beacons_${timestamp}.csv"
    docker compose run --rm rita rita show-beacons $datasetName | Out-File -FilePath $outputFile -Encoding utf8

    Write-Host ""
    Write-Host "── BEACON RESULTS ─────────────────────────────────" -ForegroundColor Cyan
    Get-Content $outputFile
    Write-Host "───────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[+] Done! CSV → $outputFile  |  Web → http://localhost:8080" -ForegroundColor Green
}

function Invoke-Cleanup {
    Write-Host "[*] Stopping all containers and wiping database..." -ForegroundColor Yellow
    docker compose down -v
    Remove-Item ".\zeek-logs\*.log" -ErrorAction SilentlyContinue
    Remove-Item ".\zeek-logs\*.gz"  -ErrorAction SilentlyContinue
    Write-Host "[+] Clean slate. Ready for a fresh run." -ForegroundColor Green
}

# ── MAIN ────────────────────────────────────────────────────────
Show-Banner
Test-Docker
Start-Database

Write-Host "What do you want to do?"
Write-Host "  [1] Analyze a PCAP file"
Write-Host "  [2] Capture live traffic"
Write-Host "  [3] Start web dashboard only"
Write-Host "  [4] Clean up everything (wipe DB + logs)"
Write-Host "  [5] Exit"
Write-Host ""
$choice = Read-Host "Choice [1-5]"

switch ($choice) {
    "1" { Start-Dashboard; Invoke-PcapMode }
    "2" { Start-Dashboard; Invoke-LiveMode }
    "3" { Start-Dashboard }
    "4" { Invoke-Cleanup }
    "5" { Write-Host "Bye!"; exit 0 }
    default { Write-Host "[ERROR] Invalid choice." -ForegroundColor Red }
}
