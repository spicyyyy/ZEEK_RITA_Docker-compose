# ================================================================
#   ZEEK + RITA  |  Threat Detection Script (PowerShell)
#   Run: powershell -ExecutionPolicy Bypass -File .\analyze.ps1
#   Requirements: Docker Desktop running
# ================================================================

function Show-Banner {
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "    ZEEK + RITA  |  Network Beacon Hunter      " -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Docker {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Docker is not running. Start Docker Desktop first." -ForegroundColor Red
        exit 1
    }
}

function Start-Database {
    Write-Host "[*] Starting ClickHouse database..." -ForegroundColor Yellow
    docker compose up -d clickhouse
    Write-Host "[*] Waiting for ClickHouse to be healthy..." -ForegroundColor Yellow
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        $status = docker inspect --format "{{.State.Health.Status}}" clickhouse 2>&1
        if ($status -eq "healthy") { $ready = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) {
        Write-Host "[ERROR] ClickHouse did not become healthy in time." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Database ready." -ForegroundColor Green
}

function Start-Dashboard {
    Write-Host "[*] Ensuring ClickHouse is running..." -ForegroundColor Yellow
    docker compose up -d clickhouse
}

# ----------------------------------------------------------------
# HTML REPORT GENERATION
# ----------------------------------------------------------------
function Export-HtmlReport {
    param([string]$DatasetName, [string]$HtmlFile, [string]$PcapName = "")

    Write-Host "[*] Generating HTML report..." -ForegroundColor Cyan

    function Fmt-Bytes([double]$b) {
        if ($b -ge 1073741824) { return "{0:N1} GB" -f ($b / 1073741824) }
        if ($b -ge 1048576)    { return "{0:N1} MB" -f ($b / 1048576) }
        if ($b -ge 1024)       { return "{0:N1} KB" -f ($b / 1024) }
        return "$([int]$b) B"
    }

    function Fmt-Dur([double]$s) {
        if ($s -le 0)   { return "&mdash;" }
        if ($s -ge 3600){ return "{0:N1}h" -f ($s / 3600) }
        if ($s -ge 60)  { return "{0:N1}m" -f ($s / 60) }
        return "{0:N0}s" -f $s
    }

    function Score-Badge([double]$score) {
        $pct = [int]($score * 100)
        if ($score -ge 0.7) { return "<span class='badge bg-danger'>$pct%</span>" }
        if ($score -ge 0.4) { return "<span class='badge bg-warning text-dark'>$pct%</span>" }
        if ($score -gt 0)   { return "<span class='badge bg-info text-dark'>$pct%</span>" }
        return "<span class='badge bg-secondary'>$pct%</span>"
    }

    function Invoke-CH([string]$q) {
        $r = Invoke-WebRequest -Uri "http://localhost:8123/" -Method POST -Body $q -UseBasicParsing
        return ($r.Content | ConvertFrom-Json)
    }

    # --- Queries ---
    $statsResult = Invoke-CH "SELECT count() as total, countIf(beacon_threat_score > 0) as beaconing, countIf(threat_intel = true) as ti_hits, countIf(long_conn_score > 0) as long_conn, countIf(strobe_score > 0) as strobes, countIf(c2_over_dns_score > 0) as c2_dns FROM ${DatasetName}.threat_mixtape FORMAT JSON"
    $s = $statsResult.data[0]

    $allResult = Invoke-CH "SELECT beacon_threat_score, beacon_score, src, dst, fqdn, count, port_proto_service, beacon_type, long_conn_score, strobe_score, c2_over_dns_score, threat_intel, total_bytes, total_duration, last_seen, ts_score, ds_score, dur_score, hist_score FROM ${DatasetName}.threat_mixtape ORDER BY beacon_threat_score DESC FORMAT JSON"

    # --- Build main table rows ---
    $tableRows = ""
    foreach ($r in $allResult.data) {
        $score = [double]$r.beacon_threat_score
        $rowCls = if ($score -ge 0.7) { "table-danger" } elseif ($score -ge 0.4) { "table-warning" } elseif ($score -gt 0) { "table-info" } else { "" }

        $target = if ($r.fqdn -and "$($r.fqdn)" -ne "") { [System.Net.WebUtility]::HtmlEncode("$($r.fqdn)") }
                  elseif ($r.dst -and "$($r.dst)" -ne "::" -and "$($r.dst)" -ne "") { "$($r.dst)" }
                  else { "$($r.src)" }

        $ports = if ($r.port_proto_service -is [System.Array]) { ($r.port_proto_service -join ", ") }
                 else { "$($r.port_proto_service)".TrimStart('[').TrimEnd(']').Replace("'", "") }

        $tiBadge   = if ($r.threat_intel -eq $true -or "$($r.threat_intel)" -eq "true") { "<span class='badge bg-danger'>&#9888; HIT</span>" } else { "<span class='text-muted'>&mdash;</span>" }
        $longBadge = if ([double]$r.long_conn_score -gt 0) { "<span class='badge bg-warning text-dark'>Yes</span>" } else { "&mdash;" }
        $strobeBdg = if ([double]$r.strobe_score -gt 0)    { "<span class='badge bg-warning text-dark'>Yes</span>" } else { "&mdash;" }
        $c2Badge   = if ([double]$r.c2_over_dns_score -gt 0) { "<span class='badge bg-danger'>Yes</span>" } else { "&mdash;" }

        $tableRows += "            <tr class='$rowCls'>
                <td>$(Score-Badge $score)</td>
                <td class='font-monospace small'>$($r.src)</td>
                <td class='font-monospace small'>$target</td>
                <td class='small text-muted'>$ports</td>
                <td><span class='badge bg-secondary'>$($r.beacon_type)</span></td>
                <td>$($r.count)</td>
                <td>$(Fmt-Bytes([double]$r.total_bytes))</td>
                <td>$(Fmt-Dur([double]$r.total_duration))</td>
                <td>$longBadge</td>
                <td>$strobeBdg</td>
                <td>$c2Badge</td>
                <td>$tiBadge</td>
                <td class='small text-muted'>$($r.last_seen)</td>
            </tr>`n"
    }

    # --- Build score breakdown rows ---
    $scoreRows = ""
    foreach ($r in $allResult.data | Where-Object { [double]$_.beacon_score -gt 0 }) {
        $target = if ($r.fqdn -and "$($r.fqdn)" -ne "") { "$($r.fqdn)" } else { "$($r.dst)" }
        $scoreRows += "            <tr>
                <td class='font-monospace small'>$($r.src)</td>
                <td class='font-monospace small'>$target</td>
                <td>$(Score-Badge([double]$r.beacon_score))</td>
                <td>$([int]([double]$r.ts_score * 100))%</td>
                <td>$([int]([double]$r.ds_score * 100))%</td>
                <td>$([int]([double]$r.dur_score * 100))%</td>
                <td>$([int]([double]$r.hist_score * 100))%</td>
            </tr>`n"
    }

    # --- Pre-compute stat card colors ---
    $beaconingColor = if ([int]$s.beaconing -gt 0) { "text-warning" } else { "text-success" }
    $tiColor        = if ([int]$s.ti_hits -gt 0)   { "text-danger"  } else { "text-success" }
    $longConnColor  = if ([int]$s.long_conn -gt 0)  { "text-warning" } else { "text-success" }
    $strobesColor   = if ([int]$s.strobes -gt 0)    { "text-warning" } else { "text-success" }
    $c2dnsColor     = if ([int]$s.c2_dns -gt 0)     { "text-danger"  } else { "text-success" }
    $pcapInfo       = if ($PcapName) { "<span class='text-muted'>PCAP:</span> <code>$PcapName</code> &nbsp;|&nbsp;" } else { "" }
    $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $html = @"
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RITA Report — $DatasetName</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="https://cdn.datatables.net/2.0.2/css/dataTables.bootstrap5.min.css">
  <style>
    body { background:#0d1117; color:#c9d1d9; }
    .topbar { background:#161b22; border-bottom:1px solid #30363d; padding:1rem 1.5rem; display:flex; align-items:center; gap:1rem; }
    .topbar-brand { font-family:monospace; font-size:1.15rem; font-weight:700; color:#58a6ff; letter-spacing:.05em; }
    .stat-card { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:1.1rem 1rem; text-align:center; }
    .stat-val  { font-size:2rem; font-weight:700; line-height:1.1; }
    .stat-lbl  { font-size:.68rem; text-transform:uppercase; letter-spacing:.09em; color:#8b949e; margin-top:4px; }
    .section-card { background:#161b22; border:1px solid #30363d; border-radius:8px; }
    table.dataTable { color:#c9d1d9 !important; }
    table.dataTable thead th { background:#21262d !important; color:#8b949e !important; font-size:.74rem; text-transform:uppercase; letter-spacing:.06em; border-color:#30363d !important; }
    table.dataTable tbody td { border-color:#21262d !important; vertical-align:middle; font-size:.84rem; }
    table.dataTable tbody tr:hover td { background:rgba(255,255,255,.04) !important; }
    tr.table-danger  td { background:rgba(248,81,73,.13) !important; }
    tr.table-warning td { background:rgba(227,179,65,.11) !important; }
    tr.table-info    td { background:rgba(88,166,255,.09) !important; }
    .dataTables_wrapper .dataTables_filter input,
    .dataTables_wrapper .dataTables_length select { background:#21262d; border:1px solid #30363d; color:#c9d1d9; border-radius:6px; padding:4px 10px; }
    .dataTables_wrapper .dataTables_info { color:#8b949e; font-size:.8rem; }
    .dataTables_wrapper .dataTables_paginate .paginate_button { color:#8b949e !important; }
    .dataTables_wrapper .dataTables_paginate .paginate_button.current { background:#1f6feb !important; color:#fff !important; border-color:#1f6feb !important; border-radius:6px; }
    .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:4px; }
    code { color:#79c0ff; }
    footer { border-top:1px solid #30363d; color:#8b949e; font-size:.8rem; }
  </style>
</head>
<body>

  <div class="topbar mb-4">
    <span class="topbar-brand">&#128270; ZEEK + RITA</span>
    <span class="text-muted">|</span>
    <span class="text-light">$DatasetName</span>
    <span class="ms-auto small text-muted">${pcapInfo}Generated: <code>$now</code></span>
  </div>

  <div class="container-fluid px-4">

    <!-- Summary Cards -->
    <div class="row g-3 mb-4">
      <div class="col-6 col-md-2">
        <div class="stat-card">
          <div class="stat-val text-info">$($s.total)</div>
          <div class="stat-lbl">Analyzed</div>
        </div>
      </div>
      <div class="col-6 col-md-2">
        <div class="stat-card">
          <div class="stat-val $beaconingColor">$($s.beaconing)</div>
          <div class="stat-lbl">Beaconing</div>
        </div>
      </div>
      <div class="col-6 col-md-2">
        <div class="stat-card">
          <div class="stat-val $tiColor">$($s.ti_hits)</div>
          <div class="stat-lbl">Threat Intel Hits</div>
        </div>
      </div>
      <div class="col-6 col-md-2">
        <div class="stat-card">
          <div class="stat-val $longConnColor">$($s.long_conn)</div>
          <div class="stat-lbl">Long Connections</div>
        </div>
      </div>
      <div class="col-6 col-md-2">
        <div class="stat-card">
          <div class="stat-val $strobesColor">$($s.strobes)</div>
          <div class="stat-lbl">Strobes</div>
        </div>
      </div>
      <div class="col-6 col-md-2">
        <div class="stat-card">
          <div class="stat-val $c2dnsColor">$($s.c2_dns)</div>
          <div class="stat-lbl">C2 over DNS</div>
        </div>
      </div>
    </div>

    <!-- Beacon Analysis Table -->
    <div class="section-card p-3 mb-4">
      <div class="d-flex align-items-center flex-wrap gap-3 mb-3">
        <h5 class="text-info mb-0">&#127919; Beacon Analysis</h5>
        <span class="small text-muted"><span class="dot bg-danger"></span>High &ge;70%</span>
        <span class="small text-muted"><span class="dot bg-warning"></span>Medium &ge;40%</span>
        <span class="small text-muted"><span class="dot bg-info"></span>Low &gt;0%</span>
      </div>
      <div class="table-responsive">
        <table id="mainTable" class="table table-sm table-hover w-100">
          <thead>
            <tr>
              <th>Threat Score</th><th>Source</th><th>Destination / FQDN</th>
              <th>Port / Service</th><th>Type</th><th>Conns</th>
              <th>Bytes</th><th>Duration</th><th>Long Conn</th>
              <th>Strobe</th><th>C2/DNS</th><th>Threat Intel</th><th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
$tableRows          </tbody>
        </table>
      </div>
    </div>

    <!-- Score Breakdown Table -->
    <div class="section-card p-3 mb-4">
      <h5 class="text-info mb-1">&#128202; Beacon Score Breakdown</h5>
      <p class="small text-muted mb-3">Component weights: Timestamp consistency, Data size regularity, Session duration, Traffic histogram shape.</p>
      <div class="table-responsive">
        <table id="scoreTable" class="table table-sm table-hover w-100">
          <thead>
            <tr>
              <th>Source</th><th>Destination / FQDN</th><th>Beacon Score</th>
              <th>Timestamp</th><th>Data Size</th><th>Duration</th><th>Histogram</th>
            </tr>
          </thead>
          <tbody>
$scoreRows          </tbody>
        </table>
      </div>
    </div>

  </div>

  <footer class="text-center py-3 mt-2">
    ZEEK + RITA &mdash; Dataset: $DatasetName &mdash; $now
  </footer>

  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
  <script src="https://cdn.datatables.net/2.0.2/js/dataTables.min.js"></script>
  <script src="https://cdn.datatables.net/2.0.2/js/dataTables.bootstrap5.min.js"></script>
  <script>
    `$('#mainTable').DataTable({ pageLength: 25, order: [[0, 'desc']] });
    `$('#scoreTable').DataTable({ pageLength: 25, order: [[2, 'desc']] });
  </script>
</body>
</html>
"@

    $html | Out-File -FilePath $HtmlFile -Encoding utf8
    Write-Host "[+] HTML report -> $HtmlFile" -ForegroundColor Green
}

# ----------------------------------------------------------------

function Invoke-PcapMode {
    Write-Host ""
    Write-Host "--- PCAP MODE ---" -ForegroundColor Cyan
    Write-Host ""

    $pcapFiles = @(Get-ChildItem -Path ".\pcaps\" -File | Where-Object { $_.Extension -eq ".pcap" -or $_.Extension -eq ".pcapng" })
    if ($pcapFiles.Count -eq 0) {
        Write-Host "[ERROR] No .pcap files found in .\pcaps\" -ForegroundColor Red
        Write-Host "  Copy your PCAP into the .\pcaps\ folder then re-run."
        return
    }

    Write-Host "Available PCAP files:"
    for ($i = 0; $i -lt $pcapFiles.Count; $i++) {
        Write-Host "  [$i] $($pcapFiles[$i].Name)"
    }

    Write-Host ""
    $selection = Read-Host "Enter the number of the PCAP to analyze"
    if ($selection -notmatch "^\d+$" -or [int]$selection -ge $pcapFiles.Count) {
        Write-Host "[ERROR] Invalid selection." -ForegroundColor Red
        return
    }
    $pcapName = $pcapFiles[[int]$selection].Name
    Write-Host "Selected: $pcapName" -ForegroundColor Green

    # Auto-generate dataset name from PCAP filename + timestamp
    $baseName  = [System.IO.Path]::GetFileNameWithoutExtension($pcapName)
    $sanitized = ($baseName -replace '[^a-zA-Z0-9]', '_').ToLower() -replace '_+', '_'
    $sanitized = $sanitized.Trim('_')
    if ($sanitized -match '^\d') { $sanitized = "pcap_$sanitized" }
    if ($sanitized.Length -gt 24) { $sanitized = $sanitized.Substring(0, 24).TrimEnd('_') }
    $datasetName = $sanitized + "_" + (Get-Date -Format "yyyyMMdd_HHmmss")
    Write-Host "Dataset name: $datasetName" -ForegroundColor Cyan

    Write-Host ""
    Write-Host "[1/4] Running Zeek on $pcapName ..." -ForegroundColor Yellow
    Remove-Item ".\zeek-logs\*.log" -ErrorAction SilentlyContinue
    Remove-Item ".\zeek-logs\*.gz"  -ErrorAction SilentlyContinue
    docker compose run --rm zeek -C -r /pcaps/$pcapName local
    Write-Host "[+] Zeek logs written to .\zeek-logs\" -ForegroundColor Green

    Write-Host ""
    Write-Host "[2/4] Importing logs into RITA ..." -ForegroundColor Yellow
    docker compose run --rm rita import --database $datasetName --logs /zeek-logs
    Write-Host "[+] Import complete. Dataset: $datasetName" -ForegroundColor Green

    Write-Host ""
    Write-Host "[3/4] Exporting CSV ..." -ForegroundColor Yellow
    $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvFile    = ".\results\${datasetName}_beacons_${timestamp}.csv"
    $csvQuery   = "SELECT beacon_threat_score, beacon_score, src, dst, fqdn, count, port_proto_service, beacon_type, long_conn_score, strobe_score, c2_over_dns_score, threat_intel, total_bytes, total_duration, last_seen FROM ${datasetName}.threat_mixtape ORDER BY beacon_threat_score DESC FORMAT CSVWithNames"
    (Invoke-WebRequest -Uri "http://localhost:8123/" -Method POST -Body $csvQuery -UseBasicParsing).Content | Out-File -FilePath $csvFile -Encoding utf8
    Write-Host "[+] CSV -> $csvFile" -ForegroundColor Green

    Write-Host ""
    Write-Host "[4/4] Generating HTML report ..." -ForegroundColor Yellow
    $htmlFile = ".\results\${datasetName}_report_${timestamp}.html"
    Export-HtmlReport -DatasetName $datasetName -HtmlFile $htmlFile -PcapName $pcapName

    Write-Host ""
    Write-Host "--- DONE ---" -ForegroundColor Cyan
    Write-Host "  CSV    -> $csvFile"
    Write-Host "  Report -> $htmlFile" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Opening report in browser..." -ForegroundColor Cyan
    Start-Process $htmlFile
}

function Invoke-LiveMode {
    Write-Host ""
    Write-Host "--- LIVE CAPTURE MODE ---" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Note: Live capture requires Docker Desktop with Linux containers." -ForegroundColor Yellow
    Write-Host ""

    Write-Host "Available network interfaces:"
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
        Write-Host "  $($_.Name) - $($_.InterfaceDescription)"
    }

    Write-Host ""
    $iface = Read-Host "Enter the interface name (as shown above)"

    Write-Host ""
    Write-Host "[*] Starting Zeek on $iface - press Ctrl+C to stop." -ForegroundColor Yellow
    docker compose run --rm zeek -i $iface local

    Write-Host "[+] Capture stopped. Logs in .\zeek-logs\" -ForegroundColor Green

    # Auto-generate dataset name from interface + timestamp
    $sanitized = ($iface -replace '[^a-zA-Z0-9]', '_').ToLower() -replace '_+', '_'
    $sanitized  = $sanitized.Trim('_')
    if ($sanitized -match '^\d') { $sanitized = "live_$sanitized" }
    $datasetName = "live_" + $sanitized + "_" + (Get-Date -Format "yyyyMMdd_HHmmss")
    Write-Host "Dataset name: $datasetName" -ForegroundColor Cyan

    docker compose run --rm rita import --database $datasetName --logs /zeek-logs

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvFile   = ".\results\${datasetName}_beacons_${timestamp}.csv"
    $csvQuery  = "SELECT beacon_threat_score, beacon_score, src, dst, fqdn, count, port_proto_service, beacon_type, long_conn_score, strobe_score, c2_over_dns_score, threat_intel, total_bytes, total_duration, last_seen FROM ${datasetName}.threat_mixtape ORDER BY beacon_threat_score DESC FORMAT CSVWithNames"
    (Invoke-WebRequest -Uri "http://localhost:8123/" -Method POST -Body $csvQuery -UseBasicParsing).Content | Out-File -FilePath $csvFile -Encoding utf8

    $htmlFile = ".\results\${datasetName}_report_${timestamp}.html"
    Export-HtmlReport -DatasetName $datasetName -HtmlFile $htmlFile

    Write-Host ""
    Write-Host "--- DONE ---" -ForegroundColor Cyan
    Write-Host "  CSV    -> $csvFile"
    Write-Host "  Report -> $htmlFile" -ForegroundColor Green
    Start-Process $htmlFile
}

function Invoke-Cleanup {
    Write-Host "[*] Stopping all containers and wiping database..." -ForegroundColor Yellow
    docker compose down -v
    Remove-Item ".\zeek-logs\*.log" -ErrorAction SilentlyContinue
    Remove-Item ".\zeek-logs\*.gz"  -ErrorAction SilentlyContinue
    Write-Host "[+] Clean slate. Ready for a fresh run." -ForegroundColor Green
}

# ================================================================
# MAIN
# ================================================================
Show-Banner
Test-Docker
Start-Database

Write-Host "What do you want to do?"
Write-Host "  [1] Analyze a PCAP file"
Write-Host "  [2] Capture live traffic"
Write-Host "  [3] Clean up everything (wipe DB + logs)"
Write-Host "  [4] Exit"
Write-Host ""
$choice = Read-Host "Choice [1-4]"

switch ($choice) {
    "1" { Start-Dashboard; Invoke-PcapMode }
    "2" { Start-Dashboard; Invoke-LiveMode }
    "3" { Invoke-Cleanup }
    "4" { Write-Host "Bye!"; exit 0 }
    default { Write-Host "[ERROR] Invalid choice." -ForegroundColor Red }
}
