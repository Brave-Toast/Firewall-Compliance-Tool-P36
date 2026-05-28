param (
    [string]$RulesetPath = ""
)

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   NGFW Suricata Simulation Orchestrator     " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# 1. Teardown existing containers
Write-Host "Step 1: Destroying existing simulation containers..." -ForegroundColor Yellow
docker compose down

# 2. Provision new containers
Write-Host "Step 2: Starting new simulation containers..." -ForegroundColor Yellow
docker compose up -d

# Wait for container initialization
Write-Host "Waiting for containers to initialize (5s)..." -ForegroundColor Gray
Start-Sleep -Seconds 5

# 3. Verify containers are running
$containers = docker ps --format "{{.Names}}"
if ($containers -notcontains "ngfw_suricata" -or $containers -notcontains "ext_client" -or $containers -notcontains "web_server") {
    Write-Error "Error: Core containers failed to start. Please check 'docker compose ps'."
    exit 1
}

# 4. Dependency Injection inside Suricata container
Write-Host "Step 3: Installing iptables inside ngfw_suricata container..." -ForegroundColor Yellow
docker exec ngfw_suricata dnf install -y iptables
docker exec ngfw_suricata mkdir -p /var/lib/suricata/rules


# 5. Interception Configuration (NFQUEUE)
Write-Host "Step 4: Injecting inline packet interception (NFQUEUE)..." -ForegroundColor Yellow
docker exec ngfw_suricata iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass

# 6. Bidirectional Routing Injection
Write-Host "Step 5: Injecting static routes for zone boundary simulation..." -ForegroundColor Yellow
# Client route to reach DMZ zone (10.0.50.0/24) via NGFW external IP (10.0.1.5)
docker exec ext_client ip route del 10.0.50.0/24 2>$null
docker exec ext_client ip route add 10.0.50.0/24 via 10.0.1.5

# Web Server route to reach External zone (10.0.1.0/24) via NGFW DMZ IP (10.0.50.5)
docker exec web_server ip route del 10.0.1.0/24 2>$null
docker exec web_server ip route add 10.0.1.0/24 via 10.0.50.5

# 7. Ruleset Injection Pipeline
Write-Host "Step 6: Rule compilation and injection..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "reports" | Out-Null

$activeRulesPath = "reports/active_suricata.rules"

if ($RulesetPath -and (Test-Path $RulesetPath)) {
    Write-Host "Compiling premade ruleset: $RulesetPath ..." -ForegroundColor Cyan
    # Use the compliance tool CLI to parse, normalize, Z3-optimize, and translate
    python -m src.main compile --file $RulesetPath --output $activeRulesPath
} else {
    Write-Host "No premade ruleset specified or file not found. Deploying default baseline..." -ForegroundColor Gray
    # Write default baseline rules
    $baselineRules = @(
        'drop icmp any any -> any any (msg:"Block ICMP ping"; sid:1000001; rev:1;)'
        'drop tcp any any -> any 80 (msg:"Block HTTP /admin"; content:"/admin"; http_uri; sid:1000002; rev:1;)'
    )
    ($baselineRules -join "`n") | Out-File -FilePath $activeRulesPath -Encoding utf8 -NoNewline
    # Clean up carriage returns to prevent Suricata parsing issues
    $content = Get-Content $activeRulesPath -Raw
    $content = $content -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText($activeRulesPath, $content)
}

# Copy rules into Suricata container
docker cp $activeRulesPath ngfw_suricata:/var/lib/suricata/rules/suricata.rules
docker cp $activeRulesPath ngfw_suricata:/etc/suricata/suricata.rules

# 8. Hot Reload Suricata rules
Write-Host "Step 7: Hot reloading Suricata engine ruleset..." -ForegroundColor Yellow
docker exec ngfw_suricata suricatasc -c reload-rules

Write-Host "`n=============================================" -ForegroundColor Green
Write-Host "   Simulation Setup Completed Successfully   " -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "Useful Validation Commands:" -ForegroundColor Cyan
Write-Host "1. Test ICMP Ping (should be blocked by default):" -ForegroundColor Gray
Write-Host "   docker exec ext_client ping -c 3 -W 2 10.0.50.10" -ForegroundColor White
Write-Host "2. Test standard Web HTTP (should succeed):" -ForegroundColor Gray
Write-Host "   docker exec ext_client wget -qO- --timeout=3 http://10.0.50.10/" -ForegroundColor White
Write-Host "3. Test Web HTTP /admin block (should time out/fail):" -ForegroundColor Gray
Write-Host "   docker exec ext_client wget -qO- --timeout=3 http://10.0.50.10/admin" -ForegroundColor White
