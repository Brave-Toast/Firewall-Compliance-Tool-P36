Write-Host "=============================================" -ForegroundColor Red
Write-Host "   NGFW Suricata Simulation Teardown         " -ForegroundColor Red
Write-Host "=============================================" -ForegroundColor Red

Write-Host "Tearing down containerized environment and custom networks..." -ForegroundColor Yellow
docker compose down

Write-Host "Success! Teardown completed cleanly." -ForegroundColor Green
