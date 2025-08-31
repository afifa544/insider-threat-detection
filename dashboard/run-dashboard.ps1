Write-Host "Setting up Insider Threat Dashboard" -ForegroundColor Green
Write-Host ""

Write-Host "Checking for data files..." -ForegroundColor Yellow
python create_json.py

Write-Host ""
Write-Host "Starting Dashboard..." -ForegroundColor Green
Write-Host "Please wait while the dashboard loads..."

Start-Sleep -Seconds 2

streamlit run dashboard/lightweight_app.py