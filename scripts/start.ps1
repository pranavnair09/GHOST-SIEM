$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "=== GHOST-SIEM STARTUP ===" -ForegroundColor Red
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python was not found. Install Python 3.10+ and enable 'Add Python to PATH'."
}

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "[1/3] Creating virtual environment..."
    python -m venv .venv
}
Write-Host "[2/3] Installing / verifying dependencies..."
& ".venv\Scripts\python.exe" -m pip install --upgrade pip
& ".venv\Scripts\python.exe" -m pip install -r requirements.txt

Write-Host "[3/3] Starting local services..."
$apiCommand = "Set-Location '$ProjectRoot'; & '.venv\Scripts\python.exe' -m uvicorn app.ingest_server:app --host 127.0.0.1 --port 8765"
$uiCommand = "Set-Location '$ProjectRoot'; & '.venv\Scripts\streamlit.exe' run app\dashboard.py --server.address 127.0.0.1 --server.port 8501"
Start-Process powershell.exe -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $apiCommand
Start-Sleep -Seconds 2
Start-Process powershell.exe -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $uiCommand

Write-Host ""
Write-Host "GHOST-SIEM services launched." -ForegroundColor Green
Write-Host "Dashboard: http://127.0.0.1:8501"
Write-Host "API health: http://127.0.0.1:8765/health"
Write-Host "Now run .\scripts\forwarder.ps1 in an elevated PowerShell window."
