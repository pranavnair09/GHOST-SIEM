# GHOST-SIEM
**Mini SIEM & Windows Log Forwarder**  
A local-only educational SIEM built with PowerShell, Python, FastAPI, SQLite and Streamlit.

## What it does
- PowerShell polls Windows Event Log channels (`Security`, `System`, `Application`) and forwards new events as JSON.
- FastAPI validates and ingests batches on `127.0.0.1:8765`.
- SQLite stores normalized events and deduplicates them.
- Streamlit presents a dark charcoal / red-orange SIEM dashboard on `127.0.0.1:8501`.
- Includes a synthetic event generator so the dashboard can be explored before connecting a Windows event source.

## Architecture
`Windows Event Logs -> PowerShell Forwarder -> FastAPI -> SQLite -> Streamlit Dashboard`

Both services bind to loopback only. Do not change the bind addresses to `0.0.0.0` unless you have deliberately redesigned and secured the deployment.

## Requirements
- Windows 10/11 or Windows Server for the PowerShell event forwarder.
- Python 3.10+ (3.11 recommended).
- PowerShell 5.1+.
- Administrator PowerShell is recommended for reading the Security channel. System and Application may be readable without elevation depending on local policy.
- Internet access is needed once to install Python dependencies.

## Quick start (Windows)
1. Extract the ZIP to a folder, for example `C:\GHOST-SIEM`.
2. Open PowerShell in that folder.
3. Run:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\scripts\start.ps1
   ```
   This creates `.venv`, installs dependencies, then starts the ingestion API and dashboard in separate PowerShell windows.
4. Open the dashboard at **http://127.0.0.1:8501**.
5. In a second PowerShell window, preferably run as Administrator:
   ```powershell
   cd C:\GHOST-SIEM
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\scripts\forwarder.ps1
   ```
6. Generate normal Windows activity (logon/logoff, service activity, application launches) and watch events appear. Security-channel visibility depends on audit policy and permissions.

## Explore without Windows event access
With the API and dashboard running, open another PowerShell window:
```powershell
cd C:\GHOST-SIEM
.\.venv\Scripts\python.exe .\scripts\generate_demo_events.py --count 30
```
This inserts clearly labelled synthetic events into the local API. They are not real security telemetry.

## Start services manually
Terminal 1:
```powershell
.\.venv\Scripts\python.exe -m uvicorn app.ingest_server:app --host 127.0.0.1 --port 8765
```
Terminal 2:
```powershell
.\.venv\Scripts\streamlit.exe run app\dashboard.py --server.address 127.0.0.1 --server.port 8501
```

## Stop
Close the two service PowerShell windows with `Ctrl+C`. Stop the forwarder with `Ctrl+C`. The database is stored at `data\ghost_siem.db` and persists between runs.

## Configuration
Edit `config\config.json`:
- `api_url`: local ingestion endpoint.
- `channels`: Windows Event Log channels to poll.
- `poll_interval_seconds`: polling interval.
- `batch_size`: max events sent per request.
- `lookback_minutes_on_start`: initial lookback when the forwarder starts.

The forwarder remembers the highest RecordId per channel during its current run. On restart, it intentionally looks back by the configured interval; database uniqueness prevents duplicate storage.

## API endpoints
- `GET /health` - service and database status.
- `POST /ingest` - accepts `{"events": [...]}`.
- `GET /api/stats` - dashboard summary data.
- `GET /api/events?limit=100` - latest stored events.

## Event fields
`timestamp`, `computer`, `channel`, `provider`, `event_id`, `record_id`, `level`, `message`, `source`, `event_key`.

## Important limitations
- This is a learning project, not a production SIEM or EDR.
- Polling is not guaranteed lossless under all event-volume and downtime conditions.
- Windows Security events depend on audit policy, channel permissions and retention.
- No alert response, threat-intelligence enrichment, multi-host authentication, TLS, RBAC or tamper-resistant storage is implemented.
- Messages may contain usernames, hostnames, IP addresses or other sensitive data. Keep the database local and handle it as security telemetry.
- Only forward logs from systems you own or are explicitly authorized to monitor.

## Troubleshooting
**`Access is denied` reading Security:** launch PowerShell as Administrator and verify the Security log is enabled.

**Dashboard says API offline:** check that the API window is running and visit `http://127.0.0.1:8765/health`.

**No events appear:** run the demo generator first; check `config\config.json`; verify the selected channels exist with `Get-WinEvent -ListLog *`.

**Port already in use:** stop the process using port 8765 or 8501, or update the ports consistently in the config, scripts and README.

## Project structure
```text
GHOST-SIEM/
├── app/
│   ├── __init__.py
│   ├── database.py
│   ├── ingest_server.py
│   └── dashboard.py
├── config/
│   └── config.json
├── scripts/
│   ├── start.ps1
│   ├── forwarder.ps1
│   └── generate_demo_events.py
├── data/
│   └── .gitkeep
├── requirements.txt
└── README.md
```
