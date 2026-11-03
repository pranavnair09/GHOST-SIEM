import argparse
import random
import socket
from datetime import datetime, timezone, timedelta
import requests

API = "http://127.0.0.1:8765/ingest"
HOST = socket.gethostname()

SAMPLES = [
    ("Information", "Microsoft-Windows-Security-Auditing", 4624, "Successful account logon (synthetic demonstration event)."),
    ("Warning", "Microsoft-Windows-Security-Auditing", 4625, "Failed logon attempt (synthetic demonstration event)."),
    ("Information", "Service Control Manager", 7036, "A service entered the running state (synthetic demonstration event)."),
    ("Error", "Application Error", 1000, "Application fault reported (synthetic demonstration event)."),
    ("Critical", "Microsoft-Windows-Kernel-Power", 41, "Unexpected shutdown detected (synthetic demonstration event)."),
    ("Information", "Microsoft-Windows-Windows Defender", 1116, "Antimalware detection example (synthetic demonstration event)."),
]

def main():
    parser = argparse.ArgumentParser(description="Send synthetic events to GHOST-SIEM.")
    parser.add_argument("--count", type=int, default=20)
    args = parser.parse_args()
    if args.count < 1 or args.count > 500:
        raise SystemExit("--count must be between 1 and 500")
    now = datetime.now(timezone.utc)
    events = []
    for i in range(args.count):
        level, provider, event_id, message = random.choice(SAMPLES)
        ts = now - timedelta(seconds=random.randint(0, 3600))
        events.append({
            "timestamp": ts.isoformat(),
            "computer": HOST,
            "channel": random.choice(["Security", "System", "Application"]),
            "provider": provider,
            "event_id": event_id,
            "record_id": 900000 + i,
            "level": level,
            "message": "[DEMO - NOT REAL TELEMETRY] " + message,
            "source": "demo",
            "event_key": f"demo|{HOST}|{now.timestamp()}|{i}"
        })
    try:
        response = requests.post(API, json={"events": events}, timeout=5)
        response.raise_for_status()
        print(response.json())
    except requests.RequestException as exc:
        raise SystemExit(f"Could not reach GHOST-SIEM API at {API}: {exc}")

if __name__ == "__main__":
    main()
