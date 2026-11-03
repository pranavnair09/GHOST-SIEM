from datetime import datetime, timezone
from typing import Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from app.database import init_db, insert_events, fetch_events, fetch_stats

app = FastAPI(title="GHOST-SIEM Ingestion API", version="1.0.0")

class Event(BaseModel):
    timestamp: str | None = None
    computer: str = "unknown"
    channel: str = "unknown"
    provider: str = "unknown"
    event_id: int | None = None
    record_id: int | None = None
    level: str = "Information"
    message: str = ""
    source: str = "windows"
    event_key: str | None = None

class EventBatch(BaseModel):
    events: list[Event] = Field(min_length=1, max_length=500)

@app.on_event("startup")
def startup():
    init_db()

@app.get("/health")
def health():
    try:
        stats = fetch_stats()
        return {"status": "ok", "service": "GHOST-SIEM", "stored_events": stats["total"]}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc))

@app.post("/ingest")
def ingest(batch: EventBatch):
    try:
        normalized = []
        for item in batch.events:
            event = item.model_dump()
            if not event["timestamp"]:
                event["timestamp"] = datetime.now(timezone.utc).isoformat()
            normalized.append(event)
        count = insert_events(normalized)
        return {"status": "accepted", "received": len(normalized), "inserted": count}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {exc}")

@app.get("/api/stats")
def stats():
    return fetch_stats()

@app.get("/api/events")
def events(limit: int = 200):
    if limit < 1 or limit > 5000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 5000")
    return {"events": fetch_events(limit)}
