# server/api/events.py
# Events ingest + query API — fully PostgreSQL backed
# POST /api/v1/events        — agent batch ingest (saves to DB)
# GET  /api/v1/events        — query events (reads from DB)
# GET  /api/v1/events/stats  — processing statistics

import logging
import os
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request, Query, status

log    = logging.getLogger("sentinel.api.events")
router = APIRouter()

API_KEY = os.getenv("API_KEY", "changeme")

# In-memory ring buffer — keeps last 5000 events for fast access
EVENT_STORE: list[dict] = []
MAX_EVENTS = 5000


def _auth(request: Request):
    """
    Validate Bearer token on ingest requests.
    Accepts: raw API key OR a valid session token from auth module.
    FIXED: previously only checked presence of token, not validity.
    """
    auth = request.headers.get("Authorization", "")
    key  = auth.replace("Bearer ", "").strip()

    if not key:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    # Accept raw API key
    if key == API_KEY:
        return

    # Accept valid session tokens
    try:
        from api.auth import VALID_TOKENS
        if key in VALID_TOKENS:
            return
    except Exception:
        pass

    raise HTTPException(status_code=401, detail="Invalid API key or token")


def _normalize_event(e: dict) -> dict:
    """
    Normalize event fields so DB storage and detection engine
    always receive consistent structure regardless of agent version.

    Agent v1.0+ sends:
      {
        "event_id":   "uuid",
        "agent_id":   "uuid",
        "hostname":   "ubuntu",
        "event_type": "file_event",        ← top level
        "severity":   "HIGH",
        "timestamp":  "2026-...",
        "event_data": {                    ← top level
          "type":   "file_event",
          "path":   "/etc/hosts",
          "action": "hash_changed",
          ...
        }
      }
    """
    import json

    # ── Extract event_data ────────────────────────────────────
    event_data = e.get("event_data", {})
    if isinstance(event_data, str):
        try:
            event_data = json.loads(event_data)
        except Exception:
            event_data = {}

    # Fallback to old "data" key
    if not event_data:
        event_data = e.get("data", {})

    # ── Extract event_type ────────────────────────────────────
    event_type = (
        e.get("event_type", "")
        or event_data.get("type", "")
        or e.get("data", {}).get("type", "")
    )

    # ── Ensure all required fields present ───────────────────
    now = datetime.now(timezone.utc).isoformat()

    e["event_id"]   = e.get("event_id") or e.get("id") or ""
    e["event_type"] = event_type
    e["event_data"] = event_data
    e["hostname"]   = e.get("hostname", "unknown")
    e["agent_id"]   = e.get("agent_id", "")
    e["severity"]   = (e.get("severity", "INFO") or "INFO").upper()
    e["timestamp"]  = e.get("timestamp") or now
    e["received_at"]= e.get("received_at", now)

    # Keep backward compat — also set old "data" key
    # so any code still using event.get("data") still works
    if not e.get("data"):
        e["data"] = event_data

    return e


async def _db_save_events(events: list[dict]) -> None:
    """Save normalized events to PostgreSQL."""
    try:
        from db.store import save_event
        for e in events:
            await save_event(e)
    except Exception as ex:
        log.warning(f"_db_save_events failed: {ex}")


async def _db_load_events(
    limit=200, event_type=None,
    hostname=None, offset=0
) -> list[dict]:
    """Load events from PostgreSQL."""
    try:
        from db.store import load_events
        return await load_events(
            limit      = limit + offset,
            event_type = event_type,
            hostname   = hostname,
        )
    except Exception as ex:
        log.warning(f"_db_load_events failed: {ex}")
        return []


def _sync_alert_store(request: Request):
    """Sync GENERATED_ALERTS into app.state.alert_store."""
    from ingest.processor import GENERATED_ALERTS
    if not hasattr(request.app.state, "alert_store"):
        request.app.state.alert_store = {}
    for a in GENERATED_ALERTS:
        aid = a.get("alert_id") or a.get("id")
        if aid and aid not in request.app.state.alert_store:
            request.app.state.alert_store[aid] = a


# ── INGEST ────────────────────────────────────────────────────
@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def ingest_events(request: Request):
    _auth(request)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Accept bare array, {"events":[...]} wrapper, or single object
    if   isinstance(body, list):                       events = body
    elif isinstance(body, dict) and "events" in body:  events = body["events"]
    elif isinstance(body, dict):                       events = [body]
    else:                                              events = []

    if not events:
        return {"accepted": 0}

    # ── Normalize all events ──────────────────────────────────
    # This ensures event_type and event_data are always set correctly
    # before saving to DB and passing to detection engine
    events = [_normalize_event(e) for e in events]

    # ── Save to PostgreSQL ────────────────────────────────────
    await _db_save_events(events)

    # ── Keep in-memory ring buffer for fast recent access ─────
    global EVENT_STORE
    EVENT_STORE.extend(events)
    if len(EVENT_STORE) > MAX_EVENTS:
        EVENT_STORE = EVENT_STORE[-MAX_EVENTS:]

    # ── Enqueue for detection processing ─────────────────────
    try:
        processor = request.app.state.event_processor
        await processor.enqueue(events)
    except Exception as e:
        log.warning(f"Processor enqueue failed: {e}")

    # ── Sync alerts to app state ──────────────────────────────
    _sync_alert_store(request)

    log.debug(f"Accepted {len(events)} events → saved to DB + queued for detection")
    return {"accepted": len(events)}


# ── QUERY ─────────────────────────────────────────────────────
@router.get("")
async def list_events(
    request:    Request,
    hostname:   str | None = Query(None),
    severity:   str | None = Query(None),
    event_type: str | None = Query(None),
    limit:      int        = Query(100, ge=1, le=1000),
    offset:     int        = Query(0,   ge=0),
):
    # Load from PostgreSQL
    db_events = await _db_load_events(
        limit      = limit + offset + 200,
        event_type = event_type,
        hostname   = hostname,
    )

    # Merge with in-memory (catches very recent events not yet in DB)
    seen_ids  = {e.get("event_id") for e in db_events if e.get("event_id")}
    mem_extra = [
        e for e in reversed(EVENT_STORE)
        if e.get("event_id") not in seen_ids
    ]
    events = db_events + mem_extra

    # Apply filters
    if hostname:
        events = [e for e in events if e.get("hostname") == hostname]

    if severity:
        events = [e for e in events
                  if e.get("severity", "").upper() == severity.upper()]

    if event_type:
        # FIXED: check both event_type (top level) AND event_data.type
        # previously only checked old "data" key which was always empty
        events = [
            e for e in events
            if e.get("event_type") == event_type
            or (e.get("event_data") or {}).get("type") == event_type
            or (e.get("data") or {}).get("type") == event_type
        ]

    # Sort newest first
    events.sort(
        key=lambda e: str(e.get("timestamp") or e.get("received_at") or ""),
        reverse=True
    )

    total = len(events)
    return {
        "events": events[offset:offset + limit],
        "total":  total,
        "limit":  limit,
        "offset": offset,
    }


# ── STATS ─────────────────────────────────────────────────────
@router.get("/stats")
async def event_stats(request: Request):
    try:
        processor  = request.app.state.event_processor
        proc_stats = processor.get_stats()
    except Exception:
        proc_stats = {
            "processed": len(EVENT_STORE),
            "alerts":    0,
            "errors":    0,
        }

    try:
        from ingest.processor import manager
        proc_stats["ws_clients"] = len(manager.active)
    except Exception:
        proc_stats["ws_clients"] = 0

    proc_stats["queue_depth"] = len(EVENT_STORE)

    # Event type breakdown from in-memory store
    type_counts: dict[str, int] = {}
    for e in EVENT_STORE:
        et = e.get("event_type") or (e.get("event_data") or {}).get("type") or "unknown"
        type_counts[et] = type_counts.get(et, 0) + 1
    proc_stats["event_types"] = type_counts

    # Alert count from DB
    try:
        from db.store import load_alerts
        all_alerts = await load_alerts(limit=5000)
        proc_stats["alert_count"] = len(all_alerts)
        proc_stats["alerts"]      = len(all_alerts)

        # Severity breakdown
        proc_stats["alert_severity"] = {
            "critical": sum(1 for a in all_alerts if a.get("severity","").upper() == "CRITICAL"),
            "high":     sum(1 for a in all_alerts if a.get("severity","").upper() == "HIGH"),
            "medium":   sum(1 for a in all_alerts if a.get("severity","").upper() == "MEDIUM"),
            "low":      sum(1 for a in all_alerts if a.get("severity","").upper() == "LOW"),
        }
    except Exception:
        try:
            alert_store = getattr(request.app.state, "alert_store", {})
            proc_stats["alert_count"] = len(alert_store)
        except Exception:
            pass

    return proc_stats
