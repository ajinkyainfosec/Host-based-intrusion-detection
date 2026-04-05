# server/api/alerts.py
# Complete Alerts API — reads from PostgreSQL, falls back to in-memory
# GET    /api/v1/alerts          — list with filters
# GET    /api/v1/alerts/stats    — counts for metric cards
# GET    /api/v1/alerts/{id}     — single alert
# PATCH  /api/v1/alerts/{id}/acknowledge
# PATCH  /api/v1/alerts/{id}/investigating
# PATCH  /api/v1/alerts/{id}/contained
# PATCH  /api/v1/alerts/{id}/close
# POST   /api/v1/alerts/{id}/assign

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request, Query

log    = logging.getLogger("sentinel.api.alerts")
router = APIRouter()

# In-memory store — fallback when DB unavailable
ALERT_STORE: dict[str, dict] = {}

def store(req: Request) -> dict:
    return getattr(req.app.state, "alert_store", ALERT_STORE)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def analyst(req: Request) -> str:
    return req.headers.get("Authorization", "").replace("Bearer ", "").strip()[:20] or "analyst"


def _normalize_alert(a: dict) -> dict:
    """
    Normalize alert fields so dashboard always gets consistent data
    regardless of whether alert came from DB or in-memory.
    """
    # Ensure event_data is a dict not a string
    ed = a.get("event_data", {})
    if isinstance(ed, str):
        import json
        try:
            ed = json.loads(ed)
        except Exception:
            ed = {}
    a["event_data"] = ed

    # Ensure event_subtype is set
    if not a.get("event_subtype"):
        a["event_subtype"] = ed.get("type", "") or a.get("event_type", "")

    # Normalize timestamp → always use created_at as timestamp for dashboard
    if not a.get("timestamp"):
        a["timestamp"] = str(a.get("created_at", now_iso()))

    # Ensure severity is uppercase
    if a.get("severity"):
        a["severity"] = a["severity"].upper()

    # Ensure status has a default
    if not a.get("status"):
        a["status"] = "new"

    # Ensure tags is always a list
    if not isinstance(a.get("tags"), list):
        a["tags"] = []

    return a


async def _load_from_db(
    severity=None, status=None, hostname=None,
    limit=500, offset=0, alert_id=None
) -> list[dict]:
    """Load alerts from PostgreSQL."""
    try:
        from db.store import load_alerts
        rows = await load_alerts(
            limit    = limit + offset,
            severity = severity,
            status   = status,
            hostname = hostname,
        )
        # Filter by alert_id if specified
        if alert_id:
            rows = [r for r in rows if r.get("alert_id") == alert_id]
        return rows
    except Exception as e:
        log.warning(f"_load_from_db failed: {e}")
        return []


def _merge(db_alerts: list[dict], mem_store: dict) -> list[dict]:
    """
    Merge PostgreSQL alerts with in-memory alerts.
    DB is primary source. In-memory overrides status fields (most recent).
    """
    merged = {a["alert_id"]: a for a in db_alerts}

    for alert_id, a in mem_store.items():
        if alert_id in merged:
            # Override status fields from memory (latest ACK/close shows immediately)
            for field in ("status", "assigned_to", "acknowledged_at",
                          "acknowledged_by", "closed_at", "closed_by"):
                if a.get(field):
                    merged[alert_id][field] = a[field]
        else:
            # Alert in memory but not yet committed to DB
            merged[alert_id] = a

    return list(merged.values())


# ── LIST ──────────────────────────────────────────────────────
@router.get("")
async def list_alerts(
    request:  Request,
    severity: str | None = Query(None),
    status:   str | None = Query(None),
    hostname: str | None = Query(None),
    tags:     str | None = Query(None),
    mitre_id: str | None = Query(None),
    limit:    int        = Query(100, ge=1, le=500),
    offset:   int        = Query(0,   ge=0),
):
    # Load from PostgreSQL
    db_alerts = await _load_from_db(
        severity = severity,
        status   = status,
        hostname = hostname,
        limit    = limit + offset + 200,
    )

    # Merge with in-memory
    alerts = _merge(db_alerts, store(request))

    # Apply remaining filters
    if severity: alerts = [a for a in alerts if a.get("severity","").upper() == severity.upper()]
    if status:   alerts = [a for a in alerts if a.get("status","").lower()   == status.lower()]
    if hostname: alerts = [a for a in alerts if a.get("hostname","")         == hostname]
    if mitre_id: alerts = [a for a in alerts if a.get("mitre_id","")         == mitre_id]
    if tags:
        tl = [t.strip() for t in tags.split(",")]
        alerts = [a for a in alerts if any(t in (a.get("tags") or []) for t in tl)]

    # Sort newest first
    alerts.sort(
        key=lambda a: str(a.get("timestamp") or a.get("created_at") or ""),
        reverse=True
    )

    # Normalize all alerts before returning
    alerts = [_normalize_alert(a) for a in alerts]

    total = len(alerts)
    return {
        "alerts": alerts[offset:offset + limit],
        "total":  total,
        "limit":  limit,
        "offset": offset,
    }


# ── STATS ─────────────────────────────────────────────────────
@router.get("/stats")
async def alert_stats(request: Request):
    db_alerts = await _load_from_db(limit=2000)
    alerts    = _merge(db_alerts, store(request))
    return {
        "total":         len(alerts),
        "critical":      sum(1 for a in alerts if a.get("severity","").upper() == "CRITICAL"),
        "high":          sum(1 for a in alerts if a.get("severity","").upper() == "HIGH"),
        "medium":        sum(1 for a in alerts if a.get("severity","").upper() == "MEDIUM"),
        "low":           sum(1 for a in alerts if a.get("severity","").upper() == "LOW"),
        "new":           sum(1 for a in alerts if a.get("status","")           == "new"),
        "acknowledged":  sum(1 for a in alerts if a.get("status","")           == "acknowledged"),
        "investigating": sum(1 for a in alerts if a.get("status","")           == "investigating"),
        "contained":     sum(1 for a in alerts if a.get("status","")           == "contained"),
        "closed":        sum(1 for a in alerts if a.get("status","")           == "closed"),
    }


# ── SINGLE ────────────────────────────────────────────────────
@router.get("/{alert_id}")
async def get_alert(alert_id: str, request: Request):
    # ── Check in-memory first (fastest) ──────────────────────
    a = store(request).get(alert_id)
    if a:
        return _normalize_alert(a)

    # ── Search DB with enough rows to find the alert ──────────
    # FIXED: was loading limit=1 which almost never matched
    db_alerts = await _load_from_db(limit=2000, alert_id=alert_id)
    if db_alerts:
        return _normalize_alert(db_alerts[0])

    raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")


# ── STATUS TRANSITIONS ────────────────────────────────────────
async def _set_status(alert_id: str, status: str, request: Request, extra: dict = {}):
    # Update in-memory
    s = store(request)
    a = s.setdefault(alert_id, {"alert_id": alert_id, "status": "new"})
    a.update({"status": status, "updated_at": now_iso(), **extra})

    # Update PostgreSQL
    try:
        from db.store import update_alert_status
        await update_alert_status(alert_id, status, extra or None)
        log.info(f"Alert {alert_id} → {status} (saved to DB)")
    except Exception as e:
        log.warning(f"DB status update failed for {alert_id}: {e}")

    # Broadcast status change to all dashboard clients
    try:
        from ingest.processor import manager
        await manager.broadcast({
            "type": "alert_update",
            "payload": {
                "alert_id": alert_id,
                "status":   status,
                **extra,
            },
        })
    except Exception:
        pass

    return {"alert_id": alert_id, "status": status, **extra}


@router.patch("/{alert_id}/acknowledge")
async def ack(alert_id: str, req: Request):
    return await _set_status(
        alert_id, "acknowledged", req,
        {
            "acknowledged_at": now_iso(),
            "acknowledged_by": analyst(req),
        }
    )

@router.patch("/{alert_id}/investigating")
async def investigating(alert_id: str, req: Request):
    return await _set_status(alert_id, "investigating", req)

@router.patch("/{alert_id}/contained")
async def contained(alert_id: str, req: Request):
    return await _set_status(alert_id, "contained", req)

@router.patch("/{alert_id}/close")
async def close(alert_id: str, req: Request):
    return await _set_status(
        alert_id, "closed", req,
        {
            "closed_at": now_iso(),
            "closed_by": analyst(req),
        }
    )

# ── ASSIGN ────────────────────────────────────────────────────
@router.post("/{alert_id}/assign")
async def assign(alert_id: str, req: Request):
    body = await req.json()
    s    = store(req)

    # Find alert in memory or DB
    a = s.get(alert_id)
    if not a:
        db_alerts = await _load_from_db(limit=2000, alert_id=alert_id)
        if db_alerts:
            a = db_alerts[0]
            s[alert_id] = a
        else:
            raise HTTPException(status_code=404, detail="Alert not found")

    assigned_to      = body.get("analyst", "")
    a["assigned_to"] = assigned_to
    a["updated_at"]  = now_iso()

    # Save to DB
    try:
        from db.store import update_alert_status
        await update_alert_status(
            alert_id,
            a.get("status", "new"),
            {"assigned_to": assigned_to}
        )
        log.info(f"Alert {alert_id} assigned to {assigned_to}")
    except Exception as e:
        log.warning(f"DB assign failed: {e}")

    # Broadcast assignment
    try:
        from ingest.processor import manager
        await manager.broadcast({
            "type": "alert_update",
            "payload": {
                "alert_id":    alert_id,
                "assigned_to": assigned_to,
            },
        })
    except Exception:
        pass

    return {"alert_id": alert_id, "assigned_to": assigned_to}
