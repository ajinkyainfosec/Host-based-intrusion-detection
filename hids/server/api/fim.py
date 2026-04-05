# server/api/fim.py
# File Integrity Monitoring API
# GET /api/v1/fim/changes   — list FIM changes (from events table)
# GET /api/v1/fim/baseline  — list baseline files

import logging
from fastapi import APIRouter, Request, Query

log    = logging.getLogger("sentinel.api.fim")
router = APIRouter()


@router.get("/changes")
async def list_fim_changes(
    request:  Request,
    limit:    int        = Query(50, ge=1, le=500),
    hostname: str | None = Query(None),
    action:   str | None = Query(None),  # hash_changed, created, deleted, modified
):
    """
    Returns FIM changes by reading file_event rows from the events table.
    Falls back to fim_changes table if populated.
    """

    changes = []

    # ── Try fim_changes table first ───────────────────────────
    try:
        from db.database import AsyncSessionLocal
        from sqlalchemy import text
        if AsyncSessionLocal:
            async with AsyncSessionLocal() as session:
                filters = []
                params  = {"limit": limit}
                if hostname:
                    filters.append(
                        "fc.agent_id = (SELECT agent_id FROM agents "
                        "WHERE hostname = :hostname LIMIT 1)"
                    )
                    params["hostname"] = hostname
                if action:
                    filters.append("fc.action = :action")
                    params["action"] = action.lower()

                where = ("WHERE " + " AND ".join(filters)) if filters else ""

                # JOIN agents so we get the hostname alongside the change
                rows = await session.execute(text(f"""
                    SELECT fc.agent_id,
                           COALESCE(a.hostname, fc.agent_id) AS hostname,
                           fc.path,
                           fc.action,
                           fc.old_hash,
                           fc.new_hash,
                           fc.created_at
                    FROM fim_changes fc
                    LEFT JOIN agents a ON a.agent_id = fc.agent_id
                    {where}
                    ORDER BY fc.created_at DESC
                    LIMIT :limit
                """), params)
                cols = list(rows.keys())
                changes = [dict(zip(cols, row)) for row in rows.fetchall()]
    except Exception as e:
        log.debug(f"fim_changes table query failed: {e}")

    # ── Fall back to file_event rows in events table ──────────
    if not changes:
        try:
            from db.store import load_events
            events = await load_events(
                limit      = limit,
                event_type = "file_event",
                hostname   = hostname,
            )
            for e in events:
                ed = e.get("event_data") or {}
                # Handle both dict and raw JSON string
                if isinstance(ed, str):
                    import json
                    try:
                        ed = json.loads(ed)
                    except Exception:
                        ed = {}

                act = ed.get("action", "unknown")
                if action and act.lower() != action.lower():
                    continue

                changes.append({
                    "agent_id":   e.get("agent_id", ""),
                    "hostname":   e.get("hostname", ""),
                    "path":       ed.get("path", "—"),
                    "action":     act,
                    "new_hash":   ed.get("sha256", ""),
                    "old_hash":   "",
                    "severity":   e.get("severity", "INFO"),
                    "timestamp":  str(e.get("timestamp", "")),
                    "created_at": str(e.get("timestamp", "")),
                    # Extra fields for dashboard display
                    "uid":        ed.get("uid", 0),
                    "gid":        ed.get("gid", 0),
                    "mode":       ed.get("mode", 0),
                    "size":       ed.get("size", 0),
                })
        except Exception as e:
            log.warning(f"load_events for FIM failed: {e}")

    # ── Also check alerts for FIM-related detections ──────────
    try:
        from db.store import load_alerts
        fim_alerts = await load_alerts(limit=limit)
        fim_alerts = [
            a for a in fim_alerts
            if (a.get("rule_id", "").upper().find("FIM") >= 0
                or (a.get("event_data") or {}).get("path")
                or a.get("event_subtype") == "file_event")
        ]
        # Merge alert-based FIM entries not already in changes
        existing_paths = {c.get("path") for c in changes}
        for a in fim_alerts:
            ed   = a.get("event_data") or {}
            path = ed.get("path") or a.get("reason", "")
            if path and path not in existing_paths:
                changes.append({
                    "agent_id":   a.get("agent_id", ""),
                    "hostname":   a.get("hostname", ""),
                    "path":       path,
                    "action":     ed.get("action", "hash_changed"),
                    "new_hash":   ed.get("sha256", ""),
                    "old_hash":   "",
                    "severity":   a.get("severity", "HIGH"),
                    "timestamp":  str(a.get("timestamp", "")),
                    "created_at": str(a.get("created_at") or a.get("timestamp", "")),
                    "rule_title": a.get("rule_title", ""),
                })
                existing_paths.add(path)
    except Exception as e:
        log.debug(f"FIM alert merge failed: {e}")

    # Sort newest first
    changes.sort(
        key=lambda c: str(c.get("created_at") or c.get("timestamp") or ""),
        reverse=True
    )

    return {
        "changes": changes[:limit],
        "total":   len(changes),
    }


@router.get("/baseline")
async def list_fim_baseline(
    request:  Request,
    limit:    int        = Query(100, ge=1, le=1000),
    hostname: str | None = Query(None),
):
    """Returns the FIM baseline — known-good file hashes."""
    try:
        from db.database import AsyncSessionLocal
        from sqlalchemy import text
        if not AsyncSessionLocal:
            return {"baseline": [], "total": 0}

        async with AsyncSessionLocal() as session:
            params = {"limit": limit}
            where  = ""
            if hostname:
                where = (
                    "WHERE fb.agent_id = "
                    "(SELECT agent_id FROM agents WHERE hostname = :hostname LIMIT 1)"
                )
                params["hostname"] = hostname

            rows = await session.execute(text(f"""
                SELECT fb.agent_id,
                       COALESCE(a.hostname, fb.agent_id) AS hostname,
                       fb.path,
                       fb.hash,
                       fb.created_at
                FROM fim_baseline fb
                LEFT JOIN agents a ON a.agent_id = fb.agent_id
                {where}
                ORDER BY fb.created_at DESC
                LIMIT :limit
            """), params)
            cols     = list(rows.keys())
            baseline = [dict(zip(cols, row)) for row in rows.fetchall()]

        return {"baseline": baseline, "total": len(baseline)}

    except Exception as e:
        log.warning(f"list_fim_baseline failed: {e}")
        return {"baseline": [], "total": 0}
