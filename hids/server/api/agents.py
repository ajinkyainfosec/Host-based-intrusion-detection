# server/api/agents.py
# Agents API — fully PostgreSQL backed
# GET    /api/v1/agents                  — list all agents (from DB)
# GET    /api/v1/agents/{id}             — single agent
# POST   /api/v1/agents/{id}/heartbeat  — save heartbeat to DB
# PATCH  /api/v1/agents/{id}/status     — update status in DB
# DELETE /api/v1/agents/{id}            — deregister from DB

import logging
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException, Request

log    = logging.getLogger("sentinel.api.agents")
router = APIRouter()

# In-memory fallback registry
AGENT_REGISTRY: dict[str, dict] = {}

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _registry(req: Request) -> dict:
    return getattr(req.app.state, "agent_registry", AGENT_REGISTRY)

def _compute_status(last_seen) -> str:
    """Auto-compute agent status from last heartbeat time."""
    if not last_seen:
        return "offline"
    try:
        if isinstance(last_seen, str):
            last = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        elif isinstance(last_seen, datetime):
            last = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
        else:
            return "offline"
        diff = datetime.now(timezone.utc) - last
        if diff < timedelta(seconds=30):  return "online"
        if diff < timedelta(minutes=2):   return "degraded"
        return "offline"
    except Exception:
        return "unknown"

async def _db_load_agents() -> list[dict]:
    """Load all agents from PostgreSQL."""
    try:
        from db.store import load_agents
        return await load_agents()
    except Exception as e:
        log.warning(f"_db_load_agents failed: {e}")
        return []

async def _db_upsert_agent(agent: dict) -> None:
    """Save/update agent in PostgreSQL."""
    try:
        from db.store import upsert_agent
        await upsert_agent(agent)
    except Exception as e:
        log.warning(f"_db_upsert_agent failed: {e}")

def _merge_agents(db_agents: list[dict], mem_registry: dict) -> list[dict]:
    """Merge DB agents with in-memory registry. Memory wins on status."""
    merged = {a["agent_id"]: a for a in db_agents}
    for agent_id, a in mem_registry.items():
        if agent_id in merged:
            # Override with latest in-memory fields
            merged[agent_id].update({
                "status":    a.get("status",    merged[agent_id].get("status")),
                "last_seen": a.get("last_seen", merged[agent_id].get("last_seen")),
                "cpu_pct":   a.get("cpu_pct",   merged[agent_id].get("cpu_pct", 0)),
                "mem_pct":   a.get("mem_pct",   merged[agent_id].get("mem_pct", 0)),
            })
        else:
            merged[agent_id] = a
    return list(merged.values())

# ── LIST ──────────────────────────────────────────────────────
@router.get("")
async def list_agents(request: Request):
    # Load from DB
    db_agents = await _db_load_agents()

    # Merge with in-memory
    agents = _merge_agents(db_agents, _registry(request))

    # Recompute live status
    for a in agents:
        a["status"] = _compute_status(a.get("last_seen"))

    # Count open alerts per agent from DB
    try:
        from db.store import load_alerts
        all_alerts = await load_alerts(limit=2000, status="new")
        for a in agents:
            a["open_alerts"] = sum(
                1 for al in all_alerts
                if al.get("hostname") == a.get("hostname")
            )
    except Exception:
        # Fallback to in-memory alert store
        try:
            alert_store = getattr(request.app.state, "alert_store", {})
            for a in agents:
                a["open_alerts"] = sum(
                    1 for al in alert_store.values()
                    if al.get("hostname") == a.get("hostname")
                    and al.get("status") == "new"
                )
        except Exception:
            pass

    agents.sort(key=lambda a: (a.get("status", "") != "online", a.get("hostname", "")))

    return {
        "agents":   agents,
        "total":    len(agents),
        "online":   sum(1 for a in agents if a.get("status") == "online"),
        "degraded": sum(1 for a in agents if a.get("status") == "degraded"),
        "offline":  sum(1 for a in agents if a.get("status") == "offline"),
    }

# ── SINGLE ────────────────────────────────────────────────────
@router.get("/{agent_id}")
async def get_agent(agent_id: str, request: Request):
    # Check memory first
    agent = _registry(request).get(agent_id)
    if not agent:
        # Try DB
        db_agents = await _db_load_agents()
        for a in db_agents:
            if a.get("agent_id") == agent_id:
                agent = a
                break
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent["status"] = _compute_status(agent.get("last_seen"))
    return agent

# ── HEARTBEAT ─────────────────────────────────────────────────
@router.post("/{agent_id}/heartbeat")
async def heartbeat(agent_id: str, request: Request):
    registry = _registry(request)
    body     = await request.json()
    existing = registry.get(agent_id, {})

    agent = {
        **existing,
        "agent_id":      agent_id,
        "hostname":      body.get("hostname",      existing.get("hostname",      "unknown")),
        "os_name":       body.get("os_name",       existing.get("os_name",       "Linux")),
        "os_version":    body.get("os_version",    existing.get("os_version",    "")),
        "agent_version": body.get("agent_version", existing.get("agent_version", "1.0.0")),
        "status":        "online",
        "last_seen":     now_iso(),
        "cpu_pct":       float(body.get("cpu_pct", 0) or 0),
        "mem_pct":       float(body.get("mem_pct", 0) or 0),
        "uptime_secs":   body.get("uptime_secs", 0),
        "ip_address":    request.client.host if request.client else "unknown",
        "open_alerts":   existing.get("open_alerts", 0),
    }

    # Save to memory
    registry[agent_id] = agent

    # Save to PostgreSQL
    await _db_upsert_agent(agent)

    log.debug(f"Heartbeat saved: {agent['hostname']} ({agent_id})")

    # Broadcast to dashboard
    try:
        from ingest.processor import manager
        await manager.broadcast({
            "type":    "agent_heartbeat",
            "payload": agent,
        })
    except Exception:
        pass

    return {"status": "ok", "agent_id": agent_id}

# ── MANUAL STATUS ─────────────────────────────────────────────
@router.patch("/{agent_id}/status")
async def set_status(agent_id: str, request: Request):
    registry = _registry(request)
    body     = await request.json()
    agent    = registry.get(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent["status"]     = body.get("status", agent["status"])
    agent["updated_at"] = now_iso()

    # Save updated status to DB
    await _db_upsert_agent(agent)

    return {"agent_id": agent_id, "status": agent["status"]}

# ── DEREGISTER ────────────────────────────────────────────────
@router.delete("/{agent_id}")
async def delete_agent(agent_id: str, request: Request):
    registry = _registry(request)
    if agent_id in registry:
        del registry[agent_id]
    # Note: we keep agent in DB for historical record
    # Set status to offline instead of hard delete
    try:
        from db.store import upsert_agent
        await upsert_agent({
            "agent_id": agent_id,
            "status":   "offline",
            "last_seen": now_iso(),
        })
    except Exception:
        pass
    log.info(f"Agent deregistered: {agent_id}")
    return {"deleted": agent_id}
