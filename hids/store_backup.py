# server/db/store.py
# PostgreSQL persistence layer
import json
import logging
import uuid
from datetime import datetime, timezone

log = logging.getLogger("sentinel.store")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(ts) -> datetime:
    """
    Convert any timestamp to a datetime object for PostgreSQL.
    Handles nanosecond precision from Rust agent e.g. 2026-03-25T07:29:15.596148301Z
    by truncating fractional seconds to 6 digits (microseconds = PostgreSQL max).
    """
    if ts is None:
        return _now()
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    try:
        s = str(ts).strip()
        # Truncate fractional seconds to max 6 digits
        if '.' in s:
            dot = s.index('.')
            end = dot + 1
            while end < len(s) and s[end].isdigit():
                end += 1
            frac = s[dot+1:end][:6].ljust(6, '0')
            s = s[:dot+1] + frac + s[end:]
        # Normalise Z to +00:00
        s = s.replace('Z', '+00:00')
        return datetime.fromisoformat(s)
    except Exception:
        return _now()


def _safe_json(obj) -> str:
    try:
        return json.dumps(obj) if obj else "{}"
    except Exception:
        return "{}"


def _get_session():
    """
    Always import at call time so we get the live AsyncSessionLocal
    even if init_db() ran after this module was first imported.
    """
    import db.database as db_mod
    return db_mod.AsyncSessionLocal


# ── Alert persistence ──────────────────────────────────────────
async def save_alert(alert: dict) -> None:
    AsyncSessionLocal = _get_session()
    if AsyncSessionLocal is None:
        log.warning("save_alert: DB not ready, alert not saved")
        return
    try:
        from sqlalchemy import text
        async with AsyncSessionLocal() as session:
            await session.execute(text("""
                INSERT INTO alerts (
                    alert_id,
                    rule_id,
                    rule_title,
                    hostname,
                    severity,
                    score,
                    status,
                    reason,
                    mitre_id,
                    mitre_tactic,
                    event_subtype,
                    event_data,
                    assigned_to,
                    created_at
                ) VALUES (
                    :alert_id,
                    :rule_id,
                    :rule_title,
                    :hostname,
                    :severity,
                    :score,
                    :status,
                    :reason,
                    :mitre_id,
                    :mitre_tactic,
                    :event_subtype,
                    :event_data ::jsonb,
                    :assigned_to,
                    :created_at
                )
                ON CONFLICT (alert_id) DO UPDATE SET
                    status      = EXCLUDED.status,
                    assigned_to = EXCLUDED.assigned_to
            """), {
                "alert_id":     str(alert.get("alert_id")     or uuid.uuid4()),
                "rule_id":      str(alert.get("rule_id")      or ""),
                "rule_title":   str(alert.get("rule_title")   or ""),
                "hostname":     str(alert.get("hostname")     or ""),
                "severity":     str(alert.get("severity")     or "INFO"),
                "score":        int(alert.get("score")        or 0),
                "status":       str(alert.get("status")       or "new"),
                "reason":       str(alert.get("reason")       or ""),
                "mitre_id":     str(alert.get("mitre_id")     or ""),
                "mitre_tactic": str(alert.get("mitre_tactic") or ""),
                "event_subtype":str(alert.get("event_subtype")or ""),
                "event_data":   _safe_json(alert.get("event_data")),
                "assigned_to":  str(alert.get("assigned_to")  or ""),
                "created_at":   _parse_ts(alert.get("timestamp")),
            })
            await session.commit()
            log.info(
                f"save_alert OK: {alert.get('alert_id')} "
                f"[{alert.get('severity')}] {alert.get('rule_title')}"
            )
    except Exception as e:
        log.error(
            f"save_alert FAILED: {e} | alert_id={alert.get('alert_id')}"
        )


async def load_alerts(limit: int = 200, severity: str = None,
                      status: str = None, hostname: str = None) -> list[dict]:
    AsyncSessionLocal = _get_session()
    if AsyncSessionLocal is None:
        return []
    try:
        from sqlalchemy import text
        filters = []
        params  = {"limit": limit}
        if severity:
            filters.append("severity = :severity")
            params["severity"] = severity
        if status:
            filters.append("status = :status")
            params["status"] = status
        if hostname:
            filters.append("hostname = :hostname")
            params["hostname"] = hostname
        where = ("WHERE " + " AND ".join(filters)) if filters else ""

        async with AsyncSessionLocal() as session:
            rows = await session.execute(text(f"""
                SELECT alert_id, rule_id, rule_title, hostname, severity,
                       score, status, reason, mitre_id, mitre_tactic,
                       event_subtype, event_data, assigned_to,
                       acknowledged_at, created_at
                FROM alerts
                {where}
                ORDER BY created_at DESC
                LIMIT :limit
            """), params)
            cols   = list(rows.keys())
            result = []
            for row in rows.fetchall():
                d = dict(zip(cols, row))
                d["timestamp"] = str(d.get("created_at", ""))
                result.append(d)
            return result
    except Exception as e:
        log.error(f"load_alerts FAILED: {e}")
        return []


async def update_alert_status(alert_id: str, status: str,
                               extra: dict = None) -> bool:
    AsyncSessionLocal = _get_session()
    if AsyncSessionLocal is None:
        return False
    try:
        from sqlalchemy import text
        sets   = ["status = :status"]
        params = {"status": status, "alert_id": alert_id}
        if extra:
            for k, v in extra.items():
                sets.append(f"{k} = :{k}")
                params[k] = v
        async with AsyncSessionLocal() as session:
            await session.execute(text(f"""
                UPDATE alerts
                SET {', '.join(sets)}
                WHERE alert_id = :alert_id
            """), params)
            await session.commit()
        return True
    except Exception as e:
        log.error(f"update_alert_status FAILED: {e}")
        return False


# ── Event persistence ──────────────────────────────────────────
async def save_event(event: dict) -> None:
    AsyncSessionLocal = _get_session()
    if AsyncSessionLocal is None:
        return
    try:
        from sqlalchemy import text
        data = event.get("data", {})
        async with AsyncSessionLocal() as session:
            await session.execute(text("""
                INSERT INTO events (
                    event_id,
                    agent_id,
                    hostname,
                    severity,
                    event_type,
                    event_data,
                    timestamp
                ) VALUES (
                    :event_id,
                    :agent_id,
                    :hostname,
                    :severity,
                    :event_type,
                    :event_data ::jsonb,
                    :timestamp
                )
                ON CONFLICT (event_id) DO NOTHING
            """), {
                "event_id":   str(event.get("event_id") or uuid.uuid4()),
                "agent_id":   str(event.get("agent_id")  or ""),
                "hostname":   str(event.get("hostname")  or ""),
                "severity":   str(event.get("severity")  or "INFO"),
                "event_type": str(data.get("type")       or "unknown"),
                "event_data": _safe_json(data),
                "timestamp":  _parse_ts(event.get("timestamp")),
            })
            await session.commit()
    except Exception as e:
        log.error(f"save_event FAILED: {e}")


async def load_events(limit: int = 200, event_type: str = None,
                      hostname: str = None) -> list[dict]:
    AsyncSessionLocal = _get_session()
    if AsyncSessionLocal is None:
        return []
    try:
        from sqlalchemy import text
        filters = []
        params  = {"limit": limit}
        if event_type:
            filters.append("event_type = :event_type")
            params["event_type"] = event_type
        if hostname:
            filters.append("hostname = :hostname")
            params["hostname"] = hostname
        where = ("WHERE " + " AND ".join(filters)) if filters else ""

        async with AsyncSessionLocal() as session:
            rows = await session.execute(text(f"""
                SELECT event_id, agent_id, hostname, severity,
                       event_type, event_data, timestamp
                FROM events
                {where}
                ORDER BY timestamp DESC
                LIMIT :limit
            """), params)
            cols = list(rows.keys())
            return [dict(zip(cols, row)) for row in rows.fetchall()]
    except Exception as e:
        log.error(f"load_events FAILED: {e}")
        return []


# ── Agent persistence ──────────────────────────────────────────
async def upsert_agent(agent: dict) -> None:
    AsyncSessionLocal = _get_session()
    if AsyncSessionLocal is None:
        return
    try:
        from sqlalchemy import text
        async with AsyncSessionLocal() as session:
            await session.execute(text("""
                INSERT INTO agents (
                    agent_id,
                    hostname,
                    ip_address,
                    os_name,
                    agent_version,
                    status,
                    cpu_pct,
                    mem_pct,
                    open_alerts,
                    last_seen
                ) VALUES (
                    :agent_id,
                    :hostname,
                    :ip_address,
                    :os_name,
                    :agent_version,
                    :status,
                    :cpu_pct,
                    :mem_pct,
                    :open_alerts,
                    :last_seen
                )
                ON CONFLICT (agent_id) DO UPDATE SET
                    hostname      = EXCLUDED.hostname,
                    ip_address    = EXCLUDED.ip_address,
                    status        = EXCLUDED.status,
                    cpu_pct       = EXCLUDED.cpu_pct,
                    mem_pct       = EXCLUDED.mem_pct,
                    open_alerts   = EXCLUDED.open_alerts,
                    last_seen     = EXCLUDED.last_seen
            """), {
                "agent_id":      str(agent.get("agent_id")      or ""),
                "hostname":      str(agent.get("hostname")      or ""),
                "ip_address":    str(agent.get("ip_address")    or ""),
                "os_name":       str(agent.get("os_name")       or "Linux"),
                "agent_version": str(agent.get("agent_version") or ""),
                "status":        str(agent.get("status")        or "online"),
                "cpu_pct":       float(agent.get("cpu_pct")     or 0),
                "mem_pct":       float(agent.get("mem_pct")     or 0),
                "open_alerts":   int(agent.get("open_alerts")   or 0),
                "last_seen":     _parse_ts(agent.get("last_seen")),
            })
            await session.commit()
    except Exception as e:
        log.error(f"upsert_agent FAILED: {e}")


async def load_agents() -> list[dict]:
    AsyncSessionLocal = _get_session()
    if AsyncSessionLocal is None:
        return []
    try:
        from sqlalchemy import text
        async with AsyncSessionLocal() as session:
            rows = await session.execute(text("""
                SELECT agent_id, hostname, ip_address, os_name,
                       agent_version, status, cpu_pct, mem_pct,
                       open_alerts, last_seen, registered_at
                FROM agents
                ORDER BY last_seen DESC
            """))
            cols = list(rows.keys())
            return [dict(zip(cols, row)) for row in rows.fetchall()]
    except Exception as e:
        log.error(f"load_agents FAILED: {e}")
        return []
