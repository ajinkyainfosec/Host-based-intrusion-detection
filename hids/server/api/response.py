# server/api/response.py
# Response Actions API — called by dashboard One-Click Response panel
# All endpoints log the action to DB and broadcast to dashboard.
# Wire to real system commands in production (ansible, fabric, ssh, etc.)

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Request

log    = logging.getLogger("sentinel.api.response")
router = APIRouter()

# In-memory action log (also saved to DB via broadcast)
ACTION_LOG: list[dict] = []
MAX_LOG = 500


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _analyst(req: Request) -> str:
    return req.headers.get("Authorization", "").replace("Bearer ", "").strip()[:20] or "analyst"


async def _log_action(
    action:   str,
    target:   str,
    analyst:  str,
    result:   str,
    details:  dict = {},
) -> dict:
    """Log action to memory and broadcast to dashboard."""
    entry = {
        "action":    action,
        "target":    target,
        "analyst":   analyst,
        "result":    result,
        "details":   details,
        "timestamp": now_iso(),
    }

    # Keep in-memory log
    ACTION_LOG.append(entry)
    if len(ACTION_LOG) > MAX_LOG:
        ACTION_LOG.pop(0)

    log.info(f"RESPONSE [{action}] target={target} by={analyst} → {result}")

    # Broadcast to dashboard so action log updates live
    try:
        from ingest.processor import manager
        await manager.broadcast({
            "type":    "response_action",
            "payload": entry,
        })
    except Exception as e:
        log.debug(f"Broadcast failed: {e}")

    return entry


# ── ISOLATE HOST ──────────────────────────────────────────────
@router.post("/isolate")
async def isolate_host(req: Request):
    body     = await req.json()
    hostname = body.get("hostname", "")
    if not hostname:
        return {"error": "hostname required"}

    # Production implementation:
    # import subprocess
    # subprocess.run(["ssh", f"root@{hostname}",
    #   "iptables -I INPUT -j DROP; iptables -I OUTPUT -j DROP; "
    #   "iptables -I INPUT -s MGMT_IP -j ACCEPT"])

    return await _log_action(
        "ISOLATE_HOST", hostname, _analyst(req),
        "queued — apply iptables DROP rules on host",
        {"hostname": hostname, "executed_by": body.get("executed_by", "")}
    )


# ── KILL PROCESS ─────────────────────────────────────────────
@router.post("/kill-process")
async def kill_process(req: Request):
    body = await req.json()
    pid  = body.get("pid", "")
    host = body.get("hostname", "")

    # Production:
    # subprocess.run(["ssh", f"root@{host}", f"kill -9 {pid}"])

    return await _log_action(
        "KILL_PROCESS", f"{host}:PID={pid}", _analyst(req),
        "queued — send SIGKILL to process",
        {"pid": pid, "hostname": host}
    )


# ── BLOCK IP ─────────────────────────────────────────────────
@router.post("/block-ip")
async def block_ip(req: Request):
    body = await req.json()
    ip   = body.get("ip", "")
    if not ip:
        return {"error": "ip required"}

    # Production:
    # subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    # subprocess.run(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"])

    return await _log_action(
        "BLOCK_IP", ip, _analyst(req),
        "queued — add to firewall blocklist",
        {"ip": ip}
    )


# ── DISABLE USER ─────────────────────────────────────────────
@router.post("/disable-user")
async def disable_user(req: Request):
    body = await req.json()
    user = body.get("username", "")
    if not user:
        return {"error": "username required"}

    # Production:
    # subprocess.run(["passwd", "-l", user])
    # subprocess.run(["pkill", "-u", user])

    return await _log_action(
        "DISABLE_USER", user, _analyst(req),
        "queued — lock account and kill sessions",
        {"username": user}
    )


# ── QUARANTINE FILE ───────────────────────────────────────────
@router.post("/quarantine")
async def quarantine_file(req: Request):
    body = await req.json()
    path = body.get("path", "")
    if not path:
        return {"error": "path required"}

    # Production:
    # import shutil, os
    # quarantine_dir = "/var/quarantine"
    # os.makedirs(quarantine_dir, exist_ok=True)
    # shutil.move(path, quarantine_dir)
    # os.chmod(f"{quarantine_dir}/{os.path.basename(path)}", 0o000)

    return await _log_action(
        "QUARANTINE", path, _analyst(req),
        "queued — move file to /var/quarantine",
        {"path": path}
    )


# ── RESTART SERVICE ───────────────────────────────────────────
@router.post("/restart-service")
async def restart_service(req: Request):
    body = await req.json()
    svc  = body.get("service", "")
    if not svc:
        return {"error": "service required"}

    # Production:
    # subprocess.run(["systemctl", "restart", svc])

    return await _log_action(
        "RESTART_SERVICE", svc, _analyst(req),
        "queued — systemctl restart",
        {"service": svc}
    )


# ── SNAPSHOT ─────────────────────────────────────────────────
@router.post("/snapshot")
async def snapshot(req: Request):
    body = await req.json()
    host = body.get("hostname", "")

    # Production:
    # Call cloud provider API (AWS EC2 AMI, GCP snapshot, Azure disk snapshot)
    # Or LVM snapshot: subprocess.run(["lvcreate", "-L10G", "-s", "-n", "snap", "/dev/vg/lv"])

    return await _log_action(
        "SNAPSHOT", host, _analyst(req),
        "queued — forensic snapshot initiated",
        {"hostname": host}
    )


# ── NOTIFY SOC ────────────────────────────────────────────────
@router.post("/notify")
async def notify_soc(req: Request):
    body     = await req.json()
    incident = body.get("incident_id", "")

    # Production:
    # requests.post("https://events.pagerduty.com/v2/enqueue", json={...})
    # Or: slack_webhook.post({"text": f"INCIDENT: {incident}"})

    return await _log_action(
        "NOTIFY_SOC", incident, _analyst(req),
        "queued — notification dispatched to SOC",
        {"incident_id": incident}
    )


# ── ACTION LOG ────────────────────────────────────────────────
@router.get("/log")
async def get_action_log():
    return {
        "actions": list(reversed(ACTION_LOG)),
        "total":   len(ACTION_LOG),
    }


# ── CLEAR LOG ────────────────────────────────────────────────
@router.delete("/log")
async def clear_action_log():
    ACTION_LOG.clear()
    return {"status": "cleared"}
