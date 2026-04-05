# server/api/ws.py
# WebSocket endpoint — streams live alerts + events to dashboard
# ws://server/ws/events

import logging
import os

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from ingest.processor import manager

log    = logging.getLogger("sentinel.api.ws")
router = APIRouter()

API_KEY = os.getenv("API_KEY", "changeme")


@router.websocket("/events")
async def ws_events(
    websocket: WebSocket,
    token: str = Query(default=""),   # dashboard sends ?token=<api_key>
):
    """
    Dashboard connects here to receive live data.

    Auth: pass API key as query param → ws://server/ws/events?token=<api_key>
    Dashboard already does this via CFG.apiKey in the JS.

    Message types sent TO dashboard:
      { "type": "alert",           "payload": { ...alert fields } }
      { "type": "event",           "payload": { ...raw event }    }
      { "type": "alert_update",    "payload": { alert_id, status } }
      { "type": "agent_heartbeat", "payload": { ...agent fields } }
      { "type": "incident",        "payload": { ...incident }     }
    """

    # ── Auth check ────────────────────────────────────────────
    # Accept raw API key OR a valid session token
    if token and token != API_KEY:
        # Check against valid session tokens from auth module
        try:
            from api.auth import VALID_TOKENS
            if token not in VALID_TOKENS:
                await websocket.close(code=4401, reason="Unauthorized")
                log.warning(f"WS rejected — invalid token from {websocket.client.host}")
                return
        except Exception:
            # If auth module unavailable, fall back to API key only check
            await websocket.close(code=4401, reason="Unauthorized")
            return

    # ── Connect ───────────────────────────────────────────────
    await manager.connect(websocket)
    client_ip = websocket.client.host if websocket.client else "unknown"
    log.info(f"WS connected: {client_ip} — total clients: {len(manager.active)}")

    # ── Send last 10 alerts on connect so dashboard isn't empty ──
    try:
        from db.store import load_alerts
        recent = await load_alerts(limit=10)
        if recent:
            import json
            await websocket.send_text(json.dumps({
                "type":    "recent_alerts",
                "payload": recent,
            }, default=str))
            log.debug(f"Sent {len(recent)} recent alerts to new WS client")
    except Exception as e:
        log.debug(f"Could not send recent alerts on connect: {e}")

    # ── Message loop ──────────────────────────────────────────
    try:
        while True:
            msg = await websocket.receive_text()

            if msg == "ping":
                await websocket.send_text("pong")

            elif msg == "get_alerts":
                # Dashboard can request fresh alerts anytime
                try:
                    from db.store import load_alerts
                    import json
                    alerts = await load_alerts(limit=50)
                    await websocket.send_text(json.dumps({
                        "type":    "alerts_refresh",
                        "payload": alerts,
                    }, default=str))
                except Exception as e:
                    log.debug(f"get_alerts failed: {e}")

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        log.info(f"WS disconnected: {client_ip} — remaining: {len(manager.active)}")

    except Exception as e:
        log.warning(f"WS error from {client_ip}: {e}")
        manager.disconnect(websocket)
