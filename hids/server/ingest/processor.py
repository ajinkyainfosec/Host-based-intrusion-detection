from db.store import save_alert, save_event
# server/ingest/processor.py
# Event Processor — v4

import asyncio
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from detection.engine import DetectionEngine

log = logging.getLogger("sentinel.ingest")

# ── Global alert store (shared with alerts API) ────────────────
GENERATED_ALERTS: list[dict] = []
MAX_ALERTS = 2000

# ── Disk backup queue path ─────────────────────────────────────
BACKUP_QUEUE_PATH = "/var/log/sentinel/unsent_events.jsonl"

# ── Correlation rules ──────────────────────────────────────────
CORRELATION_CHAINS = [
    {
        "name":        "Brute Force → Successful Login",
        "trigger":     "SENT-AUTH-001",
        "follow_up":   ["SENT-PE-001"],
        "window_secs": 300,
        "incident":    "BRUTE_FORCE_SUCCESS",
        "severity":    "CRITICAL",
        "description": "Brute force attack followed by privilege escalation — active compromise",
    },
    {
        "name":        "Web Shell → C2 Connection",
        "trigger":     "SENT-PERS-004",
        "follow_up":   ["SENT-NET-001", "SENT-RS-001"],
        "window_secs": 600,
        "incident":    "WEBSHELL_C2",
        "severity":    "CRITICAL",
        "description": "Web shell dropped followed by C2 connection — active backdoor",
    },
    {
        "name":        "New User → Sudo Escalation",
        "trigger":     "SENT-PERS-002",
        "follow_up":   ["SENT-PE-001"],
        "window_secs": 300,
        "incident":    "BACKDOOR_ACCOUNT_ESCALATION",
        "severity":    "CRITICAL",
        "description": "Backdoor account created then used for privilege escalation",
    },
    {
        "name":        "Rootkit → C2 Connection",
        "trigger":     "SENT-RK-001",
        "follow_up":   ["SENT-NET-001", "SENT-NET-002"],
        "window_secs": 600,
        "incident":    "ROOTKIT_C2",
        "severity":    "CRITICAL",
        "description": "Rootkit loaded followed by C2 communication — full compromise",
    },
]


# ── WebSocket Connection Manager ───────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: list = []

    async def connect(self, ws):
        await ws.accept()
        self.active.append(ws)
        log.info(f"WS connected — {len(self.active)} clients")

    def disconnect(self, ws):
        if ws in self.active:
            self.active.remove(ws)
        log.info(f"WS disconnected — {len(self.active)} clients")

    async def broadcast(self, message: dict):
        if not self.active:
            return
        data = json.dumps(message, default=str)
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self.active:
                self.active.remove(ws)


manager = ConnectionManager()


def _get_event_data(event: dict) -> dict:
    """
    Robustly extract the event data payload from any event format.

    Agent sends:
      { "event_type": "file_event", "event_data": {"path": "/etc/hosts", ...} }

    Old format:
      { "data": {"type": "file_event", "path": "/etc/hosts", ...} }
    """
    # Primary format — agent v1.0+
    data = event.get("event_data", {})

    # Handle JSON string (from DB round-trip)
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            data = {}

    # Fallback — old format
    if not data:
        data = event.get("data", {})

    return data or {}


def _get_event_type(event: dict) -> str:
    """
    Robustly extract event type from any event format.
    """
    # Primary: top-level event_type field
    event_type = event.get("event_type", "")

    # Fallback 1: inside event_data
    if not event_type:
        data = _get_event_data(event)
        event_type = data.get("type", "")

    # Fallback 2: inside old "data" field
    if not event_type:
        event_type = event.get("data", {}).get("type", "")

    return event_type


# ── Event Processor ────────────────────────────────────────────
class EventProcessor:
    def __init__(self, detection_engine: DetectionEngine):
        self.engine       = detection_engine
        self.queue        = asyncio.Queue(maxsize=50_000)
        self.running      = False
        self.stats        = {
            "processed":  0,
            "alerts":     0,
            "errors":     0,
            "duplicates": 0,
            "incidents":  0,
            "escalated":  0,
        }
        self._app_state   = None
        self._seen_alerts = {}
        self._recent_alerts: dict = {}
        self._host_risk: dict = {}
        Path(BACKUP_QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)

    def _is_duplicate(self, alert: dict) -> bool:
        now    = time.time()
        bucket = int(now // 300)
        key    = hashlib.md5(
            f"{alert['rule_id']}:{alert['hostname']}:{bucket}".encode()
        ).hexdigest()
        self._seen_alerts = {k: v for k, v in self._seen_alerts.items() if v > now}
        if key in self._seen_alerts:
            return True
        self._seen_alerts[key] = now + 300
        return False

    def _check_correlation(self, alert: dict) -> dict | None:
        hostname = alert.get("hostname", "unknown")
        rule_id  = alert.get("rule_id", "")
        now      = time.time()

        if hostname not in self._recent_alerts:
            self._recent_alerts[hostname] = {}
        self._recent_alerts[hostname][rule_id] = now

        for host in list(self._recent_alerts.keys()):
            self._recent_alerts[host] = {
                r: t for r, t in self._recent_alerts[host].items()
                if now - t < 600
            }

        for chain in CORRELATION_CHAINS:
            trigger    = chain["trigger"]
            follow_ups = chain["follow_up"]
            window     = chain["window_secs"]

            host_history = self._recent_alerts.get(hostname, {})

            if rule_id not in follow_ups:
                continue
            trigger_time = host_history.get(trigger)
            if not trigger_time:
                continue
            if now - trigger_time > window:
                continue

            incident = {
                "incident_id":   f"INC-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
                "incident_type": chain["incident"],
                "name":          chain["name"],
                "hostname":      hostname,
                "severity":      chain["severity"],
                "description":   chain["description"],
                "trigger_rule":  trigger,
                "followup_rule": rule_id,
                "timestamp":     datetime.now(timezone.utc).isoformat(),
                "alert_ids":     [alert["alert_id"]],
            }
            log.warning(f"INCIDENT [{chain['incident']}] on {hostname} — {chain['name']}")
            return incident

        return None

    def _apply_risk_escalation(self, alert: dict) -> dict:
        hostname   = alert.get("hostname", "unknown")
        open_count = sum(
            1 for a in GENERATED_ALERTS
            if a.get("hostname") == hostname and a.get("status") == "new"
        )
        self._host_risk[hostname] = open_count
        original  = alert["severity"]
        escalated = original

        if open_count >= 10:
            if original in ("MEDIUM", "HIGH"):
                escalated = "CRITICAL"
        elif open_count >= 5:
            if original == "MEDIUM":
                escalated = "HIGH"

        if escalated != original:
            alert["severity"] = escalated
            alert["reason"]  += (
                f" [ESCALATED {original}→{escalated}: "
                f"host has {open_count} open alerts]"
            )
            self.stats["escalated"] += 1
            log.warning(
                f"ESCALATED {original}→{escalated}: "
                f"{alert['rule_title']} on {hostname} "
                f"({open_count} open alerts)"
            )
        return alert

    def _write_backup_queue(self, events: list[dict]) -> None:
        try:
            with open(BACKUP_QUEUE_PATH, "a") as f:
                for event in events:
                    f.write(json.dumps(event, default=str) + "\n")
            log.warning(f"Wrote {len(events)} events to backup queue: {BACKUP_QUEUE_PATH}")
        except Exception as e:
            log.error(f"Failed to write backup queue: {e}")

    def _replay_backup_queue(self) -> int:
        path = Path(BACKUP_QUEUE_PATH)
        if not path.exists() or path.stat().st_size == 0:
            return 0
        replayed = 0
        try:
            with open(BACKUP_QUEUE_PATH) as f:
                lines = f.readlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    self.queue.put_nowait(event)
                    replayed += 1
                except Exception:
                    pass
            open(BACKUP_QUEUE_PATH, "w").close()
            log.info(f"Replayed {replayed} events from backup queue")
        except Exception as e:
            log.error(f"Backup queue replay failed: {e}")
        return replayed

    async def start(self):
        self.running = True
        replayed = self._replay_backup_queue()
        if replayed > 0:
            log.info(f"Recovery: {replayed} events replayed from disk backup")
        log.info("Event processor started with 4 workers")
        workers = [asyncio.create_task(self._worker(i)) for i in range(4)]
        await asyncio.gather(*workers)

    async def stop(self):
        self.running = False

    async def enqueue(self, events: list[dict]):
        dropped = []
        for event in events:
            try:
                self.queue.put_nowait(event)
            except asyncio.QueueFull:
                dropped.append(event)
                self.stats["errors"] += 1
        if dropped:
            log.warning(f"Queue full — writing {len(dropped)} events to disk backup")
            self._write_backup_queue(dropped)

    async def _worker(self, wid: int):
        log.info(f"Worker {wid} ready")
        while self.running:
            try:
                event = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                await self._process(event)
                self.queue.task_done()
                self.stats["processed"] += 1
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                log.error(f"Worker {wid} error: {e}")
                self.stats["errors"] += 1

    async def _process(self, event: dict):
        if "timestamp" not in event:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()

        await self._register_agent(event)

        # ── Normalize event for detection engine ──────────────
        # Engine expects event_type + event_data at top level
        # Ensure both keys are always present regardless of source format
        event_data = _get_event_data(event)
        event_type = _get_event_type(event)

        # Inject normalized fields so engine always finds them
        event["event_type"] = event_type
        event["event_data"] = event_data

        # Run detection
        results = self.engine.analyze(event)

        for result in results:
            if not result.triggered:
                continue

            alert = {
                "alert_id":      f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
                "event_id":      event.get("event_id") or event.get("id"),
                "agent_id":      event.get("agent_id"),
                "hostname":      event.get("hostname"),
                "timestamp":     event.get("timestamp"),
                "rule_id":       result.rule.id,
                "rule_title":    result.rule.title,
                "severity":      result.rule.severity.upper(),
                "score":         result.score,
                "reason":        result.reason,
                "mitre_id":      result.mitre.get("technique_id", "") if result.mitre else "",
                "mitre_tactic":  result.mitre.get("tactic", "") if result.mitre else "",
                "mitre_name":    result.mitre.get("technique_name", result.mitre.get("technique", "")) if result.mitre else "",
                "tags":          result.rule.tags,
                # ✅ FIXED: use correct event_data key
                "event_data":    event_data,
                "event_subtype": event_type,
                "status":        "new",
                "assigned_to":   "",
                "incident_id":   "",
            }

            if self._is_duplicate(alert):
                self.stats["duplicates"] += 1
                log.debug(f"Duplicate suppressed: {alert['rule_title']} on {alert['hostname']}")
                continue

            alert = self._apply_risk_escalation(alert)

            global GENERATED_ALERTS
            GENERATED_ALERTS.append(alert)
            asyncio.ensure_future(save_alert(alert))
            if len(GENERATED_ALERTS) > MAX_ALERTS:
                GENERATED_ALERTS = GENERATED_ALERTS[-MAX_ALERTS:]

            if self._app_state and hasattr(self._app_state, "alert_store"):
                self._app_state.alert_store[alert["alert_id"]] = alert

            self.stats["alerts"] += 1
            log.warning(
                f"ALERT [{alert['severity']}] {alert['rule_title']} "
                f"on {alert['hostname']} — {alert['reason']}"
            )

            incident = self._check_correlation(alert)
            if incident:
                self.stats["incidents"] += 1
                alert["incident_id"] = incident["incident_id"]
                alert["severity"] = "CRITICAL"
                if self._app_state and hasattr(self._app_state, "alert_store"):
                    self._app_state.alert_store[alert["alert_id"]] = alert
                await manager.broadcast({"type": "incident", "payload": incident})

            await manager.broadcast({"type": "alert", "payload": alert})

        # Broadcast raw event to dashboard
        await manager.broadcast({
            "type": "event",
            "payload": {
                "id":         event.get("event_id") or event.get("id"),
                "hostname":   event.get("hostname"),
                "agent_id":   event.get("agent_id"),
                "timestamp":  event.get("timestamp"),
                "severity":   event.get("severity", "INFO"),
                "event_type": event_type,
                "data":       event_data,
                "tags":       event.get("tags", []),
            },
        })

    async def _register_agent(self, event: dict):
        if not self._app_state:
            return
        if not hasattr(self._app_state, "agent_registry"):
            self._app_state.agent_registry = {}

        agent_id = event.get("agent_id")
        hostname = event.get("hostname")
        if not agent_id or not hostname:
            return

        existing = self._app_state.agent_registry.get(agent_id, {})
        agent = {
            **existing,
            "agent_id":      agent_id,
            "hostname":      hostname,
            "status":        "online",
            "last_seen":     event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "agent_version": event.get("agent_version", existing.get("agent_version", "1.0.0")),
        }

        self._app_state.agent_registry[agent_id] = agent

        try:
            from db.store import upsert_agent
            asyncio.ensure_future(upsert_agent(agent))
        except Exception as e:
            log.debug(f"upsert_agent failed: {e}")

    def get_stats(self) -> dict:
        return {
            **self.stats,
            "queue_size": self.queue.qsize(),
            "ws_clients": len(manager.active),
            "host_risk":  self._host_risk,
        }
