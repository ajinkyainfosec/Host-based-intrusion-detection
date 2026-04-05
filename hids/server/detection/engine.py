# server/detection/engine.py
# Detection Engine
# Loads Sigma rules from YAML, matches incoming events, generates alerts
# Also applies MITRE ATT&CK mapping and severity scoring

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger("sentinel.detection")


@dataclass
class SigmaRule:
    id:          str
    title:       str
    description: str
    severity:    str
    tags:        list[str]
    mitre:       dict
    detection:   dict
    compiled:    list[dict]


@dataclass
class DetectionResult:
    triggered:  bool
    rule:       SigmaRule | None = None
    score:      int = 0
    reason:     str = ""
    mitre:      dict = field(default_factory=dict)


class DetectionEngine:
    def __init__(self):
        self.rules:      list[SigmaRule] = []
        self.rule_count: int = 0
        self._failure_counts: dict = {}

    async def load_rules(self, rules_dir: str) -> None:
        path = Path(rules_dir)

        if not path.exists():
            log.warning(f"Rules directory not found: {rules_dir} — falling back to built-in rules")
            self._load_builtin_rules()
            return

        loaded = 0
        for rule_file in path.glob("**/*.yml"):
            try:
                with open(rule_file) as f:
                    content = f.read()

                for doc in content.split('---'):
                    doc = doc.strip()
                    if not doc:
                        continue
                    data = yaml.safe_load(doc)
                    if data and isinstance(data, dict) and data.get("id"):
                        rule = self._parse_rule(data)
                        if rule:
                            self.rules.append(rule)
                            loaded += 1

            except Exception as e:
                log.warning(f"Failed to load rule {rule_file}: {e}")

        if loaded == 0:
            log.warning("No YAML rules loaded — falling back to built-in rules")
            self._load_builtin_rules()
        else:
            self.rule_count = len(self.rules)
            log.info(f"Loaded {self.rule_count} rules from YAML — built-in rules skipped")

    def _load_builtin_rules(self) -> None:
        builtin = [
            {
                "id": "SENT-001",
                "title": "Rootkit — Execution from Hidden Path",
                "description": "Process executing from /proc or hidden path",
                "severity": "critical",
                "tags": ["process", "hidden-path"],
                "mitre": {"tactic": "Defense Evasion", "technique_id": "T1014", "technique_name": "Rootkit"},
                "detection": {"process_exe_contains": ["/proc/", "/dev/shm/", "/."]},
            },
            {
                "id": "SENT-002",
                "title": "Brute Force — Repeated SSH Failures",
                "description": "More than 5 failed SSH logins from same IP",
                "severity": "high",
                "tags": ["brute-force", "auth"],
                "mitre": {"tactic": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force"},
                "detection": {"auth_action": ["failed_login"]},
            },
            {
                "id": "SENT-003",
                "title": "Reverse Shell — Interactive Shell Pattern",
                "description": "Detected reverse shell command pattern in process cmdline",
                "severity": "critical",
                "tags": ["reverse-shell", "c2"],
                "mitre": {"tactic": "Command and Control", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"},
                "detection": {"cmdline_contains": ["bash -i", "sh -i", "/dev/tcp/", "0>&1", "mkfifo"]},
            },
            {
                "id": "SENT-004",
                "title": "Privilege Escalation — Sudo to Root",
                "description": "Non-root user executed sudo to gain root shell",
                "severity": "high",
                "tags": ["privesc", "sudo"],
                "mitre": {"tactic": "Privilege Escalation", "technique_id": "T1548", "technique_name": "Abuse Elevation Control Mechanism"},
                "detection": {"auth_action": ["sudo_command"]},
            },
            {
                "id": "SENT-005",
                "title": "FIM — Critical System File Modified",
                "description": "Modification detected on a critical system binary or config",
                "severity": "critical",
                "tags": ["fim", "integrity"],
                "mitre": {"tactic": "Defense Evasion", "technique_id": "T1036", "technique_name": "Masquerading"},
                "detection": {"file_path_contains": ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts", "/usr/bin/sudo", "/lib/libpam"]},
            },
            {
                "id": "SENT-006",
                "title": "Persistence — Cron Job Created",
                "description": "New cron job added to user crontab or system cron directories",
                "severity": "high",
                "tags": ["persistence", "cron"],
                "mitre": {"tactic": "Persistence", "technique_id": "T1053", "technique_name": "Scheduled Task/Job"},
                "detection": {"file_path_contains": ["/var/spool/cron", "/etc/cron.d/", "/etc/crontab"]},
            },
            {
                "id": "SENT-007",
                "title": "C2 — Connection to Known Malicious IP",
                "description": "Outbound connection to known threat intelligence IOC",
                "severity": "critical",
                "tags": ["c2", "network"],
                "mitre": {"tactic": "Command and Control", "technique_id": "T1071", "technique_name": "Application Layer Protocol"},
                "detection": {"network_suspicious": True},
            },
            {
                "id": "SENT-008",
                "title": "Persistence — New User Account Created",
                "description": "A new user account was created on the system",
                "severity": "high",
                "tags": ["persistence", "account"],
                "mitre": {"tactic": "Persistence", "technique_id": "T1136", "technique_name": "Create Account"},
                "detection": {"auth_action": ["user_added"]},
            },
            {
                "id": "SENT-009",
                "title": "Execution — Base64 Encoded Payload",
                "description": "Base64 encoded command detected in process cmdline",
                "severity": "high",
                "tags": ["evasion", "execution"],
                "mitre": {"tactic": "Defense Evasion", "technique_id": "T1027", "technique_name": "Obfuscated Files or Information"},
                "detection": {"cmdline_contains": ["base64", "eval", "exec("]},
            },
            {
                "id": "SENT-010",
                "title": "Network — Suspicious Listening Port",
                "description": "Process opened a listener on a suspicious port (common C2 ports)",
                "severity": "high",
                "tags": ["network", "c2"],
                "mitre": {"tactic": "Command and Control", "technique_id": "T1095", "technique_name": "Non-Standard Port"},
                "detection": {"network_port_in": [4444, 5555, 1337, 31337, 6666, 9001]},
            },
            {
                "id": "SENT-011",
                "title": "Rootkit — Agent Kernel-Level Detection",
                "description": "Rootkit confirmed by agent: hidden process, hidden port, kernel module, or kallsyms anomaly",
                "severity": "critical",
                "tags": ["rootkit", "defense-evasion"],
                "mitre": {"tactic": "Defense Evasion", "technique_id": "T1014", "technique_name": "Rootkit"},
                "detection": {"rootkit_detection_methods": []},
            },
        ]

        for r in builtin:
            rule = self._parse_rule(r)
            if rule:
                self.rules.append(rule)

        self.rule_count = len(self.rules)
        log.info(f"Loaded {self.rule_count} built-in detection rules (fallback mode)")

    def _parse_rule(self, data: dict) -> SigmaRule | None:
        try:
            return SigmaRule(
                id=data.get("id", "UNKNOWN"),
                title=data.get("title", ""),
                description=data.get("description", ""),
                severity=data.get("severity", "medium").lower(),
                tags=data.get("tags", []),
                mitre=data.get("mitre", {}),
                detection=data.get("detection", {}),
                compiled=[],
            )
        except Exception as e:
            log.warning(f"Rule parse error: {e}")
            return None

    def analyze(self, event: dict) -> list[DetectionResult]:
        """Run all rules against a single event. Returns list of triggered results."""
        results = []
        for rule in self.rules:
            result = self._match_rule(rule, event)
            if result.triggered:
                results.append(result)
        return results

    def _extract_event_fields(self, event: dict) -> tuple[str, dict]:
        """
        Robustly extract event_type and event data from any event format.

        The agent sends events in this structure:
          {
            "event_id": "...",
            "agent_id": "...",
            "hostname": "...",
            "event_type": "file_event",       ← TOP LEVEL
            "event_data": {                    ← TOP LEVEL (nested dict)
              "type": "file_event",
              "path": "/etc/hosts",
              "action": "hash_changed",
              ...
            }
          }

        Old/fallback format also supported:
          {
            "data": {
              "type": "file_event",
              "path": "/etc/hosts",
            }
          }
        """
        # ── Primary format: event_type + event_data at top level ──
        event_type = event.get("event_type", "")
        data       = event.get("event_data", {})

        # event_data may be a JSON string (from DB deserialization)
        if isinstance(data, str):
            try:
                import json
                data = json.loads(data)
            except Exception:
                data = {}

        # ── Fallback: old format uses "data" key ──────────────────
        if not event_type or not data:
            old_data   = event.get("data", {})
            event_type = event_type or old_data.get("type", "")
            data       = data or old_data

        # ── Last resort: check inside data dict for type ──────────
        if not event_type:
            event_type = data.get("type", "")

        return event_type, data

    def _match_rule(self, rule: SigmaRule, event: dict) -> DetectionResult:
        det = rule.detection

        # Use robust field extraction
        event_type, data = self._extract_event_fields(event)

        # ── File event matching ───────────────────────────────────
        if "file_path_contains" in det and event_type == "file_event":
            # path can be in data["path"] or data["file_path"]
            path = data.get("path", "") or data.get("file_path", "")
            for pattern in det["file_path_contains"]:
                if pattern in path:
                    action = data.get("action", "modified")
                    return DetectionResult(
                        triggered=True, rule=rule,
                        score=self._severity_score(rule.severity),
                        reason=f"File path matches: {path} [{action}]",
                        mitre=rule.mitre,
                    )

        # ── Process event matching ────────────────────────────────
        if "cmdline_contains" in det and event_type == "process_event":
            # cmdline can be in data["cmdline"] or data["cmd"] or data["command"]
            cmdline = (
                data.get("cmdline", "")
                or data.get("cmd", "")
                or data.get("command", "")
            ).lower()
            for pattern in det["cmdline_contains"]:
                if pattern.lower() in cmdline:
                    return DetectionResult(
                        triggered=True, rule=rule,
                        score=self._severity_score(rule.severity),
                        reason=f"Cmdline pattern: {pattern}",
                        mitre=rule.mitre,
                    )

        if "process_exe_contains" in det and event_type == "process_event":
            exe = (data.get("exe", "") or data.get("executable", "")).lower()
            for pattern in det["process_exe_contains"]:
                if pattern.lower() in exe:
                    return DetectionResult(
                        triggered=True, rule=rule,
                        score=self._severity_score(rule.severity),
                        reason=f"Process exe matches: {pattern}",
                        mitre=rule.mitre,
                    )

        # ── Auth event matching ───────────────────────────────────
        if "auth_action" in det and event_type == "auth_event":
            action = data.get("action", "")
            if action in det["auth_action"]:
                threshold = det.get("auth_consecutive", 1)

                if threshold > 1:
                    src_ip    = data.get("source_ip", "unknown")
                    hostname  = event.get("hostname", "unknown")
                    track_key = f"{rule.id}:{hostname}:{src_ip}"

                    self._failure_counts[track_key] = \
                        self._failure_counts.get(track_key, 0) + 1
                    current = self._failure_counts[track_key]

                    if current < threshold:
                        return DetectionResult(triggered=False)

                    self._failure_counts[track_key] = 0
                    return DetectionResult(
                        triggered=True, rule=rule,
                        score=self._severity_score(rule.severity),
                        reason=f"Auth action: {action} — {current} consecutive failures from {src_ip}",
                        mitre=rule.mitre,
                    )

                return DetectionResult(
                    triggered=True, rule=rule,
                    score=self._severity_score(rule.severity),
                    reason=f"Auth action: {action}",
                    mitre=rule.mitre,
                )

        # ── Network event matching ────────────────────────────────
        if "network_suspicious" in det and event_type == "network_event":
            if data.get("suspicious", False):
                dest_ip = data.get("dest_ip", "") or data.get("remote_ip", "")
                return DetectionResult(
                    triggered=True, rule=rule,
                    score=self._severity_score(rule.severity),
                    reason=f"Suspicious network connection to {dest_ip}",
                    mitre=rule.mitre,
                )

        if "network_port_in" in det and event_type == "network_event":
            remote_port = data.get("remote_port", 0) or data.get("dest_port", 0)
            local_port  = data.get("local_port",  0) or data.get("src_port",  0)
            port        = remote_port or local_port
            if port in det["network_port_in"]:
                return DetectionResult(
                    triggered=True, rule=rule,
                    score=self._severity_score(rule.severity),
                    reason=f"Suspicious port: {port}",
                    mitre=rule.mitre,
                )

        # ── Rootkit event matching ────────────────────────────────
        if event_type == "rootkit_event":
            method = data.get("detection_method", "")
            if "rootkit_detection_methods" in det:
                if not det["rootkit_detection_methods"] or method in det["rootkit_detection_methods"]:
                    return DetectionResult(
                        triggered=True, rule=rule,
                        score=100,
                        reason=f"Rootkit detection [{method}]: {data.get('description', '')}",
                        mitre=rule.mitre,
                    )
            elif "rootkit" in rule.tags:
                return DetectionResult(
                    triggered=True, rule=rule,
                    score=100,
                    reason=f"Rootkit detection [{method}]: {data.get('description', '')}",
                    mitre=rule.mitre,
                )

        return DetectionResult(triggered=False)

    @staticmethod
    def _severity_score(severity: str) -> int:
        return {
            "info":     10,
            "low":      25,
            "medium":   50,
            "high":     75,
            "critical": 100,
        }.get(severity, 50)
