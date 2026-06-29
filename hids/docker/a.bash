# Apply fix — replace save_alert INSERT with new version
docker compose exec server python3 << 'PYEOF'
import re

with open('/app/db/store.py', 'r') as f:
    content = f.read()

# Find and replace the INSERT INTO alerts block
old_insert = """                INSERT INTO alerts (
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
                    assigned_to = EXCLUDED.assigned_to"""

new_insert = """                INSERT INTO alerts (
                    alert_id, agent_id, rule_id, rule_title,
                    hostname, severity, score, status, reason,
                    mitre_id, mitre_tactic, mitre_name,
                    event_subtype, event_data, assigned_to,
                    tags, incident_id, created_at
                ) VALUES (
                    :alert_id, :agent_id, :rule_id, :rule_title,
                    :hostname, :severity, :score, :status, :reason,
                    :mitre_id, :mitre_tactic, :mitre_name,
                    :event_subtype, :event_data ::jsonb, :assigned_to,
                    :tags, :incident_id, :created_at
                )
                ON CONFLICT (alert_id) DO UPDATE SET
                    status      = EXCLUDED.status,
                    assigned_to = EXCLUDED.assigned_to,
                    mitre_name  = EXCLUDED.mitre_name,
                    tags        = EXCLUDED.tags,
                    incident_id = EXCLUDED.incident_id"""

if old_insert in content:
    content = content.replace(old_insert, new_insert)
    print("INSERT block replaced successfully")
else:
    print("ERROR: INSERT block not found - check spacing")

# Fix the params dict - add missing fields
old_params = '''                "alert_id":     str(alert.get("alert_id")     or uuid.uuid4()),
                "rule_id":      str(alert.get("rule_id")      or ""),
                "rule_title":   str(alert.get("rule_title")   or ""),
                "hostname":     str(alert.get("hostname")     or ""),
                "severity":     str(alert.get("severity")     or "INFO"),
                "score":        int(alert.get("score")        or 0),
                "status":       str(alert.get("status")       or "new"),'''

new_params = '''                "alert_id":     str(alert.get("alert_id")     or uuid.uuid4()),
                "agent_id":     str(alert.get("agent_id")     or ""),
                "rule_id":      str(alert.get("rule_id")      or ""),
                "rule_title":   str(alert.get("rule_title")   or ""),
                "hostname":     str(alert.get("hostname")     or ""),
                "severity":     str(alert.get("severity")     or "INFO"),
                "score":        int(alert.get("score")        or 0),
                "status":       str(alert.get("status")       or "new"),'''

if old_params in content:
    content = content.replace(old_params, new_params)
    print("Params block replaced successfully")
else:
    print("ERROR: Params block not found")

with open('/app/db/store.py', 'w') as f:
    f.write(content)
print("store.py saved")
PYEOF
