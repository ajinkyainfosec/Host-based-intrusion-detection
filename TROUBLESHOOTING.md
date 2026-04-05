# 🔧 Troubleshooting Guide — Sentinel HIDS

## Common Issues

---

### Agent not sending events

**Symptom:** Agent logs show `Send failed` or `operation timed out`

**Cause:** Server IP changed or server is down

**Fix:**
```bash
# Check server URL in agent config
cat /etc/sentinel/agent.json | python3 -c \
  'import sys,json; print(json.load(sys.stdin)["server_url"])'

# Update IP if changed
sudo sed -i 's/OLD-IP/NEW-IP/g' /etc/sentinel/agent.json
sudo systemctl restart sentinel-agent

# Verify server is reachable
curl http://YOUR-SERVER-IP:8000/health
```

---

### Rootkit false positives (inet_diag, tcp_diag, tls)

**Symptom:** Many CRITICAL rootkit alerts for legitimate kernel modules

**Cause:** Agent took baseline before all modules finished loading

**Fix:**
```bash
# Rebuild agent with dynamic stability check
cd /opt/hids/agent
cargo build --release
sudo systemctl stop sentinel-agent
sudo install -m755 target/release/sentinel-agent /usr/local/bin/
sudo systemctl start sentinel-agent

# Delete existing false positive alerts
docker compose exec postgres psql -U sentinel -d sentinel -c "
DELETE FROM alerts
WHERE rule_id = 'SENT-RK-001'
AND reason LIKE '%New kernel module loaded after startup%';"
```

---

### Dashboard shows no alerts after server restart

**Symptom:** Dashboard is empty even though alerts exist in database

**Cause:** `alerts.py` was reading from memory only

**Fix:** Ensure you have the latest `alerts.py` which reads from PostgreSQL:
```bash
docker exec sentinel-server grep -n "load_alerts" /app/api/alerts.py
# Should show: "from db.store import load_alerts as pg_load_alerts"
```

---

### Database tables not created

**Symptom:** `ERROR: relation "alerts" does not exist`

**Cause:** `database.py` not initialising tables correctly

**Fix:**
```bash
# Check server logs for DB errors
docker compose logs server | grep -E "ERROR|postgres|database"

# Manually check tables
docker compose exec postgres psql -U sentinel -d sentinel -c "\dt"
```

---

### Login fails with valid API key

**Symptom:** Dashboard shows "Invalid API key" even with correct key

**Cause:** Server unreachable or API key mismatch

**Fix:**
```bash
# Test API key directly
curl -s http://localhost:8000/health \
  -H "Authorization: Bearer YOUR-API-KEY"

# Check server is running
docker compose ps
docker compose logs server --tail=20
```

---

### FIM panel shows "No FIM changes"

**Symptom:** File changes not appearing in FIM panel

**Cause:** FIM alerts have different tags than expected

**Fix:** Trigger a test change and verify:
```bash
sudo touch /etc/fim-test.txt
sleep 65
sudo rm /etc/fim-test.txt

# Check if FIM alert was generated
API_KEY=$(cat /etc/sentinel/agent.json | python3 -c \
  'import sys,json; print(json.load(sys.stdin)["api_key"])')
curl -s "http://localhost:8000/api/v1/alerts?limit=5" \
  -H "Authorization: Bearer $API_KEY" | \
  python3 -c "import sys,json; \
  [print(a['rule_id'], a['reason']) for a in json.load(sys.stdin)['alerts'] \
  if 'FIM' in a.get('rule_id','')]"
```

---

### High memory usage on agent host

**Symptom:** Agent using 200MB+ RAM

**Cause:** FIM baseline too large (too many watched files)

**Fix:** Add more exclusion paths to `agent.json`:
```json
"fim_exclude_paths": [
  "/etc/mtab", "/etc/resolv.conf",
  "/usr/share/locale", "/usr/share/doc",
  "/usr/share/man", "/usr/share/info",
  "/usr/share/zoneinfo", "/usr/lib/locale",
  "/var/lib/dpkg", "/var/lib/apt",
  "/var/cache", "/proc", "/sys", "/run", "/tmp"
]
```

---

### Compile errors in rootkit.rs

**Symptom:** `cargo build` fails with `E0502` borrow checker error

**Cause:** Ownership issue with `HashSet` comparison

**Fix:** Use the stable check approach:
```rust
let curr = read_loaded_modules();
if curr == prev {
    break;
}
prev = curr;   // move curr into prev — don't use curr after this
```

---

### WebSocket disconnects frequently

**Symptom:** Dashboard shows `RECONNECTING` repeatedly

**Cause:** Nginx timeout too short for WebSocket connections

**Fix:** Add to Nginx config:
```nginx
location /ws/ {
    proxy_pass http://server:8000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 3600s;    # 1 hour timeout
    proxy_send_timeout 3600s;
}
```

---

## Useful Debug Commands

```bash
# Agent status and recent logs
sudo systemctl status sentinel-agent --no-pager
sudo journalctl -u sentinel-agent -n 50 --no-pager

# Server logs
docker compose logs server --tail=30

# Database contents
docker compose exec postgres psql -U sentinel -d sentinel \
  -c "SELECT severity, COUNT(*) FROM alerts GROUP BY severity;"

# Check all containers
docker compose ps
docker compose stats --no-stream

# Server health
curl -s http://localhost:8000/health | python3 -m json.tool

# Test detection (triggers sudo alert)
sudo ls /root
```
