# 🛡 Sentinel HIDS — Host-Based Intrusion Detection System

**Production-grade, multi-agent HIDS for Linux.**  
Detects threats in real-time across your entire fleet and streams alerts to your dashboard.

---

## Architecture

```
[Linux Hosts]                    [Central Server]
  Agent (Rust)  ──gRPC/HTTPS──▶  FastAPI Ingest
  ├─ FIM (inotify + SHA256)        │
  ├─ Process Monitor (/proc)       ▼
  ├─ Network Monitor (/proc/net) Detection Engine
  ├─ Auth Monitor (auth.log)       │  (Sigma Rules)
  └─ Syscall (auditd)              ▼
                                PostgreSQL + Redis
                                   │
                                   ▼ WebSocket
                                Dashboard (Your HTML)
```

---

## Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Agent** | Rust | Lightweight, safe, single binary per host |
| **Backend** | Python FastAPI | Event ingest, REST API, WebSocket |
| **Detection** | Sigma rules (YAML) | Industry-standard rule format |
| **Database** | PostgreSQL + TimescaleDB | Incidents, alerts, baselines |
| **Cache** | Redis | Live agent state, session data |
| **Search** | Elasticsearch | Full-text log search |
| **Proxy** | Nginx | TLS termination, rate limiting |
| **Container** | Docker Compose | Service orchestration |
| **Monitoring** | Prometheus | Server-side metrics |

---

## Quick Start

### 1. Server Setup (Ubuntu 22.04+)

```bash
git clone https://github.com/your-org/sentinel-hids
cd sentinel-hids

# Install everything (Docker, Postgres, Redis, Nginx, certs)
sudo bash scripts/install-server.sh
```

The script will:
- Install Docker and all dependencies
- Generate random secrets and TLS certificate
- Configure firewall (UFW) and fail2ban
- Start all services via Docker Compose
- Print your API key for agent configuration

### 2. Agent Setup (each Linux host)

```bash
# On every host you want to protect:
export SENTINEL_SERVER_URL=https://YOUR_SERVER_IP
export SENTINEL_API_KEY=YOUR_API_KEY_FROM_STEP_1

sudo bash scripts/install-agent.sh
```

The agent will start monitoring immediately and appear in your dashboard.

### 3. Dashboard

Open your browser to `https://YOUR_SERVER_IP`  
The dashboard connects via WebSocket and shows live alerts.

---

## Project Structure

```
sentinel-hids/
├── agent/                    # Rust agent (runs on every Linux host)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs           # Entry point — spawns all collectors
│       ├── models.rs         # Event types (FIM, Process, Network, Auth)
│       ├── config.rs         # Agent configuration
│       ├── fim.rs            # File Integrity Monitor (SHA256 + inotify)
│       ├── process.rs        # Process monitor (/proc scanning)
│       ├── network.rs        # Network monitor (/proc/net/tcp)
│       ├── auth.rs           # Auth log monitor (auth.log tailing)
│       └── sender.rs         # Batched event sender with retry
│
├── server/                   # Python FastAPI backend
│   ├── main.py               # Application entry point
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── api/
│   │   ├── events.py         # POST /api/v1/events (agent ingest)
│   │   ├── alerts.py         # Alert CRUD endpoints
│   │   ├── agents.py         # Agent registry endpoints
│   │   ├── auth.py           # JWT authentication
│   │   └── ws.py             # WebSocket live feed
│   ├── detection/
│   │   └── engine.py         # Sigma rule loader + event matcher
│   ├── ingest/
│   │   └── processor.py      # Async event processor + WS broadcaster
│   └── db/
│       └── database.py       # Database connection
│
├── rules/sigma/              # Detection rules (Sigma format YAML)
│   └── linux_rules.yml       # 9 built-in rules
│
├── dashboard/                # Your HTML dashboard (place hids_ultimate.html here)
│
├── docker/
│   ├── postgres/init.sql     # Full database schema
│   ├── nginx/nginx.conf      # Rate limiting config
│   └── nginx/sentinel.conf   # Reverse proxy + TLS config
│
├── scripts/
│   ├── install-server.sh     # Full server installation
│   └── install-agent.sh      # Per-host agent installation
│
├── docker-compose.yml        # Full stack orchestration
├── .env.example              # Environment variable template
└── README.md
```

---

## Detection Rules

Rules are YAML files in `rules/sigma/`. Add your own:

```yaml
title: My Custom Rule
id: CUSTOM-001
severity: high        # critical / high / medium / low
tags:
  - persistence
mitre:
  tactic: Persistence
  technique_id: T1053
  technique: Scheduled Task/Job
detection:
  file_path_contains:
    - "/etc/cron.d/suspicious"
  cmdline_contains:
    - "wget http://"
```

---

## Built-in Detection Rules

| Rule ID | Title | Severity | MITRE |
|---|---|---|---|
| SENT-RS-001 | Reverse Shell Detection | Critical | T1059 |
| SENT-PE-001 | Privilege Escalation via Sudo | High | T1548 |
| SENT-RK-001 | Rootkit — Hidden Process | Critical | T1014 |
| SENT-FIM-001 | Critical System File Modified | Critical | T1036 |
| SENT-PERS-001 | Persistence via Cron | High | T1053 |
| SENT-AUTH-001 | SSH Brute Force | High | T1110 |
| SENT-NET-001 | C2 Beacon Connection | Critical | T1071 |
| SENT-PERS-002 | New User Account Created | High | T1136 |
| SENT-EVA-001 | Base64 Encoded Execution | High | T1027 |

---

## What the Agent Monitors

### File Integrity Monitor (FIM)
- Watches: `/etc`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/boot`, `/root`, `/var/spool/cron`
- Detects: file created, modified, deleted, hash changed, permission changed
- Method: SHA-256 hash comparison every 30 seconds

### Process Monitor
- Scans `/proc` every 5 seconds
- Detects: execution from `/tmp`/`/dev/shm`, reverse shell patterns,
  suspicious process names, root processes from unusual paths, kernel thread impersonation

### Network Monitor
- Reads `/proc/net/tcp` and `/proc/net/udp` every 10 seconds
- Detects: connections to known bad IPs, C2 ports (4444, 1337, etc.),
  Tor connections, IRC channels, suspicious listeners

### Auth Monitor
- Tails `/var/log/auth.log` in real-time (2s polling)
- Detects: SSH brute force, successful root logins, sudo abuse,
  new user creation, password changes, SSH key additions

---

## API Reference

```
POST /api/v1/events          # Agent event ingest (requires Bearer token)
GET  /api/v1/events          # Query events
GET  /api/v1/events/stats    # Processing statistics

GET  /api/v1/alerts          # List alerts
PATCH /api/v1/alerts/{id}/acknowledge
PATCH /api/v1/alerts/{id}/close

GET  /api/v1/agents          # List registered agents
GET  /api/v1/agents/{id}     # Single agent detail
POST /api/v1/agents/{id}/heartbeat

WS   /ws/events              # Live alert + event stream (dashboard)

POST /api/v1/auth/token      # Get JWT token
GET  /health                 # Health check
```

---

## Connecting the Dashboard

In your `hids_ultimate_dashboard.html`, replace the simulated data with real WebSocket:

```javascript
const ws = new WebSocket('wss://YOUR_SERVER/ws/events');

ws.onmessage = (msg) => {
  const data = JSON.parse(msg.data);
  if (data.type === 'alert') {
    // Add to alert feed
    addAlertToFeed(data.payload);
  } else if (data.type === 'event') {
    // Add to live log
    addToLog(data.payload);
  }
};

// Keep alive
setInterval(() => ws.send('ping'), 30000);
```

---

## Security Hardening Checklist

- [ ] Change default API key in `.env`
- [ ] Replace self-signed TLS certificate with CA-signed cert
- [ ] Change default admin password
- [ ] Enable PostgreSQL SSL connections
- [ ] Set up log rotation for `/var/log/sentinel/`
- [ ] Configure backup for PostgreSQL data
- [ ] Review and tighten UFW firewall rules
- [ ] Enable Elasticsearch authentication in production
- [ ] Set up alerting (email/Slack/PagerDuty) on CRITICAL alerts
- [ ] Test agent on a staging host before production rollout
- [ ] Verify auditd rules are loaded: `auditctl -l`

---

## Troubleshooting

**Agent not starting:**
```bash
journalctl -u sentinel-agent -n 100
systemctl status sentinel-agent
```

**Agent not sending events:**
```bash
# Test connectivity
curl -sk https://YOUR_SERVER/health

# Check agent config
cat /etc/sentinel/agent.json

# Watch agent logs live
journalctl -u sentinel-agent -f
```

**No alerts appearing:**
```bash
# Check server logs
docker compose logs server -f

# Check event stats
curl http://localhost:8000/api/v1/events/stats
```

**Database connection issues:**
```bash
docker compose ps
docker compose logs postgres
docker compose restart postgres
```

---

## License

MIT — for educational and organizational security use.  
Not a substitute for professional security services.
