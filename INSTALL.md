# 📦 Installation Guide — Sentinel HIDS

## Table of Contents
- [Prerequisites](#prerequisites)
- [Server Installation](#server-installation)
- [Agent Installation](#agent-installation)
- [Dashboard Access](#dashboard-access)
- [Multi-Host Setup](#multi-host-setup)
- [Verification](#verification)
- [Uninstall](#uninstall)

---

## Prerequisites

### Server Requirements
| Requirement | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 20.04 LTS | Ubuntu 22.04 LTS |
| RAM | 2 GB | 4 GB |
| CPU | 2 cores | 4 cores |
| Disk | 10 GB | 50 GB |
| Docker | 24.0+ | latest |
| Docker Compose | 2.0+ | latest |

### Agent Requirements
| Requirement | Value |
|---|---|
| OS | Linux (Ubuntu/Debian/CentOS) |
| RAM | 50 MB |
| CPU | < 1% idle |
| Rust | 1.75+ (for building) |

---

## Server Installation

### Step 1 — Install Docker

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker --version
docker compose version
```

### Step 2 — Clone repository

```bash
git clone https://github.com/yourusername/sentinel-hids.git
sudo cp -r sentinel-hids /opt/hids
cd /opt/hids
```

### Step 3 — Configure environment

```bash
cp .env.example .env
nano .env
```

Edit the following values in `.env`:

```env
# Server
API_KEY=your-strong-api-key-here
SERVER_URL=http://your-server-ip:8000

# Database
POSTGRES_DB=sentinel
POSTGRES_USER=sentinel
POSTGRES_PASSWORD=your-strong-password

# JWT
JWT_SECRET=your-jwt-secret-key
```

### Step 4 — Start the server stack

```bash
cd /opt/hids
docker compose up -d

# Check all containers are running
docker compose ps
```

Expected output:
```
NAME                 STATUS
sentinel-server      running
sentinel-postgres    running
sentinel-redis       running
sentinel-nginx       running
```

### Step 5 — Verify server is running

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "ok",
  "rules": 17,
  "agents": 0,
  "alerts": 0
}
```

---

## Agent Installation

### Step 1 — Install Rust (on agent host)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustc --version
```

### Step 2 — Build the agent

```bash
cd /opt/hids/agent
cargo build --release

# Binary is at:
ls -lh target/release/sentinel-agent
```

### Step 3 — Install the agent

```bash
# Copy binary
sudo cp target/release/sentinel-agent /usr/local/bin/sentinel-agent
sudo chmod 755 /usr/local/bin/sentinel-agent

# Create config directory
sudo mkdir -p /etc/sentinel
```

### Step 4 — Configure the agent

```bash
sudo tee /etc/sentinel/agent.json << 'EOF'
{
  "agent_id": "REPLACE-WITH-UUID",
  "hostname": "your-hostname",
  "server_url": "http://YOUR-SERVER-IP:8000",
  "api_key": "YOUR-API-KEY",
  "batch_size": 100,
  "send_interval_ms": 500,
  "fim_watch_paths": ["/etc", "/usr/bin", "/usr/sbin", "/boot", "/root"],
  "fim_exclude_paths": [
    "/etc/mtab", "/etc/resolv.conf", "/proc", "/sys", "/run", "/tmp",
    "/var/lib/dpkg", "/var/lib/apt", "/var/cache"
  ],
  "fim_interval_secs": 60,
  "proc_scan_interval_secs": 2,
  "suspicious_paths": ["/tmp", "/dev/shm", "/var/tmp"],
  "suspicious_comms": ["nc", "nmap", "hydra", "xmrig", "msfconsole"],
  "net_scan_interval_secs": 3,
  "known_bad_ips": [],
  "suspicious_ports": [4444, 5555, 1337, 31337, 6666, 6667, 9001, 9050],
  "auth_log_path": "/var/log/auth.log",
  "max_failed_logins": 5
}
EOF
```

Generate a unique agent ID:
```bash
python3 -c "import uuid; print(uuid.uuid4())"
# Replace REPLACE-WITH-UUID in the config with this value
sudo nano /etc/sentinel/agent.json
```

### Step 5 — Install systemd service

```bash
sudo tee /etc/systemd/system/sentinel-agent.service << 'EOF'
[Unit]
Description=Sentinel HIDS Agent
Documentation=https://github.com/yourusername/sentinel-hids
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinel-agent
Restart=always
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinel-agent

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable sentinel-agent
sudo systemctl start sentinel-agent
```

### Step 6 — Verify agent is running

```bash
sudo systemctl status sentinel-agent --no-pager

# Watch live logs
sudo journalctl -u sentinel-agent -f --no-pager
```

Expected output:
```
INFO Sentinel Agent starting — agent_id=xxxx hostname=ubuntu
INFO FIM: baseline built — 2400 files indexed
INFO Rootkit detector started — waiting for module list to stabilise...
INFO Rootkit: module list stable — taking baseline
INFO ♥ Heartbeat — agent alive
INFO Sent 5 events to server
```

---

## Dashboard Access

Open your browser and navigate to:

```
http://your-server-ip
```

Login with:
- **Server URL**: `http://your-server-ip:8000`
- **Username**: `admin`
- **API Key / Password**: the `API_KEY` from your `.env` file

---

## Multi-Host Setup

To monitor additional Linux hosts, repeat the **Agent Installation** steps on each host with:

1. A **unique** `agent_id` (generate new UUID for each host)
2. The **same** `server_url` and `api_key`
3. A different `hostname`

The dashboard automatically detects new agents and shows them in the host selector.

---

## Verification

Run these commands to verify everything is working:

```bash
# Check server health
curl -s http://localhost:8000/health | python3 -m json.tool

# Check agents registered
API_KEY=$(cat /etc/sentinel/agent.json | python3 -c \
  'import sys,json; print(json.load(sys.stdin)["api_key"])')
curl -s http://localhost:8000/api/v1/agents \
  -H "Authorization: Bearer $API_KEY" | python3 -m json.tool

# Check alerts in database
docker compose exec postgres psql -U sentinel -d sentinel \
  -c "SELECT severity, COUNT(*) FROM alerts GROUP BY severity;"

# Test FIM detection
sudo touch /etc/sentinel-test.txt
sleep 65
sudo rm /etc/sentinel-test.txt
```

---

## Uninstall

### Remove agent

```bash
sudo systemctl stop sentinel-agent
sudo systemctl disable sentinel-agent
sudo rm /etc/systemd/system/sentinel-agent.service
sudo rm /usr/local/bin/sentinel-agent
sudo rm -rf /etc/sentinel
sudo systemctl daemon-reload
```

### Remove server stack

```bash
cd /opt/hids
docker compose down -v    # -v removes all data volumes
sudo rm -rf /opt/hids
```
