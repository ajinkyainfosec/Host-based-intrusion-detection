#!/usr/bin/env bash
# scripts/install-server.sh
# Sentinel HIDS — Server Installation Script
# Supports: Ubuntu 22.04 / 24.04, Debian 12
# Run as root: sudo bash install-server.sh

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; AMBER='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${GREEN}[✓]${NC} $*"; }
info()  { echo -e "${BLUE}[i]${NC} $*"; }
warn()  { echo -e "${AMBER}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
hdr()   { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

# ── Root check ──────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Must run as root: sudo bash $0"

# ── Detect OS ───────────────────────────────────────────────────
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    OS_ID="$ID"
    OS_VER="$VERSION_ID"
else
    error "Cannot detect OS. Requires Ubuntu 22.04+ or Debian 12"
fi
info "Detected: $OS_ID $OS_VER"

INSTALL_DIR="/opt/sentinel-hids"
CONFIG_DIR="/etc/sentinel"
LOG_DIR="/var/log/sentinel"
DATA_DIR="/var/lib/sentinel"

hdr "SENTINEL HIDS SERVER INSTALLATION"
echo -e "${BOLD}Installing to: ${INSTALL_DIR}${NC}"
echo ""

# ── 1. System packages ──────────────────────────────────────────
hdr "Step 1: System Packages"
apt-get update -qq
apt-get install -y --no-install-recommends \
    curl wget git ca-certificates gnupg lsb-release \
    openssl ufw fail2ban auditd audispd-plugins \
    python3 python3-pip python3-venv build-essential
log "System packages installed"

# ── 2. Docker ───────────────────────────────────────────────────
hdr "Step 2: Docker"
if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com | bash
    systemctl enable --now docker
    log "Docker installed"
else
    log "Docker already installed: $(docker --version)"
fi

if ! command -v docker &>/dev/null; then
    curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
        -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    log "Docker Compose installed"
fi

# ── 3. Create directories ───────────────────────────────────────
hdr "Step 3: Directory Structure"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
mkdir -p "$INSTALL_DIR/certs" "$INSTALL_DIR/rules/sigma"
mkdir -p "$INSTALL_DIR/docker/postgres" "$INSTALL_DIR/docker/nginx"
log "Directories created"

# ── 4. Generate .env file ───────────────────────────────────────
hdr "Step 4: Environment Configuration"
ENV_FILE="$INSTALL_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    DB_PASSWORD=$(openssl rand -hex 32)
    REDIS_PASSWORD=$(openssl rand -hex 24)
    ELASTIC_PASSWORD=$(openssl rand -hex 24)
    API_KEY=$(openssl rand -hex 32)
    SECRET_KEY=$(openssl rand -hex 64)

    cat > "$ENV_FILE" <<EOF
# Sentinel HIDS — Environment Configuration
# Generated: $(date)
# DO NOT COMMIT THIS FILE TO VERSION CONTROL

DB_PASSWORD=${DB_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}
ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
API_KEY=${API_KEY}
SECRET_KEY=${SECRET_KEY}

# Server
SENTINEL_SERVER_URL=https://localhost
LOG_LEVEL=INFO

# Paths
INSTALL_DIR=${INSTALL_DIR}
CONFIG_DIR=${CONFIG_DIR}
LOG_DIR=${LOG_DIR}
EOF
    chmod 600 "$ENV_FILE"
    log "Environment file created: $ENV_FILE"
    warn "API Key: ${API_KEY} — save this for agent configuration!"
else
    log ".env file already exists — skipping"
fi

# ── 5. TLS Certificates ─────────────────────────────────────────
hdr "Step 5: TLS Certificates"
CERT_DIR="$INSTALL_DIR/certs"
if [[ ! -f "$CERT_DIR/sentinel.crt" ]]; then
    SERVER_IP=$(hostname -I | awk '{print $1}')
    openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
        -keyout "$CERT_DIR/sentinel.key" \
        -out    "$CERT_DIR/sentinel.crt" \
        -subj   "/CN=sentinel-hids/O=SentinelHIDS/C=US" \
        -addext "subjectAltName=IP:${SERVER_IP},IP:127.0.0.1,DNS:localhost" \
        2>/dev/null
    chmod 600 "$CERT_DIR/sentinel.key"
    log "Self-signed TLS certificate generated (10 years)"
    warn "For production: replace with a proper CA-signed certificate"
else
    log "TLS certificates already exist"
fi

# ── 6. Copy project files ───────────────────────────────────────
hdr "Step 6: Project Files"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

if [[ -d "$PROJECT_DIR/server" ]]; then
    cp -r "$PROJECT_DIR/"* "$INSTALL_DIR/" 2>/dev/null || true
    log "Project files copied to $INSTALL_DIR"
else
    warn "Run from project directory. Skipping file copy."
fi

# ── 7. Firewall ─────────────────────────────────────────────────
hdr "Step 7: Firewall (UFW)"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    comment "SSH"
ufw allow 443/tcp   comment "HTTPS — Dashboard + API"
ufw allow 8000/tcp  comment "Sentinel API (agent ingest)"
# Only allow internal network for DB ports
ufw allow from 172.20.0.0/24 comment "Docker internal"
ufw --force enable
log "Firewall configured"

# ── 8. Auditd rules ─────────────────────────────────────────────
hdr "Step 8: Auditd Rules"
cat > /etc/audit/rules.d/sentinel.rules <<'AUDIT'
# Sentinel HIDS — Auditd Rules
# Privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k priv_esc
-w /usr/bin/sudo -p x -k sudo_exec
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d -p wa -k sudoers_change

# File integrity — critical paths
-w /etc/passwd -p wa -k passwd_change
-w /etc/shadow -p wa -k shadow_change
-w /etc/group -p wa -k group_change
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/pam.d -p wa -k pam_change
-w /etc/crontab -p wa -k cron_change
-w /var/spool/cron -p wa -k cron_change
-w /etc/cron.d -p wa -k cron_change

# Module loading (rootkit detection)
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k kernel_module

# Network changes
-a always,exit -F arch=b64 -S socket -S bind -S connect -k network_connect

# Process execution
-a always,exit -F arch=b64 -S execve -k process_exec

# Unauthorized file access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -k unauthorized_access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM  -k unauthorized_access
AUDIT

augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/sentinel.rules 2>/dev/null || true
systemctl enable --now auditd
log "Auditd rules applied"

# ── 9. Fail2ban ─────────────────────────────────────────────────
hdr "Step 9: Fail2ban"
cat > /etc/fail2ban/jail.d/sentinel.conf <<'F2B'
[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 5
bantime  = 3600
findtime = 600

[sentinel-api]
enabled  = false
port     = 8000,443
logpath  = /var/log/nginx/access.log
maxretry = 100
bantime  = 300
F2B
systemctl enable --now fail2ban
log "Fail2ban configured"

# ── 10. Start services ──────────────────────────────────────────
hdr "Step 10: Starting Services"
cd "$INSTALL_DIR"
if [[ -f "docker-compose.yml" ]]; then
    docker compose pull --quiet 2>/dev/null || true
    docker compose up -d
    log "Docker services started"
    sleep 5
    docker compose ps
else
    warn "docker-compose.yml not found in $INSTALL_DIR — start manually"
fi

# ── 11. Systemd service for auto-start ──────────────────────────
hdr "Step 11: Systemd Service"
cat > /etc/systemd/system/sentinel-hids.service <<EOF
[Unit]
Description=Sentinel HIDS Server
Requires=docker.service
After=docker.service network.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sentinel-hids
log "Systemd service registered"

# ── Done ────────────────────────────────────────────────────────
hdr "INSTALLATION COMPLETE"
source "$ENV_FILE"
SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${BOLD}${GREEN}✅ Sentinel HIDS Server is running!${NC}"
echo ""
echo -e "  ${BOLD}Dashboard:${NC}  https://${SERVER_IP}"
echo -e "  ${BOLD}API:${NC}        https://${SERVER_IP}/api/v1"
echo -e "  ${BOLD}Health:${NC}     https://${SERVER_IP}/health"
echo -e "  ${BOLD}WebSocket:${NC}  wss://${SERVER_IP}/ws/events"
echo ""
echo -e "${BOLD}Agent Configuration:${NC}"
echo -e "  SENTINEL_SERVER_URL = https://${SERVER_IP}"
echo -e "  SENTINEL_API_KEY    = ${API_KEY}"
echo ""
echo -e "${AMBER}⚠  Store the API key securely — it cannot be recovered${NC}"
echo -e "${AMBER}⚠  Replace the self-signed TLS cert before production use${NC}"
echo -e "${AMBER}⚠  Change the default admin password immediately${NC}"
echo ""
