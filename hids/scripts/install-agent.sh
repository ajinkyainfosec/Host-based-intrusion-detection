#!/usr/bin/env bash
# scripts/install-agent.sh
# Sentinel HIDS — Agent Installation Script
# Run on each Linux host you want to protect
# Usage: sudo SENTINEL_SERVER_URL=https://x.x.x.x SENTINEL_API_KEY=xxx bash install-agent.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; AMBER='\033[0;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${GREEN}[✓]${NC} $*"; }
info()  { echo -e "${BLUE}[i]${NC} $*"; }
warn()  { echo -e "${AMBER}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
hdr()   { echo -e "\n${BOLD}══ $* ══${NC}"; }

[[ $EUID -ne 0 ]] && error "Must run as root: sudo bash $0"

# ── Required variables ──────────────────────────────────────────
SERVER_URL="${SENTINEL_SERVER_URL:-}"
API_KEY="${SENTINEL_API_KEY:-}"

[[ -z "$SERVER_URL" ]] && error "Set SENTINEL_SERVER_URL=https://your-server"
[[ -z "$API_KEY"    ]] && error "Set SENTINEL_API_KEY=your-api-key"

AGENT_VERSION="1.0.0"
INSTALL_DIR="/opt/sentinel-agent"
CONFIG_DIR="/etc/sentinel"
LOG_DIR="/var/log/sentinel"
AGENT_BIN="/usr/local/bin/sentinel-agent"
AGENT_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)
HOSTNAME=$(hostname -f)

hdr "SENTINEL HIDS AGENT INSTALLATION"
info "Server   : $SERVER_URL"
info "Hostname : $HOSTNAME"
info "Agent ID : $AGENT_ID"

# ── 1. Dependencies ─────────────────────────────────────────────
hdr "Step 1: Dependencies"
apt-get update -qq 2>/dev/null || yum update -q 2>/dev/null || true
apt-get install -y --no-install-recommends \
    curl ca-certificates auditd libaudit1 inotify-tools 2>/dev/null || \
yum install -y curl ca-certificates audit inotify-tools 2>/dev/null || true
log "Dependencies installed"

# ── 2. Install Rust + build agent ───────────────────────────────
hdr "Step 2: Build Agent (Rust)"
if ! command -v cargo &>/dev/null; then
    info "Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable --profile minimal
    source "$HOME/.cargo/env"
    log "Rust installed: $(rustc --version)"
else
    log "Rust already available: $(rustc --version)"
fi

# Build the agent
if [[ -d "$(dirname "$0")/../agent" ]]; then
    info "Building agent from source..."
    cd "$(dirname "$0")/../agent"
    cargo build --release 2>&1 | tail -5
    cp target/release/sentinel-agent "$AGENT_BIN"
    chmod 755 "$AGENT_BIN"
    log "Agent binary built and installed: $AGENT_BIN"
else
    warn "Agent source not found. Place sentinel-agent binary manually at $AGENT_BIN"
fi

# ── 3. Create directories ───────────────────────────────────────
hdr "Step 3: Directories"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
log "Directories created"

# ── 4. Agent configuration ──────────────────────────────────────
hdr "Step 4: Configuration"
cat > "$CONFIG_DIR/agent.json" <<EOF
{
  "agent_id":              "${AGENT_ID}",
  "hostname":              "${HOSTNAME}",
  "server_url":            "${SERVER_URL}",
  "api_key":               "${API_KEY}",
  "batch_size":            100,
  "send_interval_ms":      2000,
  "fim_watch_paths": [
    "/etc", "/usr/bin", "/usr/sbin", "/usr/lib",
    "/boot", "/root", "/var/spool/cron"
  ],
  "fim_exclude_paths": [
    "/etc/mtab", "/etc/resolv.conf", "/etc/machine-id"
  ],
  "fim_interval_secs":         30,
  "proc_scan_interval_secs":    5,
  "suspicious_paths":     ["/tmp", "/dev/shm", "/var/tmp", "/run/shm"],
  "suspicious_comms":     ["nc", "ncat", "netcat", "nmap", "hydra", "masscan"],
  "net_scan_interval_secs":    10,
  "known_bad_ips":        [],
  "suspicious_ports":     [4444, 5555, 1337, 31337, 6666, 6667, 9001],
  "auth_log_path":        "/var/log/auth.log",
  "max_failed_logins":     5
}
EOF
chmod 600 "$CONFIG_DIR/agent.json"
log "Configuration written: $CONFIG_DIR/agent.json"

# ── 5. Systemd service ──────────────────────────────────────────
hdr "Step 5: Systemd Service"
cat > /etc/systemd/system/sentinel-agent.service <<EOF
[Unit]
Description=Sentinel HIDS Agent
After=network.target auditd.service
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${AGENT_BIN}
Restart=always
RestartSec=5s
Environment=SENTINEL_CONFIG=${CONFIG_DIR}/agent.json
Environment=RUST_LOG=sentinel_agent=info
Environment=RUST_BACKTRACE=1
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinel-agent

# Security hardening
NoNewPrivileges=no
ProtectSystem=no
ReadWritePaths=${LOG_DIR}

# Resource limits
LimitNOFILE=65536
MemoryMax=256M
CPUQuota=10%

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sentinel-agent
systemctl start sentinel-agent
sleep 2

if systemctl is-active --quiet sentinel-agent; then
    log "Agent service started successfully"
else
    warn "Agent service failed to start — check: journalctl -u sentinel-agent -n 50"
fi

# ── 6. Verify connectivity ──────────────────────────────────────
hdr "Step 6: Server Connectivity"
if curl -sk "$SERVER_URL/health" | grep -q "ok"; then
    log "Server reachable: $SERVER_URL/health"
else
    warn "Cannot reach server at $SERVER_URL — check network/firewall"
fi

# ── Done ────────────────────────────────────────────────────────
hdr "AGENT INSTALLATION COMPLETE"
echo ""
echo -e "${GREEN}${BOLD}✅ Sentinel HIDS Agent is running on $HOSTNAME${NC}"
echo ""
echo -e "  ${BOLD}Status:${NC}  systemctl status sentinel-agent"
echo -e "  ${BOLD}Logs:${NC}    journalctl -u sentinel-agent -f"
echo -e "  ${BOLD}Config:${NC}  $CONFIG_DIR/agent.json"
echo -e "  ${BOLD}Agent ID:${NC} $AGENT_ID"
echo ""
