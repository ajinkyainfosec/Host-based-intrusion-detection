# 📝 Changelog — Sentinel HIDS

All notable changes to Sentinel HIDS are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.0.0] — 2026-03-30

### Added
- PostgreSQL persistent storage for all alerts, events, and agents
- Multi-host support with host filter pills in dashboard
- Advanced Event Search tab with 5 filters and pagination
- Login Geo Map with D3.js + TopoJSON world map
- 6 Incident Response Playbooks with step-by-step remediation
- PDF Report Generator with live data and CSV export
- Dynamic rootkit module baseline (waits for system to stabilise)
- Attack chain correlation (4 multi-stage attack patterns)
- Host risk escalation (severity bumped on sustained attacks)
- Alert deduplication (5-minute suppression window)
- MTTD and MTTR metrics with real timestamp calculation
- Risk score that decays as alerts are resolved
- `db/store.py` persistence layer for all database operations
- Nanosecond timestamp handling from Rust agent

### Fixed
- False positives from Docker kernel module loading (inet_diag, tcp_diag, tls)
- Rootkit detector thread vs process discrimination (Pid != Tgid check)
- Risk score always showing 100 regardless of alert status
- MTTD/MTTR showing blank when no closed alerts
- Live alert feed showing historical alerts on page load
- FIM panel showing "No FIM changes" due to wrong tag filter
- Login validation — dashboard was accessible with any API key
- IPv4 address parsing (little-endian byte order fix)
- Nginx CSP header blocking Google Fonts

### Changed
- Agent send interval reduced from 2000ms to 500ms
- Process scan interval reduced from 10s to 2s
- Network scan interval reduced from 15s to 3s
- Rootkit startup delay replaced with dynamic stability check
- Dashboard redesigned as Sentinel HIDS v2 with dark/light theme
- Alert feed now shows only live WebSocket alerts (not historical)
- Safe module list expanded to 40+ entries

---

## [1.5.0] — 2026-02-15

### Added
- Rootkit detector v3 with race condition fix (3-second stability window)
- Double-snapshot process detection to eliminate timing false positives
- Disk backup queue for events during server downtime
- Kill chain attack correlation (Brute Force → Priv Esc, Web Shell → C2)
- Scoreboard tab with analyst leaderboard
- Heatmap tab with 30-day alert activity calendar
- Correlation tab with D3.js force-directed graph
- Response Actions tab with 8 one-click actions

### Fixed
- Agent memory spike during FIM scan (exclusion paths expanded)
- Duplicate brute force alerts (YAML + builtin rules both firing)
- Double rootkit alert from veth module (SENT-EVA-003 removed)

---

## [1.0.0] — 2026-01-20

### Added
- Initial release of Sentinel HIDS
- Rust agent with 5 collectors (FIM, process, network, auth, rootkit)
- Python FastAPI server with event ingest pipeline
- 17 Sigma-compatible detection rules mapped to MITRE ATT&CK
- Real-time SOC dashboard with WebSocket streaming
- Overview, MITRE ATT&CK, Kill Chain, Agents, Triage, Response tabs
- JWT authentication for dashboard
- Docker Compose deployment
- SHA-256 File Integrity Monitoring
- SSH brute force detection
- Privilege escalation detection (sudo)
- Reverse shell detection
- C2 beacon detection
- Rootkit detection (4 techniques)
- In-memory storage (PostgreSQL not yet connected)
