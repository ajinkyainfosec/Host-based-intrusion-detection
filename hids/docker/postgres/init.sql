-- docker/postgres/init.sql
-- Sentinel HIDS Database Schema

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- fast text search

-- ── Agents ────────────────────────────────────────────────────
CREATE TABLE agents (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id      TEXT UNIQUE NOT NULL,
    hostname      TEXT NOT NULL,
    ip_address    TEXT,
    os_name       TEXT,
    os_version    TEXT,
    agent_version TEXT,
    status        TEXT DEFAULT 'unknown',   -- online / degraded / offline
    last_seen     TIMESTAMPTZ,
    cpu_pct       REAL DEFAULT 0,
    mem_pct       REAL DEFAULT 0,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_agents_hostname ON agents(hostname);
CREATE INDEX idx_agents_status   ON agents(status);

-- ── Raw Events ────────────────────────────────────────────────
CREATE TABLE events (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id    TEXT UNIQUE NOT NULL,
    agent_id    TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    hostname    TEXT NOT NULL,
    timestamp   TIMESTAMPTZ NOT NULL,
    event_type  TEXT NOT NULL,   -- file_event / process_event / network_event / auth_event / rootkit_event
    severity    TEXT NOT NULL,
    data        JSONB NOT NULL,
    tags        TEXT[] DEFAULT '{}',
    mitre_id    TEXT,
    mitre_tactic TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_events_agent_id   ON events(agent_id);
CREATE INDEX idx_events_hostname   ON events(hostname);
CREATE INDEX idx_events_timestamp  ON events(timestamp DESC);
CREATE INDEX idx_events_type       ON events(event_type);
CREATE INDEX idx_events_severity   ON events(severity);
CREATE INDEX idx_events_data       ON events USING GIN(data);
CREATE INDEX idx_events_tags       ON events USING GIN(tags);

-- ── Alerts ────────────────────────────────────────────────────
CREATE TABLE alerts (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id     TEXT UNIQUE NOT NULL,
    event_id     TEXT,
    agent_id     TEXT NOT NULL,
    hostname     TEXT NOT NULL,
    timestamp    TIMESTAMPTZ NOT NULL,
    rule_id      TEXT NOT NULL,
    rule_title   TEXT NOT NULL,
    severity     TEXT NOT NULL,   -- CRITICAL / HIGH / MEDIUM / LOW
    score        INTEGER DEFAULT 0,
    reason       TEXT,
    mitre_id     TEXT,
    mitre_tactic TEXT,
    mitre_name   TEXT,
    event_subtype TEXT,          -- rootkit_hidden_process / rootkit_kernel_module / fim_file_event / etc.
    tags         TEXT[] DEFAULT '{}',
    event_data   JSONB,
    status       TEXT DEFAULT 'new',   -- new / investigating / contained / closed
    assigned_to  TEXT,
    acknowledged_at TIMESTAMPTZ,
    closed_at    TIMESTAMPTZ,
    notes        TEXT,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_alerts_agent_id  ON alerts(agent_id);
CREATE INDEX idx_alerts_hostname  ON alerts(hostname);
CREATE INDEX idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX idx_alerts_severity  ON alerts(severity);
CREATE INDEX idx_alerts_status    ON alerts(status);
CREATE INDEX idx_alerts_rule_id   ON alerts(rule_id);
CREATE INDEX idx_alerts_mitre_id  ON alerts(mitre_id);

-- ── File Integrity Baseline ────────────────────────────────────
CREATE TABLE fim_baseline (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id    TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    size        BIGINT,
    uid         INTEGER,
    gid         INTEGER,
    mode        INTEGER,
    recorded_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(agent_id, path)
);

CREATE INDEX idx_fim_agent_path ON fim_baseline(agent_id, path);

-- ── FIM Change Log ────────────────────────────────────────────
CREATE TABLE fim_changes (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id    TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    path        TEXT NOT NULL,
    action      TEXT NOT NULL,   -- created / modified / deleted / hash_changed / perm_changed
    old_sha256  TEXT,
    new_sha256  TEXT,
    old_mode    INTEGER,
    new_mode    INTEGER,
    uid         INTEGER,
    gid         INTEGER,
    detected_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_fim_changes_agent   ON fim_changes(agent_id);
CREATE INDEX idx_fim_changes_path    ON fim_changes(path);
CREATE INDEX idx_fim_changes_detected ON fim_changes(detected_at DESC);

-- ── Detection Rules ───────────────────────────────────────────
CREATE TABLE detection_rules (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id     TEXT UNIQUE NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    severity    TEXT NOT NULL,
    enabled     BOOLEAN DEFAULT TRUE,
    tags        TEXT[] DEFAULT '{}',
    mitre_id    TEXT,
    mitre_tactic TEXT,
    detection   JSONB NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── Analysts / Users ──────────────────────────────────────────
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username      TEXT UNIQUE NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT DEFAULT 'analyst',   -- admin / analyst / viewer
    is_active     BOOLEAN DEFAULT TRUE,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    last_login    TIMESTAMPTZ
);

-- Insert default admin user (password: changeme — CHANGE IN PRODUCTION)
INSERT INTO users (username, email, password_hash, role)
VALUES ('admin', 'admin@sentinel.local',
        '$2b$12$placeholder_hash_change_this_immediately', 'admin');

-- ── Incidents ─────────────────────────────────────────────────
CREATE TABLE incidents (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id  TEXT UNIQUE NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT,
    severity     TEXT NOT NULL,
    status       TEXT DEFAULT 'open',   -- open / investigating / contained / resolved
    assigned_to  TEXT,
    alert_ids    TEXT[] DEFAULT '{}',
    agent_ids    TEXT[] DEFAULT '{}',
    timeline     JSONB DEFAULT '[]',
    mitre_ids    TEXT[] DEFAULT '{}',
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW(),
    resolved_at  TIMESTAMPTZ
);

CREATE INDEX idx_incidents_status   ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);

-- ── Views ─────────────────────────────────────────────────────

-- Alert summary view
CREATE VIEW alert_summary AS
SELECT
    DATE_TRUNC('hour', timestamp) AS hour,
    severity,
    COUNT(*) AS count
FROM alerts
GROUP BY 1, 2
ORDER BY 1 DESC;

-- Agent health view
CREATE VIEW agent_health AS
SELECT
    a.agent_id,
    a.hostname,
    a.status,
    a.last_seen,
    a.cpu_pct,
    a.mem_pct,
    COUNT(al.id) FILTER (WHERE al.status = 'new') AS open_alerts,
    COUNT(al.id) FILTER (WHERE al.severity = 'CRITICAL' AND al.status = 'new') AS critical_alerts
FROM agents a
LEFT JOIN alerts al ON al.agent_id = a.agent_id
    AND al.created_at > NOW() - INTERVAL '24 hours'
GROUP BY a.agent_id, a.hostname, a.status, a.last_seen, a.cpu_pct, a.mem_pct;
