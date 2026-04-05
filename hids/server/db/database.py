# server/db/database.py
import logging
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

log = logging.getLogger("sentinel.db")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://sentinel:changeme@postgres:5432/sentinel"
)

engine           = None
AsyncSessionLocal = None

async def init_db():
    global engine, AsyncSessionLocal
    log.info("Connecting to PostgreSQL...")
    try:
        engine = create_async_engine(
            DATABASE_URL,
            echo=False,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
        )
        AsyncSessionLocal = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        async with engine.begin() as conn:
            await conn.run_sync(_create_tables)
        log.info(f"PostgreSQL connected and tables ready: {DATABASE_URL}")
    except Exception as e:
        log.error(f"PostgreSQL connection failed: {e}")
        log.warning("Falling back to in-memory storage")
        engine            = None
        AsyncSessionLocal = None

def _create_tables(conn):
    """
    Execute each CREATE TABLE as a separate statement.
    asyncpg does NOT allow multiple statements in one execute() call.
    """
    statements = [
        """
        CREATE TABLE IF NOT EXISTS events (
            id          SERIAL PRIMARY KEY,
            event_id    TEXT UNIQUE,
            agent_id    TEXT,
            hostname    TEXT,
            severity    TEXT,
            event_type  TEXT,
            event_data  JSONB,
            timestamp   TIMESTAMPTZ DEFAULT NOW(),
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id              SERIAL PRIMARY KEY,
            alert_id        TEXT UNIQUE,
            rule_id         TEXT,
            rule_title      TEXT,
            hostname        TEXT,
            severity        TEXT,
            score           INT,
            status          TEXT DEFAULT 'new',
            reason          TEXT,
            mitre_id        TEXT,
            mitre_tactic    TEXT,
            event_subtype   TEXT,
            event_data      JSONB,
            assigned_to     TEXT,
            acknowledged_at TIMESTAMPTZ,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS agents (
            id              SERIAL PRIMARY KEY,
            agent_id        TEXT UNIQUE,
            hostname        TEXT,
            ip_address      TEXT,
            os_name         TEXT,
            agent_version   TEXT,
            status          TEXT DEFAULT 'online',
            cpu_pct         FLOAT,
            mem_pct         FLOAT,
            open_alerts     INT DEFAULT 0,
            last_seen       TIMESTAMPTZ DEFAULT NOW(),
            registered_at   TIMESTAMPTZ DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS fim_baseline (
            id         SERIAL PRIMARY KEY,
            agent_id   TEXT,
            path       TEXT,
            hash       TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(agent_id, path)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS fim_changes (
            id         SERIAL PRIMARY KEY,
            agent_id   TEXT,
            path       TEXT,
            action     TEXT,
            old_hash   TEXT,
            new_hash   TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
        """,
        # Indexes — each as a separate statement
        "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts(status)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_created  ON alerts(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_events_hostname ON events(hostname)",
        "CREATE INDEX IF NOT EXISTS idx_events_created  ON events(created_at DESC)",
    ]

    for stmt in statements:
        conn.execute(text(stmt.strip()))

async def get_db():
    if AsyncSessionLocal is None:
        yield None
        return
    async with AsyncSessionLocal() as session:
        yield session
