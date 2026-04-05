# server/main.py
# Sentinel HIDS — Central Server

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from api.events   import router as events_router
from api.alerts   import router as alerts_router
from api.agents   import router as agents_router
from api.ws       import router as ws_router
from api.auth     import router as auth_router, verify_api_key
from api.response import router as response_router
from api.fim      import router as fim_router
from db.database  import init_db
from detection.engine   import DetectionEngine
from ingest.processor   import EventProcessor, GENERATED_ALERTS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("sentinel.server")


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("🛡  Sentinel HIDS Server starting...")

    app.state.alert_store    = {}
    app.state.agent_registry = {}

    await init_db()

    engine = DetectionEngine()
    await engine.load_rules("rules/sigma")
    app.state.detection_engine = engine
    log.info(f"Detection engine: {engine.rule_count} rules loaded")

    processor = EventProcessor(engine)
    processor._app_state = app.state
    app.state.event_processor = processor
    asyncio.create_task(processor.start())

    log.info("✅ Server ready — accepting agent connections")
    yield

    await processor.stop()
    log.info("Server shutdown complete")


app = FastAPI(
    title="Sentinel HIDS API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Public routes ─────────────────────────────────────────────
app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])

# ── Protected routes ──────────────────────────────────────────
app.include_router(events_router,   prefix="/api/v1/events",   tags=["events"],   dependencies=[Depends(verify_api_key)])
app.include_router(alerts_router,   prefix="/api/v1/alerts",   tags=["alerts"],   dependencies=[Depends(verify_api_key)])
app.include_router(agents_router,   prefix="/api/v1/agents",   tags=["agents"],   dependencies=[Depends(verify_api_key)])
app.include_router(response_router, prefix="/api/v1/response", tags=["response"], dependencies=[Depends(verify_api_key)])
app.include_router(fim_router,      prefix="/api/v1/fim",      tags=["fim"],      dependencies=[Depends(verify_api_key)])
app.include_router(ws_router,       prefix="/ws",              tags=["websocket"])


# ── Health (public) ───────────────────────────────────────────
@app.get("/health")
async def health():
    engine = getattr(app.state, "detection_engine", None)
    proc   = getattr(app.state, "event_processor",  None)
    return {
        "status":     "ok",
        "rules":      engine.rule_count if engine else 0,
        "agents":     len(getattr(app.state, "agent_registry", {})),
        "alerts":     len(getattr(app.state, "alert_store",    {})),
        "ws_clients": len(getattr(proc, "stats", {}).get("ws_clients", [])) if proc else 0,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False, workers=1)
