"""
CyberSleuth AI – FastAPI Application Entry Point
Member 2: Backend & Data Engineering

Wires routers, middleware, startup events.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import init_db

# ── Optional Rate limiter ──────────────────────────────────────────────────────
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT])
except ImportError:
    limiter = None
    RateLimitExceeded = None
    _rate_limit_exceeded_handler = None

# ── FastAPI app ────────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Autonomous Security Investigation Platform",
    docs_url="/docs",
    redoc_url="/redoc",
)

if limiter and RateLimitExceeded:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS – allow the Vite dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Startup ────────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    init_db()


# ── Health check ───────────────────────────────────────────────────────────────
@app.get("/api/v1/health", tags=["System"])
def health():
    return {"status": "ok", "version": settings.APP_VERSION}


# ── Routers ────────────────────────────────────────────────────────────────────
from app.api.auth import router as auth_router          # noqa: E402
from app.api.events import router as events_router      # noqa: E402
from app.api.alerts import router as alerts_router      # noqa: E402
from app.api.incidents import router as incidents_router  # noqa: E402

app.include_router(auth_router,      prefix="/api/v1/auth",      tags=["Auth"])
app.include_router(events_router,    prefix="/api/v1/events",    tags=["Events"])
app.include_router(alerts_router,    prefix="/api/v1/alerts",    tags=["Alerts"])
app.include_router(incidents_router, prefix="/api/v1/incidents", tags=["Incidents"])
