import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from .config import settings
from .db import Base, engine
from .routes import auth_router, packages_router, scans_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("depshield")


def init_db(retries: int = 20) -> None:
    """Create tables. Retries because Postgres may still be starting in Docker.
    For production, replace this with Alembic migrations."""
    for attempt in range(retries):
        try:
            Base.metadata.create_all(engine)
            return
        except Exception as exc:
            log.warning("Database not ready (%s). Retry %s/%s", exc.__class__.__name__, attempt + 1, retries)
            time.sleep(2)
    raise RuntimeError("Could not connect to the database")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="DepShield AI", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(packages_router)

try:  # exposes /metrics for Prometheus
    from prometheus_fastapi_instrumentator import Instrumentator

    Instrumentator().instrument(app).expose(app, include_in_schema=False)
except ImportError:
    pass


@app.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"status": "ok", "llm": bool(settings.openai_api_key)}
