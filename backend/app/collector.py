from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import get_settings
from app.database import build_engine, build_session_factory, initialize_schema
from app.routers.windows_receiver import router as windows_receiver_router

settings = get_settings()
engine = build_engine(settings.database_url)
SessionFactory = build_session_factory(engine)


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_schema(engine)
    yield


app = FastAPI(
    title="ThreatLens Windows Collector",
    description="Isolated bearer-token receiver for Windows Security events.",
    version="0.3.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.state.session_factory = SessionFactory
app.include_router(windows_receiver_router)


@app.get("/healthz", tags=["System"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "ThreatLens Windows Collector"}
