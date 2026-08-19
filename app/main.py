from fastapi import FastAPI

import app.detectors  # noqa: F401  -- importing this triggers detector self-registration
from app.api.v1 import audit, health, proxy, scan
from app.core.config import settings
from app.services.audit_log import init_db

app = FastAPI(
    title=settings.app_name,
    description="AI Threat Gateway -- security layer for LLM, RAG, and agentic AI systems.",
    version=settings.version,
)

init_db()

app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(scan.router, prefix="/api/v1", tags=["scan"])
app.include_router(audit.router, prefix="/api/v1", tags=["audit"])
# Mounted at /v1 (not /api/v1) on purpose: this path must match OpenAI's
# own API exactly for SentinelCore to be a genuine drop-in base_url swap.
app.include_router(proxy.router, prefix="/v1", tags=["proxy"])


@app.get("/")
def root():
    return {
        "service": settings.app_name,
        "version": settings.version,
        "docs": "/docs",
    }
