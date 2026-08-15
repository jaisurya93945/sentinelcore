from fastapi import FastAPI

from app.api.v1 import health
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    description="AI Threat Gateway -- security layer for LLM, RAG, and agentic AI systems.",
    version=settings.version,
)

app.include_router(health.router, prefix="/api/v1", tags=["health"])


@app.get("/")
def root():
    return {
        "service": settings.app_name,
        "version": settings.version,
        "docs": "/docs",
    }
