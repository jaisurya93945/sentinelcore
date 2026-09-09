from fastapi import APIRouter

from sentinelcore.core.config import settings

router = APIRouter()


@router.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.version,
    }
