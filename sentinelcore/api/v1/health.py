from fastapi import APIRouter, Response

from sentinelcore.core import metrics
from sentinelcore.core.config import settings

router = APIRouter()

# Prometheus scrapers default to /metrics at the root. Mounting it only
# under /api/v1 would mean every deployment needed a custom scrape path,
# which is the kind of friction that ends with nobody scraping at all. It
# is exposed at both.
metrics_router = APIRouter()


@router.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.version,
    }


@metrics_router.get("/metrics")
@router.get("/metrics")
def prometheus_metrics() -> Response:
    """Prometheus exposition. Mounted WITHOUT a role dependency, alongside
    /health, because a scrape target that needs a credential is a scrape
    target that ends up unmonitored -- and because Prometheus itself is
    usually reached over a network you already control.

    The cost of that choice is that these counters are readable by anyone
    who can reach the port, so nothing here carries content: labels are
    finding TYPES, decisions and enforcement outcomes, never scanned text
    or evidence. An observer learns the shape of the traffic, which is the
    point, and nothing about what was in it.
    """
    return Response(content=metrics.render(),
                    media_type="text/plain; version=0.0.4; charset=utf-8")
