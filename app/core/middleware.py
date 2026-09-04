"""
Resource-protection middleware.

Order matters and is deliberate:

  1. BODY SIZE, from Content-Length, before anything reads the body. A
     100MB payload is expensive to receive; rejecting it after reading it
     defeats the purpose.
  2. RATE LIMIT, before routing, so a limited client costs one dictionary
     lookup rather than a full detector pass.

The health endpoint is exempt. Rate-limiting health checks would cause an
orchestrator to mark a healthy service as down under load -- turning a
protection into an outage amplifier.
"""

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.limits import client_key, get_limiter

logger = logging.getLogger(__name__)

EXEMPT_PATHS = {"/api/v1/health", "/", "/docs", "/openapi.json", "/redoc"}


async def resource_protection_middleware(request: Request, call_next):
    path = request.url.path

    if path in EXEMPT_PATHS:
        return await call_next(request)

    # --- 1. body size, from the header, before reading anything ---
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > settings.max_request_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"error": {
                        "message": f"Request body exceeds {settings.max_request_bytes} bytes.",
                        "type": "sentinelcore_payload_too_large"}},
                )
        except ValueError:
            pass  # malformed header; let the framework reject it normally

    # --- 2. rate limit ---
    if settings.rate_limit_enabled:
        key = client_key(request.headers.get("x-api-key"), request.client.host if request.client else None)
        allowed, remaining, reset_in = get_limiter().check(key)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"error": {
                    "message": "Rate limit exceeded.",
                    "type": "sentinelcore_rate_limited"}},
                headers={
                    "Retry-After": str(int(reset_in) + 1),
                    "X-RateLimit-Limit": str(settings.rate_limit_requests),
                    "X-RateLimit-Remaining": "0",
                },
            )
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response

    return await call_next(request)
