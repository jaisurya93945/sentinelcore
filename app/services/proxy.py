"""
Reverse proxy forwarding.

This is what turns SentinelCore from "an API you call to ask if something
is safe" into "a gateway you sit your actual traffic behind" -- point an
existing OpenAI-SDK-compatible client's base_url at SentinelCore instead
of the real provider, and requests that pass the detection pipeline get
forwarded through untouched; requests that don't, never reach the
upstream model at all.

SentinelCore never owns or stores the upstream API key. The client's
Authorization header is forwarded through exactly as received -- this
service is a pass-through for credentials, not a credential store. That
is a deliberate security property, not an oversight.
"""

import httpx

from app.core.config import settings

# Headers that must NOT be forwarded as-is: httpx sets Host and
# Content-Length correctly for the outgoing request itself, and forwarding
# the client's original values for these causes mismatches upstream.
_HOP_BY_HOP_HEADERS = {"host", "content-length", "connection"}


async def forward_to_upstream(path: str, method: str, headers: dict, body: bytes) -> httpx.Response:
    """Forward one request to the configured upstream and return its response as-is."""
    upstream_url = f"{settings.upstream_base_url.rstrip('/')}{path}"
    forward_headers = {k: v for k, v in headers.items() if k.lower() not in _HOP_BY_HOP_HEADERS}

    async with httpx.AsyncClient(timeout=settings.upstream_timeout_seconds) as client:
        return await client.request(method, upstream_url, headers=forward_headers, content=body)


async def stream_lines_from_upstream(path: str, method: str, headers: dict, body: bytes):
    """
    Async generator yielding raw SSE lines from the upstream as they
    arrive, instead of buffering the whole response first. This is what
    lets the caller scan content incrementally and cut a stream off mid-
    flight, rather than only being able to inspect it after the fact.
    """
    upstream_url = f"{settings.upstream_base_url.rstrip('/')}{path}"
    forward_headers = {k: v for k, v in headers.items() if k.lower() not in _HOP_BY_HOP_HEADERS}

    async with httpx.AsyncClient(timeout=settings.upstream_timeout_seconds) as client:
        async with client.stream(method, upstream_url, headers=forward_headers, content=body) as response:
            async for line in response.aiter_lines():
                yield line
