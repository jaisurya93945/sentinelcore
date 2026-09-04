"""
Resource protection: rate limiting and payload size caps.

WHAT THIS DEFENDS AGAINST
A security gateway is itself an attractive target. Every request costs
CPU (regex scanning is linear in input length, and the streaming path
re-scans accumulated text), and the proxy path additionally costs money
by forwarding to a paid upstream. Without limits, an attacker who cannot
get anything PAST the gateway can still take it down, or run up the
operator's provider bill -- denial of wallet rather than denial of
service.

DESIGN: FIXED-WINDOW COUNTER, IN PROCESS
Deliberately the simplest mechanism that is honest about what it is:

  - Fixed window, not sliding or token bucket. A fixed window permits up
    to 2x the nominal rate across a window boundary. That is a real
    weakness and it is stated rather than hidden; it is accepted because
    the alternative implementations are meaningfully more code for a
    guarantee this deployment cannot make anyway (see below).

  - IN-PROCESS state. Limits are per worker process, NOT per deployment.
    Run four uvicorn workers and the effective limit is four times what
    is configured. This is the honest ceiling of a dependency-free
    implementation: a real distributed limit requires shared state
    (Redis or similar), which this project does not have and will not
    pretend to have. Anyone running multiple workers must divide the
    configured limit accordingly, and the docs say so.

  - OFF BY DEFAULT, consistent with every other optional control here.
    Enabling a limiter that is wrong for a deployment causes an outage;
    the operator chooses.

BODY SIZE IS CHECKED SEPARATELY AND FIRST
A 100MB request body is expensive before any rate counter is consulted,
because the body must be read to be counted. The size cap is enforced
from the Content-Length header where present, so an oversized request is
rejected without reading it.

WHAT THIS IS NOT
Not a WAF, not DDoS protection, not a substitute for an upstream proxy
or load balancer doing this properly. It is a last-resort guard for a
process that would otherwise have none.
"""

import threading
import time
from collections import defaultdict

from app.core.config import settings


class FixedWindowLimiter:
    """Thread-safe fixed-window counter keyed by client identity."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._counts: dict[str, list] = defaultdict(lambda: [0, 0.0])  # key -> [count, window_start]
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int, float]:
        """Returns (allowed, remaining, reset_in_seconds). Counts the
        request when allowed; a rejected request does NOT consume budget,
        so a client being limited cannot extend its own lockout."""
        now = time.monotonic()
        with self._lock:
            entry = self._counts[key]
            count, start = entry

            if now - start >= self.window_seconds:
                count, start = 0, now

            if count >= self.max_requests:
                entry[0], entry[1] = count, start
                return False, 0, max(0.0, self.window_seconds - (now - start))

            entry[0], entry[1] = count + 1, start
            return True, self.max_requests - (count + 1), max(0.0, self.window_seconds - (now - start))

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()


_limiter: FixedWindowLimiter | None = None
_limiter_config: tuple[int, int] | None = None


def get_limiter() -> FixedWindowLimiter:
    """Rebuilds when configuration changes so tests and reloads see it."""
    global _limiter, _limiter_config
    cfg = (settings.rate_limit_requests, settings.rate_limit_window_seconds)
    if _limiter is None or _limiter_config != cfg:
        _limiter = FixedWindowLimiter(*cfg)
        _limiter_config = cfg
    return _limiter


def client_key(api_key: str | None, client_host: str | None) -> str:
    """Identity for limiting purposes.

    Prefers the API key: it is the closest thing to an authenticated
    principal here, and it survives NAT and shared egress addresses where
    IP does not. Falls back to source IP when auth is disabled. IP is a
    weak identifier -- trivially spoofed behind a proxy that does not set
    a trustworthy forwarded header, and shared by every user behind one
    NAT -- which is another reason this is a last-resort guard rather
    than a primary control.
    """
    if api_key:
        return f"key:{api_key[:16]}"
    return f"ip:{client_host or 'unknown'}"
