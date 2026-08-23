"""Hardening controls applied when SECURE_MODE is enabled."""

import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from .config import LOGIN_MAX_FAILURES, LOGIN_WINDOW_SECONDS

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}

# Failed login timestamps, keyed by (client ip, username). In-memory is fine for a
# single-process lab target; production would use Redis so the counter survives
# restarts and is shared across workers.
_failures = defaultdict(deque)


def _prune(bucket: deque, now: float) -> None:
    while bucket and now - bucket[0] > LOGIN_WINDOW_SECONDS:
        bucket.popleft()


def check_login_rate(request: Request, username: str) -> None:
    """Raise 429 once a client exceeds the failed-login threshold."""
    now = time.time()
    client = request.client.host if request.client else "unknown"
    bucket = _failures[(client, username)]

    _prune(bucket, now)

    if len(bucket) >= LOGIN_MAX_FAILURES:
        retry_after = int(LOGIN_WINDOW_SECONDS - (now - bucket[0]))
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(max(retry_after, 1))},
        )


def record_login_failure(request: Request, username: str) -> None:
    client = request.client.host if request.client else "unknown"
    _failures[(client, username)].append(time.time())


def clear_login_failures(request: Request, username: str) -> None:
    """A successful login resets the counter for that client and account."""
    client = request.client.host if request.client else "unknown"
    _failures.pop((client, username), None)


def require_owner(resource_owner_id: int, current_user_id: int) -> None:
    """Object-level authorization: the caller must own the resource."""
    if resource_owner_id != current_user_id:
        raise HTTPException(status_code=403, detail="Not authorized for this resource")
