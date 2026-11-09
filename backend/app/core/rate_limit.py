import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any, Dict, Tuple
from fastapi import HTTPException, Request, status


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding-window rate limiter for API and sensitive endpoints."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._blocked_count: int = 0
        self._lock = Lock()

    def check(self, key: str, max_requests: int, window_seconds: int = 60) -> Tuple[int, int]:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._hits[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= max_requests:
                self._blocked_count += 1
                retry_after = max(1, int(window_seconds - (now - bucket[0])))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded ({max_requests} requests per {window_seconds}s). Please retry shortly.",
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(max_requests),
                        "X-RateLimit-Remaining": "0",
                    },
                )
            bucket.append(now)
            remaining = max(0, max_requests - len(bucket))
            return max_requests, remaining

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
            self._blocked_count = 0

    def status_summary(self) -> Dict[str, Any]:
        with self._lock:
            active_keys = sum(1 for b in self._hits.values() if len(b) > 0)
            return {
                "active_buckets": active_keys,
                "blocked_requests_total": self._blocked_count,
            }


rate_limiter = SlidingWindowRateLimiter()


def enforce_rate_limit(
    request: Request,
    scope: str,
    max_requests: int,
    window_seconds: int = 60,
) -> Tuple[int, int]:
    client_host = request.client.host if request.client else "unknown"
    key = f"{scope}:{client_host}"
    return rate_limiter.check(key, max_requests=max_requests, window_seconds=window_seconds)


