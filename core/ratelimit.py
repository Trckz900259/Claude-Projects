"""
ratelimit.py — conservative, thread-safe rate limiting.

Why this matters: bug-bounty programs publish rate limits, and hammering a
target is both rude and a fast way to get banned (or to cause an outage you'd be
responsible for). The platform NEVER sends a request without first passing
through here.

We provide three controls, all configurable per program:

  * a GLOBAL requests-per-second cap     (requests_per_second)
  * a PER-HOST requests-per-second cap   (per_host_rps)
  * a maximum CONCURRENCY cap            (max_concurrency)

The mechanism is the classic 'token bucket': tokens refill at a steady rate; you
must spend a token to send a request; if the bucket is empty you wait. It's
simple, smooth, and easy to reason about.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Iterator


class TokenBucket:
    """A thread-safe token bucket. `rate` is tokens added per second."""

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self.rate = float(rate)
        # Capacity is the max burst. Default to one second's worth (at least 1).
        self.capacity = float(capacity if capacity is not None else max(rate, 1.0))
        self._tokens = self.capacity
        self._timestamp = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> None:
        """Block until `tokens` are available, then consume them."""
        while True:
            with self._lock:
                now = time.monotonic()
                # Refill based on how much time has passed.
                elapsed = now - self._timestamp
                self._timestamp = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                # Not enough yet — figure out how long to sleep, then retry.
                deficit = tokens - self._tokens
                sleep_for = deficit / self.rate
            # Sleep OUTSIDE the lock so other threads can make progress.
            time.sleep(sleep_for)


class RateLimiter:
    """
    Combines a global bucket, per-host buckets, and a concurrency semaphore.

    Use it as a context manager around each outbound request:

        with rate_limiter.slot("example.com"):
            do_the_request()

    Entering the `slot` blocks until it is polite to proceed; leaving it frees
    the concurrency slot for the next waiting request.
    """

    def __init__(
        self,
        requests_per_second: float,
        per_host_rps: float,
        max_concurrency: int,
    ) -> None:
        self.global_bucket = TokenBucket(requests_per_second)
        self.per_host_rps = float(per_host_rps)
        self.max_concurrency = int(max_concurrency)

        self._host_buckets: dict[str, TokenBucket] = {}
        self._host_lock = threading.Lock()
        # BoundedSemaphore guards against accidental over-release bugs.
        self._semaphore = threading.BoundedSemaphore(max(1, self.max_concurrency))

    def _host_bucket(self, host: str) -> TokenBucket:
        """Lazily create one bucket per host (so each host is throttled alone)."""
        with self._host_lock:
            bucket = self._host_buckets.get(host)
            if bucket is None:
                bucket = TokenBucket(self.per_host_rps)
                self._host_buckets[host] = bucket
            return bucket

    @contextmanager
    def slot(self, host: str) -> Iterator[None]:
        """Acquire concurrency + global + per-host budget, then yield."""
        self._semaphore.acquire()
        try:
            # Spend a global token first, then a per-host token.
            self.global_bucket.acquire()
            if self.per_host_rps > 0 and host:
                self._host_bucket(host).acquire()
            yield
        finally:
            self._semaphore.release()
