"""Pace installed requests against the host's admission clock, not the runner's."""

from __future__ import annotations

import time
from collections.abc import Callable

BURST_CAPACITY = 5
CORRELATION_INTERVAL_SECONDS = 60.25
BURST_REFILL_SECONDS = BURST_CAPACITY * CORRELATION_INTERVAL_SECONDS
_WAIT_TIMEOUT_SECONDS = 600.0


def wait_for_host_time(deadline: float, *, clock: Callable[[], float]) -> float:
    """Recheck host UTC after sleeping; monotonic time only bounds the wait."""
    timeout = time.monotonic() + _WAIT_TIMEOUT_SECONDS
    while True:
        now = clock()
        if now >= deadline:
            return now
        remaining = timeout - time.monotonic()
        if remaining <= 0:
            raise AssertionError("host admission clock did not reach the pacing deadline")
        time.sleep(min(deadline - now, CORRELATION_INTERVAL_SECONDS, remaining))


class CorrelationPacer:
    """Conservative burst accounting shared by every fixture issuance path."""

    def __init__(self, *, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._tokens = float(BURST_CAPACITY)
        self._updated_at: float | None = None
        self._seen: set[str] = set()

    def pace(self, correlation_id: str) -> bool:
        if correlation_id in self._seen:
            return False

        if self._updated_at is None:
            now = self._clock()
        else:
            deadline = self._updated_at + max(0.0, 1.0 - self._tokens) * (
                CORRELATION_INTERVAL_SECONDS
            )
            now = wait_for_host_time(deadline, clock=self._clock)
            self._tokens = min(
                float(BURST_CAPACITY),
                self._tokens + (now - self._updated_at) / CORRELATION_INTERVAL_SECONDS,
            )

        self._tokens -= 1.0
        self._updated_at = now
        self._seen.add(correlation_id)
        return True

    def complete(self, new_correlation: bool) -> None:
        if new_correlation:
            assert self._updated_at is not None
            # Keep ignoring operation time when refilling. A backwards wall-clock
            # step must not move the next admission deadline earlier either.
            self._updated_at = max(self._updated_at, self._clock())
