"""Wait only for admission capacity proven by the installed host's history and policy."""

from __future__ import annotations

import time
from collections.abc import Callable

WAIT_TIMEOUT_SECONDS = 600.0
MAX_SLEEP_SECONDS = 60.0
BOUNDARY_GUARD_SECONDS = 0.25
MICROSECONDS_PER_SECOND = 1_000_000


class CorrelationPacer:
    """Fresh host observations credit operation time and retained exact retries."""

    def __init__(self, *, observe: Callable[[str], dict[str, object]]) -> None:
        self._observe = observe

    def pace(self, correlation_id: str) -> None:
        timeout = time.monotonic() + WAIT_TIMEOUT_SECONDS
        while True:
            observed = self._observe(correlation_id)
            if set(observed) != {"recorded", "host_now_us", "eligible_at_us"}:
                raise AssertionError("invalid installed admission observation")
            recorded, now, eligible = (
                observed["recorded"],
                observed["host_now_us"],
                observed["eligible_at_us"],
            )
            if (
                type(recorded) is not bool
                or type(now) is not int
                or type(eligible) is not int
                or now < 0
                or eligible < now
                or (recorded and eligible != now)
            ):
                raise AssertionError("invalid installed admission observation")
            if recorded or eligible == now:
                return
            remaining = timeout - time.monotonic()
            if remaining <= 0:
                raise AssertionError("host admission clock did not reach the pacing deadline")
            delay = (eligible - now) / MICROSECONDS_PER_SECOND + BOUNDARY_GUARD_SECONDS
            time.sleep(min(delay, MAX_SLEEP_SECONDS, remaining))
