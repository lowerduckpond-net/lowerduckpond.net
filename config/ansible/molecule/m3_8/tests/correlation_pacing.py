"""Wait only for admission capacity proven by the installed host's history and policy."""

from __future__ import annotations

import time
from collections.abc import Callable

from scripts.qualification_timing import measure

WAIT_TIMEOUT_SECONDS = 600.0
MAX_SLEEP_SECONDS = 60.0
BOUNDARY_GUARD_SECONDS = 0.25
MICROSECONDS_PER_SECOND = 1_000_000
MAX_ADMISSION_ATTEMPTS = 3
RATE_LIMIT_EXIT_STATUS = 75
RATE_LIMIT_MESSAGES = frozenset(
    (
        "wall-clock rollback closes new correlation admission",
        "rolling-hour correlation limit is exhausted",
        "correlation burst limit is exhausted",
    )
)


class AdmissionRateLimitError(RuntimeError):
    """The authoritative issuer rejected an admission predicted by the probe."""


class CorrelationPacer:
    """Fresh host observations credit operation time and retained exact retries."""

    def __init__(self, *, observe: Callable[[str], dict[str, object]]) -> None:
        self._observe = observe

    def pace(self, correlation_id: str) -> None:
        self._pace(correlation_id, time.monotonic() + WAIT_TIMEOUT_SECONDS)

    def issue[T](self, correlation_id: str, operation: Callable[[], T]) -> T:
        # A probe grants no reservation: clock correction or another admission
        # can invalidate it before issuance. Only an explicit admission refusal
        # can repeat this exact operation, under the original pacing deadline.
        deadline = time.monotonic() + WAIT_TIMEOUT_SECONDS
        for attempt in range(MAX_ADMISSION_ATTEMPTS):
            with measure("pacing"):
                self._pace(correlation_id, deadline)
            try:
                return operation()
            except AdmissionRateLimitError:
                if attempt == MAX_ADMISSION_ATTEMPTS - 1:
                    raise
        raise AssertionError("admission retry loop exhausted")  # pragma: no cover

    def _pace(self, correlation_id: str, timeout: float) -> None:
        while True:
            if time.monotonic() >= timeout:
                raise AssertionError("host admission clock did not reach the pacing deadline")
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
            remaining = timeout - time.monotonic()
            if remaining <= 0:
                raise AssertionError("host admission clock did not reach the pacing deadline")
            if recorded or eligible == now:
                return
            delay = (eligible - now) / MICROSECONDS_PER_SECOND + BOUNDARY_GUARD_SECONDS
            time.sleep(min(delay, MAX_SLEEP_SECONDS, remaining))
