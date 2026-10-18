"""Kernel-enforced cumulative local archive work in one privileged worker.

The installed executor owns one budget. Parser entry points share it across
sequential and nested calls; time spent waiting for provider helpers is outside
those calls. SIGALRM keeps its terminating default action, so a stuck parser
cannot turn expiry into an ordinary caught exception or a successful result.
Durable intent/staging recovery is the same as for a killed systemd worker.

Direct library callers have no privileged worker budget. Installed helper
services still have their separate five-minute systemd runtime limit.
"""

from __future__ import annotations

import os
import signal
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from typing import Final

PARSER_WORK_SECONDS: Final = 300.0
# getitimer reports timeval microseconds; this tolerates its rounding only and
# never rearms or extends the terminating timer.
_TIMER_RESOLUTION_SECONDS: Final = 0.000001
_clock = time.monotonic


class ParserBudgetError(RuntimeError):
    """The privileged parser cannot retain its terminating wall-time bound."""


def _require_main_process(pid: int) -> None:
    if os.getpid() != pid or threading.current_thread() is not threading.main_thread():
        raise ParserBudgetError("archive parser budget requires its original main thread")


def _require_signal_available() -> None:
    if (
        signal.getsignal(signal.SIGALRM) != signal.SIG_DFL
        or signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK, [])
        or signal.SIGALRM in signal.sigpending()
    ):
        raise ParserBudgetError("archive parser terminating signal is unavailable")


def _require_idle_timer() -> None:
    _require_signal_available()
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise ParserBudgetError("archive parser timer is already owned")


@dataclass(slots=True)
class _ParserBudget:
    pid: int
    remaining: float = PARSER_WORK_SECONDS
    depth: int = 0
    expires: float = 0.0

    def require_owned_timer(self) -> None:
        try:
            _require_main_process(self.pid)
            _require_signal_available()
            before = _clock()
            remaining, interval = signal.getitimer(signal.ITIMER_REAL)
            if (
                self.remaining <= 0
                or remaining <= 0
                or interval != 0
                or remaining > self.expires - before + _TIMER_RESOLUTION_SECONDS
            ):
                raise ParserBudgetError("archive parser timer ownership was lost")
        except BaseException:
            self.remaining = 0
            raise

    @contextmanager
    def work(self) -> Iterator[None]:
        _require_main_process(self.pid)
        if self.depth:
            self.require_owned_timer()
            self.depth += 1
            try:
                yield
            finally:
                self.depth -= 1
            return
        try:
            _require_idle_timer()
        except BaseException:
            self.remaining = 0
            raise
        if self.remaining <= 0:
            raise ParserBudgetError("archive parser cumulative budget is exhausted")
        started = _clock()
        try:
            signal.setitimer(signal.ITIMER_REAL, self.remaining)
            self.expires = _clock() + self.remaining
        except BaseException:
            self.remaining = 0
            raise
        self.depth = 1
        try:
            yield
        finally:
            # No Python signal handler is installed or restored. The default
            # action remains effective until the kernel timer is disarmed.
            try:
                self.require_owned_timer()
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0.0)
                self.remaining = max(0, self.remaining - (_clock() - started))
                self.depth = 0
            if self.remaining <= 0:
                raise ParserBudgetError("archive parser cumulative budget is exhausted")


_active: _ParserBudget | None = None


@contextmanager
def parser_work_budget() -> Iterator[None]:
    """Own one fixed budget for the entire installed executor invocation."""
    global _active  # noqa: PLW0603 - process-wide ownership rejects other threads
    if _active is not None:
        raise ParserBudgetError("archive parser budget cannot be replaced")
    _require_main_process(os.getpid())
    _require_idle_timer()
    _active = _ParserBudget(os.getpid())
    try:
        yield
    finally:
        _active = None


def bounded_parser_work[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    """Charge actual inspection, extraction and bundle construction calls."""

    @wraps(function)
    def bounded(*args: P.args, **kwargs: P.kwargs) -> R:
        if _active is None:
            return function(*args, **kwargs)
        with _active.work():
            return function(*args, **kwargs)

    return bounded
