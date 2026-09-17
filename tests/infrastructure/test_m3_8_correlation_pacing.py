from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from lowerduckpond_static_host_agent.correlations import _admit_rate

from config.ansible.molecule.m3_8.tests import correlation_pacing as pacing


@dataclass
class _Clocks:
    host: float = 1_800_000_000.0
    elapsed: float = 0.0
    host_rate: float = 1.0
    sleeps: list[float] = field(default_factory=list)

    def utc(self) -> float:
        return self.host

    def monotonic(self) -> float:
        return self.elapsed

    def advance(self, seconds: float) -> None:
        self.elapsed += seconds
        self.host += seconds * self.host_rate

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.advance(seconds)


@pytest.mark.parametrize("host_rate", [0.9, 1.0, 1.1])
def test_pacing_satisfies_real_admission_when_host_and_runner_clocks_diverge(
    monkeypatch: pytest.MonkeyPatch, host_rate: float
) -> None:
    clocks = _Clocks(host_rate=host_rate)
    monkeypatch.setattr(pacing, "time", clocks)
    pacer = pacing.CorrelationPacer(clock=clocks.utc)
    history: list[datetime] = []

    for index in range(30):
        new = pacer.pace(str(index))
        assert new
        clocks.advance(0.5)  # Request transport precedes host acceptance.
        candidate = datetime.fromtimestamp(clocks.host, UTC)
        _admit_rate(tuple(history), candidate)
        history.append(candidate)
        clocks.advance(1.5)
        pacer.complete(new)

    assert clocks.sleeps


def test_initial_burst_wait_rechecks_host_time_after_an_early_wakeup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clocks = _Clocks(host_rate=0.9)
    monkeypatch.setattr(pacing, "time", clocks)
    deadline = clocks.host + pacing.BURST_REFILL_SECONDS

    reached = pacing.wait_for_host_time(deadline, clock=clocks.utc)

    assert reached >= deadline
    assert clocks.elapsed > pacing.BURST_REFILL_SECONDS


def test_exact_retry_does_not_spend_or_postpone_a_new_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clocks = _Clocks()
    monkeypatch.setattr(pacing, "time", clocks)
    pacer = pacing.CorrelationPacer(clock=clocks.utc)
    for index in range(pacing.BURST_CAPACITY):
        pacer.complete(pacer.pace(str(index)))

    retry = pacer.pace("0")
    assert not retry
    clocks.advance(pacing.CORRELATION_INTERVAL_SECONDS)
    pacer.complete(retry)
    assert pacer.pace("next")
    assert clocks.sleeps == []


def test_completion_still_discards_operation_time_when_refilling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clocks = _Clocks()
    monkeypatch.setattr(pacing, "time", clocks)
    pacer = pacing.CorrelationPacer(clock=clocks.utc)
    for index in range(pacing.BURST_CAPACITY):
        new = pacer.pace(str(index))
        clocks.advance(pacing.CORRELATION_INTERVAL_SECONDS)
        pacer.complete(new)

    completed = clocks.host
    assert pacer.pace("next")
    assert clocks.host >= completed + pacing.CORRELATION_INTERVAL_SECONDS


@pytest.mark.parametrize("during_request", [False, True])
def test_backwards_host_clock_does_not_advance_the_next_deadline(
    monkeypatch: pytest.MonkeyPatch, during_request: bool
) -> None:
    clocks = _Clocks()
    monkeypatch.setattr(pacing, "time", clocks)
    pacer = pacing.CorrelationPacer(clock=clocks.utc)
    for index in range(pacing.BURST_CAPACITY):
        new = pacer.pace(str(index))
        if during_request and index == pacing.BURST_CAPACITY - 1:
            clocks.host -= 20
        pacer.complete(new)

    if not during_request:
        clocks.host -= 20
    candidate_before_wait = datetime.fromtimestamp(clocks.host, UTC)
    assert pacer.pace("next")
    candidate = datetime.fromtimestamp(clocks.host, UTC)
    assert (candidate - candidate_before_wait).total_seconds() >= (
        20 + pacing.CORRELATION_INTERVAL_SECONDS
    )


def test_stalled_host_clock_fails_with_a_bounded_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clocks = _Clocks(host_rate=0.0)
    monkeypatch.setattr(pacing, "time", clocks)

    with pytest.raises(AssertionError, match="host admission clock did not reach"):
        pacing.wait_for_host_time(clocks.host + 1, clock=clocks.utc)

    assert clocks.elapsed == pacing._WAIT_TIMEOUT_SECONDS
