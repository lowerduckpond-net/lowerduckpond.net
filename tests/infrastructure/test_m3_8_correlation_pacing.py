from __future__ import annotations

import json
import os
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.correlations import CorrelationRateLimitError, _admit_rate

from config.ansible.molecule.m3_8.tests import admission_probe as probe
from config.ansible.molecule.m3_8.tests import correlation_pacing as pacing

NOW = datetime(2026, 9, 18, tzinfo=UTC)
IDENTITY = "0198d17f-6f4a-7000-8000-000000000001"
ROOT = Path(__file__).resolve().parents[2]


@dataclass
class Clocks:
    host: datetime = NOW
    elapsed: float = 0.0
    host_rate: float = 1.0
    sleeps: list[float] = field(default_factory=list)
    history: dict[str, datetime] = field(default_factory=dict)

    def monotonic(self) -> float:
        return self.elapsed

    def advance(self, seconds: float) -> None:
        self.elapsed += seconds
        self.host += timedelta(seconds=seconds * self.host_rate)

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.advance(seconds)

    def observe(self, identity: str) -> dict[str, object]:
        return probe.observation(self.history, identity, self.host)

    def admit(self, identity: str) -> None:
        _admit_rate(tuple(self.history.values()), self.host)
        self.history[identity] = self.host


@pytest.mark.parametrize("host_rate", [0.9, 1.0, 1.1])
@pytest.mark.parametrize("operation_seconds", [0.0, 15.0, 60.0, 120.0])
def test_pacing_obeys_real_policy_with_drift_transport_and_operation_time(
    monkeypatch: pytest.MonkeyPatch, host_rate: float, operation_seconds: float
) -> None:
    clocks = Clocks(host_rate=host_rate)
    monkeypatch.setattr(pacing, "time", clocks)
    pacer = pacing.CorrelationPacer(observe=clocks.observe)
    for index in range(75):
        pacer.pace(str(index))
        clocks.advance(0.5)  # Transport elapses before authoritative host acceptance.
        clocks.admit(str(index))
        clocks.advance(operation_seconds)
    if operation_seconds * host_rate >= pacing.MAX_SLEEP_SECONDS:
        assert not clocks.sleeps
    else:
        assert clocks.sleeps


def test_restart_credits_retained_history_and_exact_retry_during_clock_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clocks = Clocks(history={str(index): NOW for index in range(5)})
    clocks.host -= timedelta(seconds=20)
    monkeypatch.setattr(pacing, "time", clocks)
    pacing.CorrelationPacer(observe=clocks.observe).pace("0")
    assert not clocks.sleeps
    pacing.CorrelationPacer(observe=clocks.observe).pace("new")
    assert clocks.host >= NOW + timedelta(minutes=1)
    clocks.admit("new")


def test_real_work_refills_capacity_without_an_extra_minute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clocks = Clocks(history={str(index): NOW for index in range(5)})
    clocks.advance(90)
    monkeypatch.setattr(pacing, "time", clocks)
    pacing.CorrelationPacer(observe=clocks.observe).pace("new")
    clocks.admit("new")
    assert not clocks.sleeps


def test_a_new_group_uses_remaining_capacity_without_forcing_a_full_refill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clocks = Clocks(history={str(index): NOW for index in range(4)})
    monkeypatch.setattr(pacing, "time", clocks)
    pacing.CorrelationPacer(observe=clocks.observe).pace("fifth")
    clocks.admit("fifth")
    assert not clocks.sleeps
    pacing.CorrelationPacer(observe=clocks.observe).pace("sixth")
    clocks.admit("sixth")
    assert clocks.sleeps


def test_rolling_hour_and_burst_boundaries_are_both_enforced() -> None:
    probe.assert_installed_policy()
    history = tuple(NOW + timedelta(minutes=index) for index in range(60))
    denied = NOW + timedelta(minutes=59, seconds=1)
    allowed = probe.eligible_at(history, denied)
    assert allowed == NOW + timedelta(hours=1)
    with pytest.raises(CorrelationRateLimitError, match="rolling-hour"):
        _admit_rate(history, allowed - probe.MICROSECOND)
    _admit_rate(history, allowed)


def test_earliest_eligibility_matches_unchanged_runtime_over_varied_histories() -> None:
    rng = random.Random(20260918)  # noqa: S311 - reproducible synthetic timing histories
    for _ in range(10):
        now = NOW
        history: list[datetime] = []
        for _ in range(100):
            now += timedelta(seconds=rng.uniform(-25, 120))
            eligible = probe.eligible_at(tuple(history), now)
            _admit_rate(tuple(history), eligible)
            if eligible > now:
                with pytest.raises(CorrelationRateLimitError):
                    _admit_rate(tuple(history), eligible - probe.MICROSECOND)
            history.append(eligible)
            now = eligible


def test_impossible_history_fails_instead_of_inventing_future_capacity() -> None:
    with pytest.raises(CorrelationRateLimitError):
        probe.eligible_at((NOW,) * 6, NOW + timedelta(days=1))


def test_a_slow_or_stalled_host_clock_has_a_bounded_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    clocks = Clocks(host_rate=0, history={str(index): NOW for index in range(5)})
    monkeypatch.setattr(pacing, "time", clocks)
    with pytest.raises(AssertionError, match="host admission clock did not reach"):
        pacing.CorrelationPacer(observe=clocks.observe).pace("new")
    assert clocks.elapsed == pacing.WAIT_TIMEOUT_SECONDS


@pytest.mark.parametrize(
    "observation",
    [
        {},
        {"recorded": True},
        {"recorded": "yes", "host_now_us": 1, "eligible_at_us": 1},
        {"recorded": False, "host_now_us": True, "eligible_at_us": 1},
        {"recorded": False, "host_now_us": 2, "eligible_at_us": 1},
        {"recorded": False, "host_now_us": -1, "eligible_at_us": 1},
        {"recorded": False, "host_now_us": 1, "eligible_at_us": 1, "extra": "private-canary"},
    ],
)
def test_unknown_or_malformed_observation_never_grants_capacity(
    observation: dict[str, object],
) -> None:
    with pytest.raises(AssertionError, match="invalid installed admission observation"):
        pacing.CorrelationPacer(observe=lambda identity: observation).pace("new")


def write_record(directory: Path) -> Path:
    record = json.loads(
        (ROOT / "tests/static-publication/fixtures/accepted/authorization-job.json").read_text()
    )
    path = directory / f"{IDENTITY}.json"
    path.write_text(json.dumps(record))
    return path


def test_history_reads_only_immutable_bindings_and_returns_no_private_fields(
    tmp_path: Path,
) -> None:
    path = write_record(tmp_path)
    original = path.read_bytes()
    history = probe.history_from(tmp_path)
    assert history == {IDENTITY: datetime(2026, 8, 29, 12, 0, 1, tzinfo=UTC)}
    assert probe.observation(history, IDENTITY, NOW) == {
        "recorded": True,
        "host_now_us": (NOW - probe.EPOCH) // probe.MICROSECOND,
        "eligible_at_us": (NOW - probe.EPOCH) // probe.MICROSECOND,
    }
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    "problem",
    [
        "missing",
        "symlink-directory",
        "symlink-record",
        "fifo",
        "oversize",
        "corrupt",
        "filename",
        "binding",
        "excess",
    ],
)
def test_unavailable_or_invalid_history_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, problem: str
) -> None:
    directory = tmp_path / "history"
    directory.mkdir()
    path = write_record(directory)
    if problem == "missing":
        path.unlink()
        directory.rmdir()
    elif problem == "symlink-directory":
        link = tmp_path / "link"
        link.symlink_to(directory, target_is_directory=True)
        directory = link
    elif problem in {"symlink-record", "fifo"}:
        path.unlink()
        if problem == "fifo":
            os.mkfifo(path)
        else:
            path.symlink_to("/dev/zero")
    elif problem == "oversize":
        monkeypatch.setattr(probe, "MAX_RECORD_BYTES", 10)
    elif problem == "corrupt":
        path.write_text("private-canary")
    elif problem == "filename":
        path.rename(path.with_suffix(".txt"))
    elif problem == "binding":
        value = json.loads(path.read_text())
        value["request"]["correlationId"] = "0198d17f-6f4a-7000-8000-000000000099"
        path.write_text(json.dumps(value))
    else:
        monkeypatch.setattr(probe, "MAX_CORRELATIONS", 0)
    with pytest.raises((ValueError, OSError)):
        probe.history_from(directory)
