from __future__ import annotations

import json
import os
import random
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace

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


def test_clock_step_between_probe_and_issuance_reproduces_burst_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clocks = Clocks(history={str(index): NOW for index in range(5)})
    monkeypatch.setattr(pacing, "time", clocks)
    pacer = pacing.CorrelationPacer(observe=clocks.observe)
    pacer.pace("new")
    clocks.host -= timedelta(seconds=56)
    with pytest.raises(CorrelationRateLimitError, match="correlation burst limit is exhausted"):
        clocks.admit("new")


@pytest.mark.parametrize("race", ["clock-step", "competing-admission"])
def test_issuance_rechecks_a_rejected_prediction_without_relaxing_policy(
    monkeypatch: pytest.MonkeyPatch, race: str
) -> None:
    clocks = Clocks(history={str(index): NOW for index in range(5)})
    monkeypatch.setattr(pacing, "time", clocks)
    attempts = []

    def issue() -> str:
        attempts.append(clocks.host)
        if len(attempts) == 1:
            if race == "clock-step":
                clocks.host -= timedelta(seconds=56)
            else:
                clocks.admit("competitor")
        try:
            clocks.admit("new")
        except CorrelationRateLimitError as error:
            assert "new" not in clocks.history
            raise pacing.AdmissionRateLimitError(str(error)) from error
        return "accepted"

    assert pacing.CorrelationPacer(observe=clocks.observe).issue("new", issue) == "accepted"
    assert len(attempts) == 2  # noqa: PLR2004 - rejected prediction, then actual admission
    assert clocks.elapsed < pacing.WAIT_TIMEOUT_SECONDS
    _admit_rate(tuple(clocks.history.values()), clocks.host + timedelta(minutes=1))


def test_repeated_admission_refusals_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    clocks = Clocks()
    monkeypatch.setattr(pacing, "time", clocks)
    attempts = []

    def issue() -> None:
        attempts.append(clocks.host)
        raise pacing.AdmissionRateLimitError("correlation burst limit is exhausted")

    with pytest.raises(pacing.AdmissionRateLimitError, match="burst"):
        pacing.CorrelationPacer(observe=clocks.observe).issue("new", issue)
    assert len(attempts) == pacing.MAX_ADMISSION_ATTEMPTS
    assert not clocks.history


def test_rejection_does_not_reset_the_original_pacing_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clocks = Clocks()
    monkeypatch.setattr(pacing, "time", clocks)

    def issue() -> None:
        clocks.advance(pacing.WAIT_TIMEOUT_SECONDS - 1)
        clocks.history = {str(index): clocks.host for index in range(5)}
        raise pacing.AdmissionRateLimitError("correlation burst limit is exhausted")

    with pytest.raises(AssertionError, match="pacing deadline"):
        pacing.CorrelationPacer(observe=clocks.observe).issue("new", issue)
    assert clocks.elapsed == pacing.WAIT_TIMEOUT_SECONDS


def test_issuance_does_not_retry_other_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    clocks = Clocks()
    monkeypatch.setattr(pacing, "time", clocks)

    def issue() -> None:
        raise RuntimeError("unexpected worker or transport failure")

    with pytest.raises(RuntimeError, match="unexpected worker"):
        pacing.CorrelationPacer(observe=clocks.observe).issue("new", issue)
    assert not clocks.sleeps


@pytest.mark.parametrize("artifact", [None, b"unchanged artifact bytes"])
def test_direct_issuance_repeats_the_same_command_only_after_a_rate_refusal(
    installed_module: Callable[[str], ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    artifact: bytes | None,
) -> None:
    support = installed_module("test_lifecycle")
    helper_pacing = installed_module("correlation_pacing")
    clocks = Clocks()
    monkeypatch.setattr(helper_pacing, "time", clocks)
    monkeypatch.setattr(
        support, "_CORRELATION_PACER", helper_pacing.CorrelationPacer(observe=clocks.observe)
    )
    commands = []

    class Host:
        def run(self, command: str, *arguments: str) -> SimpleNamespace:
            if command.startswith("readlink"):
                return SimpleNamespace(rc=0, stdout="/opt/fixture", stderr="")
            assert len(arguments) == 1
            compile(arguments[0], "<remote-issuance>", "exec")
            commands.append(arguments[0])
            if len(commands) == 1:
                clocks.history = {str(index): clocks.host for index in range(5)}
                return SimpleNamespace(
                    rc=pacing.RATE_LIMIT_EXIT_STATUS,
                    stdout="",
                    stderr="correlation burst limit is exhausted\n",
                )
            clocks.admit(IDENTITY)
            return SimpleNamespace(rc=0, stdout="accepted-job\n", stderr="")

    request = support._request("create" if artifact is None else "deploy", IDENTITY)
    if artifact is None:
        result = support._issue_without_handoff(Host(), request)
    else:
        transport = installed_module("test_transport_recovery")
        result = transport._issue_artifact_without_handoff(Host(), request, artifact)
    assert result == "accepted-job"
    assert len(commands) == 2  # noqa: PLR2004 - same command before and after re-pacing
    assert commands[0] == commands[1]
    assert clocks.sleeps


@pytest.mark.parametrize(
    ("status", "message"),
    [(1, "correlation burst limit is exhausted"), (75, "unexpected remote failure")],
)
def test_direct_issuance_does_not_misclassify_other_errors(
    installed_module: Callable[[str], ModuleType], status: int, message: str
) -> None:
    support = installed_module("test_lifecycle")
    host = SimpleNamespace(
        run=lambda *_arguments: SimpleNamespace(rc=status, stdout="", stderr=message)
    )
    with pytest.raises(AssertionError, match=message):
        support._issue_command(host, "unused")


@pytest.mark.parametrize("reason", sorted(pacing.RATE_LIMIT_MESSAGES))
def test_ssh_issuance_repaces_with_unchanged_request_and_artifact(
    installed_module: Callable[[str], ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    reason: str,
) -> None:
    support = installed_module("test_lifecycle")
    helper_pacing = installed_module("correlation_pacing")
    clocks = Clocks()
    monkeypatch.setattr(helper_pacing, "time", clocks)
    monkeypatch.setattr(
        support, "_CORRELATION_PACER", helper_pacing.CorrelationPacer(observe=clocks.observe)
    )
    requests: list[bytes] = []

    def submit(**arguments: object) -> dict[str, object]:
        path, artifact = arguments["request_path"], arguments["artifact_path"]
        assert isinstance(path, Path) and isinstance(artifact, Path)
        requests.append(path.read_bytes())
        assert artifact.read_bytes() == b"unchanged artifact bytes"
        if len(requests) == 1:
            clocks.history = {str(index): clocks.host for index in range(5)}
            raise support.OperatorClientError(f"operator transport failed: {reason}")
        clocks.admit(IDENTITY)
        return {"status": "succeeded"}

    monkeypatch.setattr(support, "submit", submit)
    result = support._submit(
        tmp_path,
        "fixture-host",
        tmp_path / "key",
        tmp_path / "ssh",
        support._request("deploy", IDENTITY),
        artifact=b"unchanged artifact bytes",
    )
    assert result == {"status": "succeeded"}
    assert len(requests) == 2  # noqa: PLR2004 - one rejected and one accepted submission
    assert requests[0] == requests[1]
    assert clocks.sleeps


def test_ssh_issuance_preserves_an_unrelated_transport_failure(
    installed_module: Callable[[str], ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    support = installed_module("test_lifecycle")
    helper_pacing = installed_module("correlation_pacing")
    clocks = Clocks()
    monkeypatch.setattr(
        support, "_CORRELATION_PACER", helper_pacing.CorrelationPacer(observe=clocks.observe)
    )
    calls = []

    def submit(**arguments: object) -> dict[str, object]:
        calls.append(arguments)
        raise support.OperatorClientError("operator transport failed: peer closed connection")

    monkeypatch.setattr(support, "submit", submit)
    with pytest.raises(support.OperatorClientError, match="peer closed connection"):
        support._submit(
            tmp_path,
            "fixture",
            tmp_path / "key",
            tmp_path / "ssh",
            support._request("create", IDENTITY),
        )
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("status", "message", "rate_limited"),
    [
        (1, "correlation burst limit is exhausted", True),
        (1, "peer closed connection", False),
        (0, "correlation burst limit is exhausted", False),
    ],
)
def test_disconnect_session_recognizes_only_an_explicit_pre_admission_refusal(
    installed_module: Callable[[str], ModuleType],
    tmp_path: Path,
    status: int,
    message: str,
    *,
    rate_limited: bool,
) -> None:
    transport = installed_module("test_transport_recovery")
    ssh = tmp_path / "ssh"
    ssh.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stdin.buffer.read()\n"
        f"sys.stderr.write({message!r})\nraise SystemExit({status})\n"
    )
    ssh.chmod(0o700)
    host = SimpleNamespace(run=lambda *_arguments: SimpleNamespace(rc=1, stdout="", stderr=""))
    with transport._start_operator_session(
        operator_host="fixture-host",
        identity=tmp_path / "key",
        ssh=ssh,
        request=transport.support._request("suspend", IDENTITY),
    ) as process:
        assert process.stdin is None
        process.wait(timeout=5)
        error = transport.support.AdmissionRateLimitError if rate_limited else AssertionError
        with pytest.raises(error, match=message):
            transport._job_id_for_correlation(host, IDENTITY, process)


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
