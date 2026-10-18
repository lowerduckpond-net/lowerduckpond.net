from __future__ import annotations

import os
import signal
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import parser_budget as budget


class _Timer:
    def __init__(self) -> None:
        self.now = 0.0
        self.timer = (0.0, 0.0)
        self.arms: list[float] = []
        self.armed_at = 0.0

    def set(self, _kind: int, seconds: float, interval: float = 0.0) -> tuple[float, float]:
        previous = self.timer
        self.timer = (seconds, interval)
        self.armed_at = self.now
        if seconds:
            self.arms.append(seconds)
        return previous


@pytest.fixture
def timer(monkeypatch: pytest.MonkeyPatch) -> _Timer:
    value = _Timer()
    monkeypatch.setattr(budget, "_clock", lambda: value.now)
    monkeypatch.setattr("lowerduckpond_static_host_agent.parser_budget.signal.setitimer", value.set)
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.parser_budget.signal.getitimer",
        lambda _kind: (
            (max(0, value.timer[0] - (value.now - value.armed_at)), value.timer[1])
            if value.timer[0]
            else value.timer
        ),
    )
    return value


def test_sequential_and_nested_parser_calls_share_one_cumulative_budget(timer: _Timer) -> None:
    @budget.bounded_parser_work
    def inner() -> None:
        timer.now += 80

    @budget.bounded_parser_work
    def outer() -> None:
        timer.now += 20
        inner()

    with budget.parser_work_budget():
        outer()
        timer.now += 900  # provider waiting outside parser work consumes no parser budget
        inner()
        assert timer.arms == [budget.PARSER_WORK_SECONDS, budget.PARSER_WORK_SECONDS - 100]
        active = budget._active
        assert active is not None
        assert active.remaining == budget.PARSER_WORK_SECONDS - 180
    assert budget._active is None
    assert timer.timer == (0.0, 0.0)


def test_exceptions_charge_work_and_cannot_renew_an_exhausted_budget(timer: _Timer) -> None:
    @budget.bounded_parser_work
    def fail() -> None:
        timer.now += budget.PARSER_WORK_SECONDS
        raise ValueError("synthetic parse failure")

    @budget.bounded_parser_work
    def forbidden() -> None:
        pytest.fail("exhausted parser must never execute again")

    with budget.parser_work_budget():
        with pytest.raises(budget.ParserBudgetError, match=r"ownership was lost|exhausted"):
            fail()
        with pytest.raises(budget.ParserBudgetError, match="exhausted"):
            forbidden()
        with (
            pytest.raises(budget.ParserBudgetError, match="cannot be replaced"),
            budget.parser_work_budget(),
        ):
            pytest.fail("active budget must not be replaced")
    assert timer.timer == (0.0, 0.0)


@pytest.mark.parametrize("conflict", ["timer", "handler", "blocked", "pending"])
def test_existing_signal_ownership_is_rejected_without_modification(
    timer: _Timer, monkeypatch: pytest.MonkeyPatch, conflict: str
) -> None:
    if conflict == "timer":
        timer.timer = (10.0, 2.0)
    elif conflict == "handler":
        monkeypatch.setattr(
            "lowerduckpond_static_host_agent.parser_budget.signal.getsignal",
            lambda _sig: signal.SIG_IGN,
        )
    elif conflict == "blocked":
        monkeypatch.setattr(
            "lowerduckpond_static_host_agent.parser_budget.signal.pthread_sigmask",
            lambda *_args: {signal.SIGALRM},
        )
    else:
        monkeypatch.setattr(
            "lowerduckpond_static_host_agent.parser_budget.signal.sigpending",
            lambda: {signal.SIGALRM},
        )
    before = timer.timer
    with pytest.raises(budget.ParserBudgetError), budget.parser_work_budget():
        pytest.fail("incompatible signal state must fail closed")
    assert budget._active is None
    assert timer.arms == []
    assert timer.timer == before


def test_other_thread_and_inherited_process_cannot_escape_active_budget(
    timer: _Timer, monkeypatch: pytest.MonkeyPatch
) -> None:
    @budget.bounded_parser_work
    def forbidden() -> None:
        pytest.fail("wrong thread or process must not parse")

    with budget.parser_work_budget():
        with (
            ThreadPoolExecutor(max_workers=1) as pool,
            pytest.raises(budget.ParserBudgetError, match="original main thread"),
        ):
            pool.submit(forbidden).result(timeout=10)
        original = os.getpid()
        monkeypatch.setattr(
            "lowerduckpond_static_host_agent.parser_budget.os.getpid", lambda: original + 1
        )
        with pytest.raises(budget.ParserBudgetError, match="original main thread"):
            forbidden()
    assert not timer.arms


def test_real_parser_is_terminated_and_leaves_recovery_obligation(tmp_path: Path) -> None:
    # Exercise the actual decorated parser in a disposable process. A private
    # shortened test budget avoids sleeping for the real security deadline.
    # The test asserts signal termination and preserved state, not wall duration.
    script = """
import os, signal, sys
from pathlib import Path
from lowerduckpond_static_host_agent import parser_budget as budget
from lowerduckpond_static_host_agent import zip_structure as parser
root = Path(sys.argv[1])
intent = root / 'intent'
intent.write_text('retained durable obligation')
artifact = root / 'input.zip'
artifact.write_bytes(b'PK' + b'\\0' * 64)
artifact.chmod(0o600)
def stuck(*args, **kwargs):
    signal.pause()
parser._validate_snapshot = stuck
with budget.parser_work_budget():
    budget._active.remaining = 0.1
    try:
        parser.inspect_deployment_zip(artifact, expected_owner=os.geteuid())
    except BaseException:
        (root / 'caught').write_text('must not catch a kernel termination')
    (root / 'result').write_text('must not publish success')
"""
    result = subprocess.run(  # noqa: S603 - fixed disposable parser test
        [sys.executable, "-c", script, str(tmp_path)], capture_output=True, timeout=15, check=False
    )
    assert result.returncode == -signal.SIGALRM, result.stderr
    assert (tmp_path / "intent").read_text() == "retained durable obligation"
    assert not (tmp_path / "result").exists()
    assert not (tmp_path / "caught").exists()


@pytest.mark.parametrize("changed", [(0.0, 0.0), (299.0, 1.0), (400.0, 0.0)])
@pytest.mark.parametrize("nested", [False, True])
def test_lost_timer_ownership_poisons_budget_even_if_error_is_caught(
    timer: _Timer, changed: tuple[float, float], nested: bool
) -> None:
    @budget.bounded_parser_work
    def inner() -> None:
        pytest.fail("a changed timer cannot permit more parser work")

    @budget.bounded_parser_work
    def tampered() -> None:
        timer.timer = changed
        if nested:
            with pytest.raises(budget.ParserBudgetError, match="ownership was lost"):
                inner()

    with budget.parser_work_budget():
        with pytest.raises(budget.ParserBudgetError, match="ownership was lost"):
            tampered()
        with pytest.raises(budget.ParserBudgetError, match="exhausted"):
            inner()
    assert timer.timer == (0.0, 0.0)


def test_failed_timer_installation_cannot_be_retried_with_fresh_budget(
    timer: _Timer, monkeypatch: pytest.MonkeyPatch
) -> None:
    @budget.bounded_parser_work
    def forbidden() -> None:
        pytest.fail("an unarmed timer cannot permit parser work")

    def failed(*_args: object) -> None:
        raise OSError("synthetic kernel failure")

    with budget.parser_work_budget():
        monkeypatch.setattr(
            "lowerduckpond_static_host_agent.parser_budget.signal.setitimer", failed
        )
        with pytest.raises(OSError):
            forbidden()
        monkeypatch.setattr(
            "lowerduckpond_static_host_agent.parser_budget.signal.setitimer", timer.set
        )
        with pytest.raises(budget.ParserBudgetError, match="exhausted"):
            forbidden()
