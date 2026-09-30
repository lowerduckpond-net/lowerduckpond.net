"""Real process deadlines preserve failure evidence outside the cancelled controller."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scripts import qualification_deadline as deadline
from scripts.qualification_storage_lease import FD_ENV

ROOT = Path(__file__).parents[2]
TIMEOUT = 124
FAILED = 7
CANARY = "private-provider-token-never-in-report"


@pytest.mark.parametrize("status", [0, FAILED, TIMEOUT, 128 + signal.SIGKILL])
def test_ordinary_exit_is_not_reclassified_as_deadline(status: int) -> None:
    result = deadline.execute(
        [sys.executable, "-c", f"raise SystemExit({status})"], os.environ, seconds=10, grace=1
    )
    assert result.status == status
    assert result.reason == "command-exit"
    assert result.direct_child_reaped


def test_supervised_child_retains_existing_storage_lease_descriptor(tmp_path: Path) -> None:
    lease = tmp_path / "lease"
    lease.write_bytes(b"owned-test-lease")
    with lease.open("rb") as stream:
        result = deadline.execute(
            [
                sys.executable,
                "-c",
                "import os; assert os.read(int(os.environ['LDP_QUALIFICATION_STORAGE_LEASE_FD']), "
                "32) == b'owned-test-lease'",
            ],
            {**os.environ, FD_ENV: str(stream.fileno())},
            seconds=10,
        )
        assert result.status == 0


def test_deadline_overrides_successful_term_handler_and_stops_descendants(tmp_path: Path) -> None:
    child_pid = tmp_path / "child.pid"
    command = """
import os, signal, sys, time
pid = os.fork()
if pid == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(1)
with open(sys.argv[1], 'w') as stream:
    stream.write(str(pid))
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True:
    time.sleep(1)
"""
    result = deadline.execute(
        [sys.executable, "-c", command, str(child_pid)], os.environ, seconds=0.5, grace=0.2
    )
    assert result.status == TIMEOUT
    assert result.reason == "deadline-exceeded"
    # A killed descendant may await the namespace's PID 1 reaper, but must no
    # longer be executing. No unrelated process or caller group is signalled.
    status = Path("/proc") / child_pid.read_text() / "stat"
    for _ in range(100):
        if not status.exists() or status.read_text().split()[2] == "Z":
            break
        time.sleep(0.01)
    else:
        pytest.fail("timed-out controller left an executing descendant")


@pytest.fixture
def journey(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    checkout = tmp_path / "checkout"
    (checkout / "scripts").mkdir(parents=True)
    run = tmp_path / "run"
    run.mkdir(mode=0o700)
    script = checkout / "scripts/m3-10-spaces-qualification"
    script.write_text(
        f"#!{sys.executable}\n"
        + """
import os, signal, sys, time
from pathlib import Path
from scripts import qualification_deadline as deadline
from scripts import qualification_timing as timing
run = Path(os.environ['TEST_RUN'])
os.environ['DOCKER_HOST'] = 'unix:///disposable/docker.sock'
timing._tool_output = lambda *_: 'unknown'
timing.start_run(run, 'spaces')
os.environ[timing.EVENT_ENV] = str(run / 'timing-events.jsonl')
deadline.record(run, 'verify')
if os.environ['TEST_RESULT'] in ('timeout', 'killed'):
    with timing.measure('verify'):
        pass
    with (run / 'timing-events.jsonl').open('a') as stream:
        stream.write('{"incomplete":')
    if os.environ['TEST_RESULT'] == 'killed':
        os.kill(os.getpid(), signal.SIGKILL)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    while True:
        time.sleep(1)
raise SystemExit(int(os.environ['TEST_RESULT']))
"""
    )
    script.chmod(0o700)
    monkeypatch.setattr(deadline, "ROOT", checkout)
    monkeypatch.setattr(deadline, "LIVE_SECONDS", 0.8)
    monkeypatch.setenv("PYTHONPATH", str(ROOT))
    monkeypatch.setenv("TEST_RUN", str(run))
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "empty-docker-config"))
    monkeypatch.setenv("DOCKER_CONTEXT", "foreign-parent-context")
    monkeypatch.setenv("SPACES_SECRET_ACCESS_KEY", CANARY)
    return run


@pytest.mark.parametrize("result", ["0", str(FAILED), "timeout", "killed"])
def test_supervisor_collects_actual_result_and_phase_after_workflow_stops(
    journey: Path, monkeypatch: pytest.MonkeyPatch, result: str
) -> None:
    monkeypatch.setenv("TEST_RESULT", result)
    expected = {"timeout": TIMEOUT, "killed": 128 + signal.SIGKILL}.get(result)
    if expected is None:
        expected = int(result)
    assert deadline.run() == expected
    exit_report = json.loads((journey / "qualification-exit.json").read_text())
    assert exit_report["status"] == expected
    assert exit_report["phase"] == "verify"
    assert exit_report["reason"] == {"timeout": "deadline-exceeded", "killed": "interrupted"}.get(
        result, "command-exit"
    )
    assert exit_report["direct_child_reaped"] is True
    assert exit_report["authority"] == "diagnostic-only"
    assert json.loads((journey / "timing.json").read_text())["exit_status"] == expected
    if result in {"timeout", "killed"}:
        assert json.loads((journey / "timing.json").read_text())["event_count"] == 1
        assert (journey / "timing-events.jsonl").read_bytes().endswith(b'{"incomplete":')
    assert not (journey / "qualification.json").exists()
    if expected:
        report = json.loads((journey / "failure.json").read_text())
        assert report["original_exit_status"] == expected
        assert report["phase"] == "verify"
        if result == "timeout":
            assert report["controller_failure"]["stage"] == "full-run-deadline"
            assert report["controller_failure"]["category"] == "timeout"
    else:
        assert not (journey / "failure.json").exists()
    assert all(CANARY not in path.read_text() for path in journey.glob("*.json"))


def test_unreapable_controller_preserves_timeout_and_collects_diagnostics(
    journey: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("TEST_RESULT", "timeout")
    original_wait = subprocess.Popen.wait
    controller: list[subprocess.Popen[bytes]] = []

    def wait(child: subprocess.Popen[bytes], timeout: float | None = None) -> int:
        if isinstance(child.args, list) and child.args[0] == str(
            deadline.ROOT / "scripts/m3-10-spaces-qualification"
        ):
            if child in controller:
                # Kernel I/O stalls cannot be safely induced in a test. Inject
                # both exhausted shutdown waits after a real controller deadline.
                assert timeout is not None
                raise subprocess.TimeoutExpired(CANARY, timeout)
            controller.append(child)
        return original_wait(child, timeout=timeout)

    monkeypatch.setattr(subprocess.Popen, "wait", wait)
    try:
        assert deadline.run() == TIMEOUT
        receipt = json.loads((journey / "qualification-exit.json").read_text())
        assert receipt["status"] == TIMEOUT
        assert receipt["reason"] == "deadline-exceeded"
        assert receipt["direct_child_reaped"] is False
        assert json.loads((journey / "failure.json").read_text())["original_exit_status"] == TIMEOUT
        output = capsys.readouterr().err
        assert "could not be reaped after SIGKILL" in output
        assert CANARY not in output
    finally:
        for child in controller:
            original_wait(child, timeout=5)


def test_reporter_failure_cannot_replace_original_timeout(
    journey: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_RESULT", "timeout")
    original = deadline.execute

    def execute(
        command: list[str], environment: dict[str, str], *, seconds: float
    ) -> deadline.Exit:
        if "report" in command:
            assert environment["DOCKER_HOST"] == "unix:///disposable/docker.sock"
            assert "DOCKER_CONTEXT" not in environment
            return original(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                environment,
                seconds=0.1,
                grace=0.1,
            )
        return original(command, environment, seconds=seconds, grace=0.1)

    monkeypatch.setattr(deadline, "execute", execute)
    assert deadline.run() == TIMEOUT
    assert json.loads((journey / "qualification-exit.json").read_text())["status"] == TIMEOUT
    assert not (journey / "qualification.json").exists()


def test_controller_interruption_is_forwarded_without_killing_supervisor(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    result = tmp_path / "result.json"
    program = """
import json, os, sys
from dataclasses import asdict
from pathlib import Path
from scripts.qualification_deadline import execute
child = ('from pathlib import Path; import time; Path('
         + repr(sys.argv[1]) + ').touch(); time.sleep(10)')
result = execute([sys.executable, '-c', child], os.environ, seconds=10, grace=0.1)
Path(sys.argv[2]).write_text(json.dumps(asdict(result)))
"""
    process = subprocess.Popen(  # noqa: S603 - disposable supervisor and sleeping child
        [sys.executable, "-c", program, str(ready), str(result)],
        cwd=ROOT,
    )
    try:
        for _ in range(500):
            if ready.exists():
                break
            time.sleep(0.01)
        assert ready.exists()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=5) == 0
        observed = json.loads(result.read_text())
        assert observed["status"] == 128 + signal.SIGTERM
        assert observed["reason"] == "interrupted"
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


@pytest.mark.parametrize("shape", ["symlink", "fifo", "oversized", "extra-fields"])
def test_context_refuses_redirected_or_malformed_channel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    path = tmp_path / "context.json"
    monkeypatch.setenv(deadline.CONTEXT_ENV, str(path))
    monkeypatch.setenv("DOCKER_HOST", "unix:///disposable/docker.sock")
    deadline.record(tmp_path, "verify")
    assert deadline.context(path) == (tmp_path, "verify", "unix:///disposable/docker.sock")
    if shape == "symlink":
        target = path.with_suffix(".saved")
        path.rename(target)
        path.symlink_to(target)
    elif shape == "fifo":
        path.unlink()
        os.mkfifo(path, 0o600)
    elif shape == "oversized":
        path.write_bytes(b"x" * (deadline.MAX_CONTEXT_BYTES + 1))
    else:
        path.write_text(
            json.dumps(
                {
                    "directory": str(tmp_path),
                    "phase": "verify",
                    "docker_host": "unix:///disposable/docker.sock",
                    "secret": CANARY,
                }
            )
        )
    with pytest.raises((OSError, ValueError)):
        deadline.context(path)
