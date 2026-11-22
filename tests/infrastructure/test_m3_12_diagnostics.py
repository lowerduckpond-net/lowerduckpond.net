"""Persistent evidence and disclosure regressions for the M3.12 launcher."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from importlib import import_module
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import m3_12_diagnostic_transport as transport
from scripts import m3_12_diagnostics as diagnostics
from scripts import m3_12_installed as installed
from scripts import qualification_disposable_cleanup as disposable
from scripts import qualification_local as local
from scripts.m3_12_contracts import decode, validate_diagnostic
from scripts.m3_12_diagnostic_guest import export_record
from scripts.m3_12_diagnostic_store import (
    ATTEMPT_ENV,
    PRIVATE_DIR,
    PRIVATE_FILE,
    ROOT,
    Attempt,
    clock,
    encode,
    failure,
    publish,
    read,
)
from scripts.qualification_case import phase, private_document
from scripts.qualification_context import HOST_ENV, RUN_ENV, run_lease

CANARY = "M3-12-SYNTHETIC-EXCLUDED-OUTPUT"
SETUP_STATUS = 7
CANCELLED = 130
ANSIBLE_FAILED = 2


def test_attempt_exists_before_setup_and_exports_original_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "attempts"
    monkeypatch.setenv("LDP_M3_12_DIAGNOSTIC_ROOT", str(root))
    command = (
        "import pathlib, os, sys;"
        f"start=pathlib.Path(os.environ[{ATTEMPT_ENV!r}])/'0000000000.json';"
        "assert start.is_file();"
        f"print({CANARY!r}); print({CANARY!r}, file=sys.stderr); sys.exit({SETUP_STATUS})"
    )

    def steps(attempt: Attempt, group: str) -> tuple[diagnostics.Step, ...]:
        assert group == "transport-recovery"
        assert attempt.record("0000000000.json")["outcome"] == "not-submitted"
        return (
            diagnostics.Step(
                "dependencies", "controller", "dependencies", (sys.executable, "-c", command)
            ),
        )

    monkeypatch.setattr(diagnostics, "installed_steps", steps)
    assert diagnostics.cli(["run", "transport-recovery"]) == SETUP_STATUS
    attempt = Attempt(next(root.glob("*/*")))
    original = validate_diagnostic((attempt.directory / "original.json").read_bytes())
    exported = decode((attempt.directory / "summary.json").read_bytes(), "diagnostic-summary")
    assert original["process"] == {"exit": SETUP_STATUS}
    assert exported["category"] == "dependencies"
    assert exported["result"] == "failed"
    assert stat.S_IMODE(attempt.directory.stat().st_mode) == PRIVATE_DIR
    assert stat.S_IMODE((attempt.directory / "original.json").stat().st_mode) == PRIVATE_FILE
    for artifact in attempt.directory.glob("*.json"):
        assert CANARY.encode() not in artifact.read_bytes()
    output = capfd.readouterr()
    assert CANARY not in output.out + output.err
    assert str(attempt.directory) in output.out


def test_lost_caller_leaves_durable_start_and_unknown_result(tmp_path: Path) -> None:
    attempt = Attempt.allocate(tmp_path / "attempts")
    code = """
import signal
import sys
from importlib import import_module
from pathlib import Path
from unittest.mock import Mock
from scripts.m3_12_diagnostic_store import Attempt, clock

attempt = Attempt(Path(sys.argv[1]))
with attempt.lock("controller.lock"):
    attempt.append("bootstrap", "systemd", clock())
    print("ready", flush=True)
    signal.pause()
"""
    with subprocess.Popen(  # noqa: S603 - fixed local test child
        [sys.executable, "-c", code, str(attempt.directory)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        text=True,
    ) as observer:
        try:
            assert observer.stdout is not None
            assert observer.stdout.readline() == "ready\n"
        finally:
            observer.kill()
    result = diagnostics.status(attempt)
    assert result["stage"] == "bootstrap"
    assert result["uncertainWork"] is True
    assert result["result"] == "unknown"
    assert "process" not in result
    assert not (attempt.directory / "original.json").exists()
    assert diagnostics.collect(attempt)["omissionCount"] == 1
    assert not (attempt.directory / "summary.json").exists()


def test_installed_successor_progress_survives_interruption(tmp_path: Path) -> None:
    installed.predecessor_progress(tmp_path, "rotation-enabled.started")
    installed.predecessor_progress(tmp_path, "rotation-enabled")
    code = """
import signal
import sys
from importlib import import_module
from pathlib import Path
from scripts.m3_12_installed import successor_stage

with successor_stage(Path(sys.argv[1]), "dark-staging"):
    print("ready", flush=True)
    signal.pause()
"""
    with subprocess.Popen(  # noqa: S603 - fixed local interruption fixture
        [sys.executable, "-c", code, str(tmp_path)], cwd=ROOT, stdout=subprocess.PIPE, text=True
    ) as observer:
        try:
            assert observer.stdout is not None
            assert observer.stdout.readline() == "ready\n"
        finally:
            observer.kill()

    progress = tmp_path / installed.PROGRESS_DIRECTORY
    assert {path.name for path in progress.iterdir()} == {
        "m3-11-rotation-enabled-started.json",
        "m3-11-rotation-enabled-completed.json",
        "dark-staging-started.json",
    }
    completed = read(progress, "m3-11-rotation-enabled-completed.json")
    interrupted = read(progress, "dark-staging-started.json")
    assert interrupted == {
        "format": "lowerduckpond-m3-12-successor-progress-v1",
        "authority": "diagnostic-only",
        "stage": "dark-staging",
        "state": "started",
        "utc": interrupted["utc"],
        "monotonicMs": interrupted["monotonicMs"],
    }
    assert interrupted["monotonicMs"] >= completed["monotonicMs"]
    with (
        pytest.raises(ValueError, match="invalid installed successor progress label"),
        installed.successor_stage(tmp_path, CANARY),
    ):
        pytest.fail("unrecognized diagnostic label was accepted")


def test_successor_progress_failure_preserves_the_original_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(installed, "publish", Mock(side_effect=OSError(CANARY)))
    original = RuntimeError("original fixture error")
    with (
        pytest.raises(RuntimeError) as observed,
        installed.successor_stage(tmp_path, "dark-repeat"),
    ):
        raise original
    assert observed.value is original
    assert capsys.readouterr().err == "Installed successor progress unavailable.\n"


def test_nested_successor_ansible_failure_retains_only_category_and_counts(tmp_path: Path) -> None:
    playbook = tmp_path / f"{CANARY}.yml"
    playbook.write_text(
        json.dumps(
            [
                {
                    "hosts": "all",
                    "gather_facts": False,
                    "tasks": [
                        {
                            "name": CANARY,
                            "ansible.builtin.command": {
                                "argv": [
                                    sys.executable,
                                    "-c",
                                    "import sys;"
                                    f"print({CANARY!r});"
                                    "sys.stderr.write('launch_authority_unavailable\\n');"
                                    "sys.exit(78)",
                                ],
                            },
                            "changed_when": False,
                        }
                    ],
                }
            ]
        )
    )
    result = subprocess.run(  # noqa: S603 - fixed localhost controller, no host changes
        [
            str(Path(sys.executable).with_name("ansible-playbook")),
            "-i",
            f"{CANARY},",
            "-c",
            "local",
            str(playbook),
        ],
        cwd=ROOT,
        env={
            **os.environ,
            "ANSIBLE_CONFIG": str(ROOT / "config/ansible/ansible.cfg"),
            "ANSIBLE_CALLBACK_PLUGINS": str(ROOT / "config/ansible/plugins/callback"),
            "ANSIBLE_CALLBACKS_ENABLED": "ldp_m3_12_successor",
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
            "ANSIBLE_REMOTE_TEMP": str(tmp_path / "remote"),
            installed.APPLY_STAGE_ENV: "enabled-repeat",
            installed.PROGRESS_ROOT_ENV: str(tmp_path),
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    assert result.returncode == ANSIBLE_FAILED
    progress = tmp_path / installed.PROGRESS_DIRECTORY
    failure = read(progress, "enabled-repeat-ansible-failure.json")
    recap = read(progress, "enabled-repeat-ansible-recap.json")
    assert failure["task"] == {
        "action": "command",
        "category": "launch-authority-unavailable",
        "line": 0,
        "source": "unknown",
    }
    assert recap["counts"] == {
        "ok": 0,
        "changed": 0,
        "failures": 1,
        "unreachable": 0,
        "rescued": 0,
        "ignored": 0,
        "skipped": 0,
    }
    for artifact in progress.iterdir():
        assert CANARY.encode() not in artifact.read_bytes()


def test_collection_conflict_preserves_original(tmp_path: Path) -> None:
    attempt = Attempt.allocate(tmp_path / "attempts")
    step = diagnostics.Step("dependencies", "controller", "dependencies", ("/bin/false",))
    assert diagnostics.execute(attempt, [step]) == 1
    original = (attempt.directory / "original.json").read_bytes()
    publish(attempt.directory, "summary.json", {"format": "synthetic-conflict"})
    with pytest.raises(ValueError, match="summary conflict"):
        diagnostics.collect(attempt)
    incident = validate_diagnostic((attempt.directory / attempt.names()[-1]).read_bytes())
    assert incident["failures"][0]["role"] == "collection"
    assert (attempt.directory / "original.json").read_bytes() == original
    assert diagnostics.status(attempt)["process"] == {"exit": 1}


def test_checkpoint_write_failure_preserves_child_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempt = Attempt.allocate(tmp_path / "attempts")
    step = diagnostics.Step("dependencies", "controller", "dependencies", ("/bin/false",))
    original_append = Attempt.append

    def append(self: Attempt, *args: object, **kwargs: object) -> object:
        if kwargs.get("original"):
            raise OSError("synthetic storage failure")
        return original_append(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Attempt, "append", append)
    assert diagnostics.execute(attempt, [step]) == 1
    assert diagnostics.status(attempt)["result"] == "unknown"
    assert attempt.record(attempt.names()[-1])["failures"][0]["role"] == "finalization"


def test_cancel_prevents_new_native_phase_and_hidden_streams(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    attempt = Attempt.allocate(tmp_path / "attempts")
    shell = shutil.which("sh")
    assert shell is not None
    fake_uv = tmp_path / "uv"
    fake_uv.write_text(f"#!{shell}\nprintf '%s\\n' '{CANARY}'\nexit {SETUP_STATUS}\n")
    fake_uv.chmod(0o700)
    environment = {**os.environ, ATTEMPT_ENV: str(attempt.directory)}
    assert phase(attempt.directory, environment, str(fake_uv), "create") == SETUP_STATUS
    assert not (attempt.directory / "create.log").exists()
    output = capfd.readouterr()
    assert CANARY not in output.out + output.err
    publish(attempt.directory, "cancel.json", {"requested": True})
    assert phase(attempt.directory, environment, str(fake_uv), "prepare") == CANCELLED


def test_guest_checkpoint_refuses_unlisted_fields(tmp_path: Path) -> None:
    attempt = Attempt.allocate(tmp_path / "attempts")
    error = RuntimeError(CANARY)
    error.__cause__ = TimeoutError(CANARY)
    result = attempt.append(
        "bootstrap",
        "systemd",
        clock(),
        status=1,
        original=True,
        incident=failure("primary", "process", "systemd", error),
    )
    assert export_record(attempt, "result") == result
    original = attempt.directory / "original.json"
    original.unlink()
    result["raw"] = CANARY
    publish(attempt.directory, original.name, result)
    with pytest.raises(ValueError, match="invalid guest checkpoint"):
        export_record(attempt, "result")


def test_public_guest_collection_reopens_the_original_bound_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "unix:///synthetic-local.sock")
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    environment = local.create_environment(tmp_path)
    daemon = "synthetic-daemon"
    host_id = "a" * 64
    monkeypatch.setattr(disposable, "daemon_id", lambda _environment: daemon)
    identity = Mock(return_value=daemon)
    monkeypatch.setattr(transport, "daemon_id", identity)
    monkeypatch.setattr(transport, "owned_containers", lambda *args, **kwargs: {HOST_ENV: host_id})
    disposable.bind(tmp_path, environment)
    private_document(tmp_path, "failure-fixture.json", {"container_id": host_id})
    attempt = Attempt.allocate(tmp_path / transport.RETAINED_ATTEMPTS)
    owner = {"run_id": environment[RUN_ENV], "container_id": host_id}
    publish(attempt.directory, transport.RETAINED_FIXTURE, owner)
    record = attempt.append("bootstrap", "systemd", clock())
    transfer = Mock(return_value=encode(record))
    monkeypatch.setattr(transport, "bounded_command", transfer)
    arguments = ["collect", str(attempt.directory), "--guest", "start"]

    with run_lease(tmp_path, create=True), pytest.raises(BlockingIOError):
        diagnostics.cli(arguments)
    identity.assert_not_called()
    transfer.assert_not_called()

    identity.return_value = "substituted-daemon"
    with pytest.raises(ValueError, match="retained fixture daemon changed"):
        diagnostics.cli(arguments)
    transfer.assert_not_called()
    identity.return_value = daemon

    companion = attempt.directory / transport.RETAINED_FIXTURE
    companion.unlink()
    publish(attempt.directory, companion.name, {**owner, "container_id": "b" * 64})
    with pytest.raises(ValueError, match="retained attempt fixture changed"):
        diagnostics.cli(arguments)
    transfer.assert_not_called()

    companion.unlink()
    publish(attempt.directory, companion.name, owner)
    assert diagnostics.cli(arguments) == 0
    assert decode(capfd.readouterr().out.encode(), "diagnostic-summary")["result"] == "unknown"
    assert attempt.record("guest-start.json") == record
    assert transfer.call_args.args[0][:3] == ["docker", "exec", host_id]
    assert transfer.call_args.kwargs["timeout"] is None
    assert not (attempt.directory / "original.json").exists()


@pytest.mark.parametrize(
    ("archive_endpoint", "expected"),
    [
        (f"{'a' * 64} 172.21.0.3", "172.21.0.3 ams3.digitaloceanspaces.com"),
        (f"{'b' * 64} 172.21.0.3", None),
        (f"{'a' * 64} 8.8.8.8", None),
        (f"{'a' * 64} 172.21.0.2", None),
        (f"{'a' * 64} 172.21.0.3\n{'b' * 64} 172.22.0.3", None),
    ],
)
def test_successor_archive_route_uses_only_the_original_shared_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, archive_endpoint: str, expected: str | None
) -> None:
    allocation = Mock(
        return_value={"docker": {"roles": {"host": {"id": "host"}, "archive": {"id": "archive"}}}}
    )
    monkeypatch.setattr(installed, "recheck_installed", allocation)
    docker = Mock(side_effect=[f"{'a' * 64} 172.21.0.2".encode(), archive_endpoint.encode()])
    monkeypatch.setattr(installed, "_docker", docker)
    environment = {"M3_10_ARCHIVE_BACKEND": "minio"}
    if expected is None:
        with pytest.raises(ValueError, match=r"^installed-archive-network-(changed|invalid)$"):
            installed.installed_archive_hosts_line(tmp_path, environment)
    else:
        assert installed.installed_archive_hosts_line(tmp_path, environment) == expected
    allocation.assert_called_once_with(tmp_path, environment)
    assert [call.args[-1] for call in docker.call_args_list] == ["host", "archive"]


def test_successor_build_retains_the_artifact_required_for_final_accounting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import qualification_retirement as retirement  # noqa: PLC0415
    from scripts.qualification_context import ARTIFACT_ENV  # noqa: PLC0415

    tests = ROOT / "config/ansible/molecule/m3_8/tests"
    monkeypatch.syspath_prepend(str(tests))
    successor = import_module("test_m3_12_successor")
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    retained = fixture_dir / "static-host-agent.tar"
    predecessor = tmp_path / "accepted-predecessor.tar"
    prior_bytes = b"accepted predecessor archive"
    candidate_bytes = b"built successor archive"
    predecessor.write_bytes(prior_bytes)
    shutil.copyfile(predecessor, retained)
    environment = {ARTIFACT_ENV: str(retained)}
    fixture = Mock(source_artifact=retained, artifact=predecessor, environment=environment)
    directory = tmp_path / "successor"
    directory.mkdir()
    monkeypatch.setattr(successor, "recheck_installed", Mock(return_value={}))

    def run(arguments: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if Path(arguments[0]).name == "build-static-host-agent":
            Path(arguments[1]).write_bytes(candidate_bytes)
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(successor.subprocess, "run", run)
    rollout = successor.Rollout(fixture, Mock(), directory, [])
    digest = rollout.build()
    monkeypatch.setattr(
        retirement,
        "bounded_command",
        Mock(return_value=encode({"state": "quiescent-installed", "artifact_sha256": digest})),
    )

    assert retirement.local_proof(environment, "owned-host") == "quiescent-installed"
    assert predecessor.read_bytes() == prior_bytes
    assert retained.read_bytes() == candidate_bytes
