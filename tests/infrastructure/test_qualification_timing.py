from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import qualification_timing as timing

ROOT = Path(__file__).parents[2]
CANARY = "private-provider-response-canary"
FAILURE_STATUS = 7


@pytest.fixture
def run_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "run"
    directory.mkdir()
    monkeypatch.setattr(timing, "_tool_output", lambda args: CANARY)
    monkeypatch.setenv("SPACES_SECRET_ACCESS_KEY", CANARY)
    monkeypatch.setenv(timing.EVENT_ENV, str(directory / "timing-events.jsonl"))
    monkeypatch.setenv(timing.CONTEXT_ENV, "core")
    timing.start_run(directory, "spaces")
    return directory


def report_text(directory: Path) -> str:
    return (directory / "timing.json").read_text() + (directory / "timing.txt").read_text()


def test_nested_spans_keep_failure_and_do_not_double_count_elapsed(run_directory: Path) -> None:
    with pytest.raises(RuntimeError, match=CANARY), timing.measure("group"):
        with timing.measure("pacing"):
            pass
        with timing.measure("operator"):
            raise RuntimeError(CANARY)
    result = timing.finish_run(run_directory, 1)
    events = timing._events(run_directory / "timing-events.jsonl")
    assert [event["outcome"] for event in events] == ["completed", "failed", "failed"]
    assert sum(event["elapsed_ns"] for event in events) > timing.union_ns(
        [(event["start_ns"], event["start_ns"] + event["elapsed_ns"]) for event in events]
    )
    assert result["exit_status"] == 1
    assert result["authority"] == "diagnostic-only"
    assert result["artifact_sha256"] == "unknown"
    assert CANARY not in report_text(run_directory)


def test_interval_union_handles_overlapping_processes() -> None:
    expected = 25
    assert timing.union_ns([(5, 15), (0, 10), (20, 30), (6, 8)]) == expected


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("uv 0.12.5 (x86_64-unknown-linux-musl)", "0.12.5"),
        ("uv 0.12.5 (abcdef012 2026-09-01)", "0.12.5"),
        (f"uv 0.12.5 {CANARY}", "0.12.5"),
        (CANARY, "unknown"),
    ],
)
def test_uv_build_details_are_excluded_from_version_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str, expected: str
) -> None:
    monkeypatch.setattr(timing, "_tool_output", lambda command: output)
    timing.start_run(tmp_path, "minio")
    metadata = (tmp_path / "timing-start.json").read_text()
    assert json.loads(metadata)["tools"]["uv"] == expected
    assert CANARY not in metadata


@pytest.mark.parametrize("shape", ["symlink", "directory", "fifo"])
def test_event_sink_failure_cannot_replace_test_failure(
    run_directory: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], shape: str
) -> None:
    path = run_directory / "timing-events.jsonl"
    path.unlink()
    if shape == "symlink":
        target = tmp_path / "untouched"
        target.write_text(CANARY)
        path.symlink_to(target)
    elif shape == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)
    with pytest.raises(RuntimeError, match="original"), timing.measure("operator"):
        raise RuntimeError("original")
    assert CANARY not in capsys.readouterr().err
    with pytest.raises((OSError, ValueError)):
        timing.finish_run(run_directory, 1)
    assert not (run_directory / "timing.json").exists()


def test_unknown_labels_and_private_metadata_are_not_published(
    run_directory: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with timing.measure(CANARY):
        pass
    assert timing._events(run_directory / "timing-events.jsonl") == []
    assert CANARY not in capsys.readouterr().err
    path = run_directory / "timing-start.json"
    metadata = json.loads(path.read_text())
    metadata["secret"] = CANARY
    path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="metadata fields"):
        timing.finish_run(run_directory, 0)
    assert not (run_directory / "timing.json").exists()


@pytest.mark.parametrize("field", ["source_revision", "runner", "kernel_version", "tools"])
def test_private_values_in_known_metadata_fields_are_rejected(
    run_directory: Path, field: str
) -> None:
    path = run_directory / "timing-start.json"
    metadata = json.loads(path.read_text())
    metadata[field] = CANARY
    path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError):
        timing.finish_run(run_directory, 0)
    assert not (run_directory / "timing.json").exists()


def test_events_from_a_different_run_are_rejected(run_directory: Path) -> None:
    event = {
        "kind": "group",
        "group": "core",
        "start_ns": 0,
        "elapsed_ns": 10,
        "outcome": "completed",
    }
    (run_directory / "timing-events.jsonl").write_text(json.dumps(event) + "\n")
    with pytest.raises(ValueError, match="different runs"):
        timing.finish_run(run_directory, 0)


@pytest.mark.parametrize("reporter_available", [True, False])
@pytest.mark.parametrize("exit_status", [0, FAILURE_STATUS])
def test_command_wrapper_preserves_the_original_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reporter_available: bool, exit_status: int
) -> None:
    monkeypatch.setattr(timing, "_tool_output", lambda args: "unknown")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    directory = tmp_path / "timing"
    if not reporter_available:
        directory.write_text("unavailable")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "timing",
            "run",
            "--directory",
            str(directory),
            "--",
            "/bin/sh",
            "-c",
            f"exit {exit_status}",
        ],
    )
    assert timing.main() == exit_status
    if reporter_available:
        assert json.loads((directory / "timing.json").read_text())["exit_status"] == exit_status
    else:
        assert directory.read_text() == "unavailable"


@pytest.mark.parametrize("failed", [False, True])
def test_real_ansible_callback_captures_playbook_and_reboot_without_payloads(
    run_directory: Path, tmp_path: Path, failed: bool
) -> None:
    playbook = tmp_path / "prepare.yml"
    playbook.write_text(
        """---
- name: private-provider-response-canary
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Reboot the disposable systemd host
      ansible.builtin.command: /bin/true
      changed_when: false
"""
        + (
            "    - ansible.builtin.fail:\n        msg: private-provider-response-canary\n"
            if failed
            else ""
        )
    )
    environment = timing.child_environment(run_directory)
    environment["ANSIBLE_CONFIG"] = str(ROOT / "config/ansible/ansible.cfg")
    result = subprocess.run(  # noqa: S603 - fixed local playbook; no real host or reboot
        [
            str(ROOT / ".venv/bin/ansible-playbook"),
            "-i",
            "localhost,",
            "-c",
            "local",
            str(playbook),
        ],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert (result.returncode != 0) == failed, result.stdout + result.stderr
    assert "Skipping plugin" not in result.stderr, result.stderr
    events = timing._events(run_directory / "timing-events.jsonl")
    assert [event["kind"] for event in events] == ["reboot", "prepare"]
    assert events[-1]["outcome"] == ("failed" if failed else "completed")
    timing.finish_run(run_directory, result.returncode)
    assert CANARY not in report_text(run_directory)


@pytest.mark.parametrize(
    ("exception", "category"),
    [
        ('AssertionError("private-provider-response-canary")', "assertion"),
        ('OperatorClientError("private-provider-response-canary")', "operator-transport"),
        (
            'OperatorClientError("operator transport failed: '
            'correlation burst limit is exhausted")',
            "admission-burst-exhausted",
        ),
        (
            'OperatorClientError("operator transport failed: tenant lifecycle '
            'is not eligible for ordinary deletion")',
            "ordinary-delete-ineligible",
        ),
    ],
)
@pytest.mark.parametrize(
    ("filename", "group"),
    [("test_lifecycle.py", "core"), ("test_combined_live.py", "combined-reconstruction")],
)
def test_real_pytest_group_retains_a_failed_operator_span(  # noqa: PLR0913
    run_directory: Path,
    tmp_path: Path,
    exception: str,
    category: str,
    filename: str,
    *,
    group: str,
) -> None:
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "conftest.py").write_bytes(
        (ROOT / "config/ansible/molecule/m3_8/tests/conftest.py").read_bytes()
    )
    body = """from scripts.qualification_timing import measure
from scripts.qualification_failure import record_submission
from lowerduckpond_static_operator import OperatorClientError

def test_private_parameter():
    record_submission(
        {'operation': 'archive', 'correlationId': '01a0b11c-8fe8-7781-b277-81e5e4c813ba'}
    )
    with measure("operator"):
        raise FIRST_FAILURE

def test_secondary_failure():
    record_submission(
        {'operation': 'delete', 'correlationId': '01a0b11d-7e30-754f-8ad5-44c8a329494d'}
    )
    raise RuntimeError("private-provider-response-canary")
"""
    (scenario / filename).write_text(body.replace("FIRST_FAILURE", exception))
    commands = tmp_path / "commands"
    commands.mkdir()
    docker = commands / "docker"
    docker.write_text("#!/bin/sh\nprintf 'private-provider-response-canary\\n'\n")
    docker.chmod(0o755)
    environment = timing.child_environment(run_directory)
    environment.update(PYTHONPATH=str(ROOT), PATH=str(commands) + ":" + os.environ["PATH"])
    result = subprocess.run(  # noqa: S603 - private failed test; mock Docker cannot contact a host
        [sys.executable, "-m", "pytest", "-q", str(scenario)],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert json.loads((run_directory / "failure-test.json").read_text()) == {
        "category": category,
        "group": group,
        "file": filename,
        "line": 10,
        "submission": {
            "operation": "archive",
            "correlation_id": "01a0b11c-8fe8-7781-b277-81e5e4c813ba",
            "group": group,
        },
    }
    events = timing._events(run_directory / "timing-events.jsonl")
    assert [(event["kind"], event["group"], event["outcome"]) for event in events] == [
        ("operator", group, "failed"),
        ("group", group, "failed"),
        ("group", group, "failed"),
    ]
    timing.finish_run(run_directory, result.returncode)
    assert CANARY not in report_text(run_directory)


@pytest.mark.parametrize("case", ["protection", "rotation"])
def test_audit_helper_failures_keep_their_allowlisted_group_and_source_location(
    run_directory: Path, tmp_path: Path, case: str
) -> None:
    scenario = tmp_path / "audit-scenario"
    scenario.mkdir()
    (scenario / "conftest.py").write_bytes(
        (ROOT / "config/ansible/molecule/m3_8/tests/conftest.py").read_bytes()
    )
    helper = f"audit_{case}_support"
    (scenario / f"{helper}.py").write_text(f"def fail():\n    raise AssertionError({CANARY!r})\n")
    (scenario / f"test_audit_{case}.py").write_text(
        f"from {helper} import fail\n\ndef test_failure():\n    fail()\n"
    )
    commands = tmp_path / "audit-commands"
    commands.mkdir()
    docker = commands / "docker"
    docker.write_text("#!/bin/sh\nexit 1\n")
    docker.chmod(0o755)
    environment = timing.child_environment(run_directory)
    environment.update(PYTHONPATH=str(ROOT), PATH=str(commands) + ":" + os.environ["PATH"])
    result = subprocess.run(  # noqa: S603 - owned failed test; Docker is a non-network stub
        [sys.executable, "-m", "pytest", "-q", str(scenario)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 1
    location = json.loads((run_directory / "failure-test.json").read_text())
    assert location["file"] == f"{helper}.py" and location["line"] == 2  # noqa: PLR2004
    assert location["group"] == f"audit-{case}"
    assert location["category"] == "assertion" and CANARY not in json.dumps(location)
    timing.finish_run(run_directory, result.returncode)
    report = json.loads((run_directory / "timing.json").read_text())
    assert report["categories"] == [
        {**report["categories"][0], "group": f"audit-{case}", "kind": "group", "failed": 1}
    ]
    assert CANARY not in report_text(run_directory)


@pytest.mark.parametrize("exit_status", [0, FAILURE_STATUS])
def test_failed_summary_does_not_replace_command_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exit_status: int,
) -> None:
    monkeypatch.setattr(timing, "_tool_output", lambda args: "unknown")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    def broken_summary(directory: Path, status: int) -> dict[str, object]:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(timing, "finish_run", broken_summary)
    assert (
        timing.run_command(["/bin/sh", "-c", f"exit {exit_status}"], tmp_path / "run")
        == exit_status
    )


def test_observed_fixture_identity_is_captured_before_destruction(
    run_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, image = "a" * 64, "b" * 64
    monkeypatch.setattr(
        timing,
        "_tool_output",
        lambda args: (
            "/opt/lowerduckpond/static-host-agent/" + artifact
            if args[1] == "exec"
            else "sha256:" + image
        ),
    )
    timing.capture_fixture_identity()
    monkeypatch.setattr(timing, "_tool_output", lambda args: CANARY)
    timing.capture_fixture_identity()
    result = timing.finish_run(run_directory, 0)
    assert result["artifact_sha256"] == artifact
    assert result["image_sha256"] == image
    assert CANARY not in report_text(run_directory)


def test_relative_timing_directory_survives_the_molecule_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(timing, "_tool_output", lambda args: "unknown")
    command = [
        sys.executable,
        "-c",
        (
            "import os,pathlib; "
            "assert pathlib.Path(os.environ['LDP_QUALIFICATION_TIMING_EVENTS']).is_absolute()"
        ),
    ]
    assert timing.run_command(command, Path("relative/run")) == 0
    assert (tmp_path / "relative/run/timing.json").is_file()


def test_interrupted_snapshot_after_real_wrapper_death_retains_original_inputs(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "killed"
    child = (
        "import os,signal; "
        "from scripts.qualification_timing import measure; "
        "\nwith measure('operator'): pass\n"
        "os.kill(os.getppid(), signal.SIGKILL)"
    )
    wrapper = (
        "from pathlib import Path; import sys; "
        "from scripts.qualification_timing import run_command; "
        f"run_command([sys.executable, '-c', {child!r}], Path({str(directory)!r}))"
    )
    result = subprocess.run(  # noqa: S603 - fixed child kills only its own wrapper
        [sys.executable, "-c", wrapper],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        check=False,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == -signal.SIGKILL
    assert not (directory / "timing.json").exists()
    originals = {path.name: path.read_bytes() for path in directory.iterdir()}
    timing.interrupted_run(directory)
    path = directory / "timing-interrupted.json"
    report = json.loads(path.read_text())
    assert report["exit_status"] is None
    assert report["observation"] == "interrupted-run-snapshot"
    assert report["authority"] == "diagnostic-only"
    assert report["event_count"] == 1
    assert report["categories"][0]["kind"] == "operator"
    assert not (directory / "case.json").exists()
    assert not (directory / "failure-exit.json").exists()
    before = path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns
    timing.interrupted_run(directory)
    assert (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns) == before
    assert all((directory / name).read_bytes() == raw for name, raw in originals.items())


def test_interrupted_snapshot_omits_only_incomplete_final_append(run_directory: Path) -> None:
    with timing.measure("operator"):
        pass
    events = run_directory / "timing-events.jsonl"
    with events.open("ab") as stream:
        stream.write(b'{"secret":"' + CANARY.encode())
    original = events.read_bytes()
    timing.interrupted_run(run_directory)
    raw = (run_directory / "timing-interrupted.json").read_text()
    assert CANARY not in raw
    assert json.loads(raw)["event_count"] == 1
    assert events.read_bytes() == original
    with pytest.raises(ValueError):
        timing.finish_run(run_directory, 1)


@pytest.mark.parametrize("target", ["timing-start.json", "timing-events.jsonl"])
def test_interrupted_snapshot_rejects_private_fields_in_complete_records(
    run_directory: Path, target: str
) -> None:
    (run_directory / target).write_text(json.dumps({"secret": CANARY}) + "\n")
    with pytest.raises(ValueError):
        timing.interrupted_run(run_directory)
    assert not (run_directory / "timing-interrupted.json").exists()


@pytest.mark.parametrize("status", [0, FAILURE_STATUS])
def test_interrupted_snapshot_preserves_completed_summary(run_directory: Path, status: int) -> None:
    timing.finish_run(run_directory, status)
    before = report_text(run_directory)
    timing.interrupted_run(run_directory)
    assert report_text(run_directory) == before
    assert not (run_directory / "timing-interrupted.json").exists()


@pytest.mark.parametrize("name", ["timing.json", "timing-interrupted.json"])
def test_interrupted_snapshot_does_not_follow_existing_output_symlink(
    run_directory: Path, tmp_path: Path, name: str
) -> None:
    destination = tmp_path / "absent"
    (run_directory / name).symlink_to(destination)
    timing.interrupted_run(run_directory)
    assert not destination.exists()
    assert (run_directory / name).is_symlink()
