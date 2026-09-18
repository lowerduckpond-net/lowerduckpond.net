from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from lowerduckpond_static_host_agent import archive_configuration

from scripts import qualification_failure as failure
from scripts import qualification_probe as probe
from scripts import qualification_timing as timing
from scripts.m3_10_qualification_report import verify_report

FAILURE_STATUS = 2
COMMAND_DEADLINE_TEST_SECONDS = 3
CANARY = "private-credential-object-name-exception-canary"
CORRELATION = "01a0b11c-8fe8-7781-b277-81e5e4c813ba"
JOB = "01a0b11d-7e30-754f-8ad5-44c8a329494d"
CONTAINER = "c" * 64


@pytest.fixture
def directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(timing.EVENT_ENV, str(tmp_path / "timing-events.jsonl"))
    monkeypatch.setenv(timing.CONTEXT_ENV, "archive")
    monkeypatch.setattr(failure, "helper_check", lambda: "not-configured")
    monkeypatch.setattr(failure, "filesystem", lambda path: "ext4")
    (tmp_path / "timing-start.json").write_text(
        json.dumps(
            {
                "source_revision": "a" * 40,
                "backend": "spaces",
                "secret": CANARY,
            }
        )
    )
    failure.record_phase("verify")
    failure.record_submission(
        {"operation": "delete", "correlationId": CORRELATION, "secret": CANARY}
    )
    failure.record_test_failure("assertion")
    (tmp_path / "failure-fixture.json").write_text(json.dumps({"container_id": CONTAINER}))
    return tmp_path


def observation() -> dict[str, object]:
    return {
        "artifact_sha256": "b" * 64,
        "state_filesystem": "ext4",
        "job": {
            "job_id": JOB,
            "correlation_id": CORRELATION,
            "operation": "delete",
            "phase": "completed",
            "execution_validated": True,
            "result_status": "succeeded",
            "result_error": "none",
            "executor_failure": False,
        },
        "local": {**dict.fromkeys(probe.LOCAL_PATHS, 0), "quarantine": False},
        "remote": {"versions_and_markers": 0, "multipart_uploads": 0, "category": "observed"},
    }


def test_failure_summary_is_allowlisted_and_cannot_qualify(
    directory: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    raw = observation()
    raw["secret"] = CANARY
    raw["service"] = {
        "category": "provider_response",
        "code": CANARY,
        "http_status": 403,
        "operation": "put_object",
        "exception": CANARY,
    }
    commands: list[list[str]] = []

    def command(arguments: list[str], **kwargs: object) -> bytes:
        commands.append(arguments)
        return json.dumps(raw).encode()

    monkeypatch.setattr(failure, "bounded_command", command)
    path = failure.collect(directory, 2)
    report = json.loads(path.read_text())
    assert commands[0][3] == CONTAINER
    assert commands[0][-1] == CORRELATION
    assert failure.CONTAINER not in commands[0]
    assert report["original_exit_status"] == FAILURE_STATUS
    assert report["last_submission_disposition"] == "operation-succeeded"
    assert report["cleanup_authority"] == "none"
    assert report["independent_operator_storage_proof"] == "not-collected"
    assert report["observation"]["service"]["code"] == "unknown"
    assert CANARY not in path.read_text() + capsys.readouterr().out
    with pytest.raises(ValueError):
        verify_report(path, source="a" * 40, artifact="b" * 64)
    assert not (directory / "qualification.json").exists()


@pytest.mark.parametrize("response", [None, b"not-json-" + CANARY.encode(), b"[]"])
def test_host_unavailable_or_malformed_produces_unknown_not_zero(
    directory: Path, monkeypatch: pytest.MonkeyPatch, response: bytes | None
) -> None:
    monkeypatch.setattr(failure, "bounded_command", lambda *args, **kwargs: response)
    report = json.loads(failure.collect(directory, 2).read_text())
    assert report["observation"]["local"]["intents"] == "unknown"
    assert report["observation"]["remote"]["versions_and_markers"] == "unknown"
    assert report["last_submission_disposition"] == "unknown"
    assert report["original_exit_status"] == FAILURE_STATUS
    assert CANARY not in json.dumps(report)


def test_unbound_run_does_not_inspect_a_replacement_fixture(
    directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (directory / "failure-fixture.json").unlink()

    def unexpected(*args: object, **kwargs: object) -> None:
        pytest.fail("must not query a later container by name")

    monkeypatch.setattr(failure, "bounded_command", unexpected)
    report = json.loads(failure.collect(directory, 2).read_text())
    assert report["host_observation"] == "unbound"


def test_capture_retains_original_container_identity(
    directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = directory / "failure-fixture.json"
    path.unlink()
    monkeypatch.setattr(failure, "bounded_command", lambda *args, **kwargs: CONTAINER.encode())
    failure.capture_fixture()
    monkeypatch.setattr(failure, "bounded_command", lambda *args, **kwargs: b"d" * 64)
    failure.capture_fixture()
    assert json.loads(path.read_text())["container_id"] == CONTAINER


def test_manual_collection_is_fresh_and_retains_original_failure(
    directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = observation()
    raw["job"] = {"phase": "claimed", "execution_validated": False}
    monkeypatch.setattr(
        failure, "bounded_command", lambda *args, **kwargs: json.dumps(raw).encode()
    )
    first = failure.collect(directory, 2)
    original = first.read_bytes()
    raw.update(observation())
    second = failure.collect(directory)
    assert first.read_bytes() == original
    assert first != second
    old, new = json.loads(original), json.loads(second.read_bytes())
    assert old["last_submission_disposition"] == "unresolved-recovery"
    assert new["last_submission_disposition"] == "operation-succeeded"
    assert new["original_exit_status"] == old["original_exit_status"] == FAILURE_STATUS
    assert new["observation_started_at"] > old["observation_started_at"]


def test_manual_collection_keeps_original_phase_and_refuses_new_exit_status(
    directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(failure, "bounded_command", lambda *args, **kwargs: None)
    failure.collect(directory, FAILURE_STATUS, "provider-preflight")
    failure.record_phase("destroy")
    report = json.loads(failure.collect(directory).read_text())
    assert report["phase"] == "provider-preflight"
    with pytest.raises(ValueError, match="cannot change"):
        failure.collect(directory, 7)


def test_later_test_and_submission_cannot_replace_first_failure_context(
    directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = (directory / "failure-test.json").read_bytes()
    monkeypatch.setenv(timing.CONTEXT_ENV, "accounting")
    failure.record_submission({"operation": "create", "correlationId": JOB})
    failure.record_test_failure("test-error", file="test_archive_completion.py", line=13)
    assert (directory / "failure-test.json").read_bytes() == original
    monkeypatch.setattr(failure, "bounded_command", lambda *args, **kwargs: None)
    report = json.loads(failure.collect(directory, FAILURE_STATUS).read_text())
    assert report["group"] == "archive"
    assert report["failure_category"] == "assertion"
    assert report["last_submission"] == {"operation": "delete", "correlation_id": CORRELATION}


def test_submission_after_first_failure_cannot_fill_missing_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(timing.EVENT_ENV, str(tmp_path / "timing-events.jsonl"))
    monkeypatch.setenv(timing.CONTEXT_ENV, "archive")
    failure.record_test_failure("assertion")
    failure.record_submission({"operation": "delete", "correlationId": CORRELATION})
    group, submission, correlation = failure._last_submission(tmp_path)
    assert group == "archive"
    assert submission["operation"] == correlation == "unknown"


def test_failure_observation_survives_teardown_and_is_not_claimed_fresh(
    directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        failure, "bounded_command", lambda *args, **kwargs: json.dumps(observation()).encode()
    )
    failure.capture_failure_observation()
    failure.record_phase("destroy")
    assert json.loads((directory / "failure-phase.json").read_text())["phase"] == "verify"
    snapshot = json.loads((directory / "failure-snapshot.json").read_text())
    monkeypatch.setattr(failure, "bounded_command", lambda *args, **kwargs: None)
    report = json.loads(failure.collect(directory, FAILURE_STATUS).read_text())
    assert report["observation_origin"] == "captured-before-teardown"
    assert report["observation_started_at"] == snapshot["started_at"]
    assert report["observation_completed_at"] == snapshot["completed_at"]
    assert report["host_observation"] == "unavailable"
    assert report["last_submission_disposition"] == "operation-succeeded"
    assert report["cleanup_authority"] == "none"
    # A later readable host wins over the historical snapshot.
    raw = observation()
    raw["job"] = {"phase": "claimed", "execution_validated": False}
    monkeypatch.setattr(
        failure, "bounded_command", lambda *args, **kwargs: json.dumps(raw).encode()
    )
    current = json.loads(failure.collect(directory).read_text())
    assert current["observation_origin"] == "fresh"
    assert current["last_submission_disposition"] == "unresolved-recovery"


def test_terminal_job_and_other_local_obligations_remain_distinct() -> None:
    raw = observation()
    raw["local"] = {"intents": 1}
    observed = probe.sanitize(raw)
    assert failure.disposition(observed) == "operation-succeeded"
    assert failure.local_obligations(observed) == "present"


@pytest.mark.parametrize(("path", "crosses"), [("/", False), ("/proc", True)])
def test_mount_diagnostic_uses_actual_mount_ids(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    crosses: bool,
) -> None:
    monkeypatch.setattr("scripts.qualification_failure.tempfile.gettempdir", lambda: path)
    assert failure.temporary_crosses_mount() is crosses


@pytest.mark.parametrize(
    ("job", "local", "expected"),
    [
        (
            {
                "phase": "failed",
                "result_status": "failed",
                "execution_validated": True,
                "executor_failure": False,
            },
            {},
            "validated-rollback-recorded",
        ),
        (
            {
                "phase": "failed",
                "result_status": "failed",
                "execution_validated": True,
                "executor_failure": True,
            },
            {},
            "validated-failure-before-execution",
        ),
        (
            {"phase": "failed", "result_status": "failed", "execution_validated": False},
            {},
            "unresolved-recovery",
        ),
        ({}, {"intents": 1}, "unknown"),
        ({}, {"quarantine": True}, "unknown"),
        ({}, {"intake": "unknown"}, "unknown"),
    ],
)
def test_terminal_dispositions_do_not_treat_absent_intents_as_success(
    job: dict[str, object], local: dict[str, object], expected: str
) -> None:
    raw = observation()
    raw["job"] = job
    raw["local"] = {**dict.fromkeys(probe.LOCAL_PATHS, 0), "quarantine": False, **local}
    assert failure.disposition(probe.sanitize(raw)) == expected


@pytest.mark.parametrize("field", ["phase", "category", "operation", "correlationId"])
def test_context_never_serializes_unknown_text(directory: Path, field: str) -> None:
    (directory / "failure-test.json").unlink()
    failure.record_phase(CANARY)
    failure.record_submission({"operation": "delete", "correlationId": CORRELATION, field: CANARY})
    failure.record_test_failure(CANARY)
    for name in ("phase", "test", "submission"):
        assert CANARY not in (directory / f"failure-{name}.json").read_text()


@pytest.mark.parametrize("shape", ["fifo", "symlink", "directory", "oversize"])
def test_record_reads_are_bounded_and_do_not_follow_special_files(
    tmp_path: Path, shape: str
) -> None:
    path = tmp_path / "input"
    if shape == "fifo":
        os.mkfifo(path)
    elif shape == "symlink":
        target = tmp_path / "secret"
        target.write_text(CANARY)
        path.symlink_to(target)
    elif shape == "directory":
        path.mkdir()
    else:
        path.write_bytes(b" " * (probe.MAX_BYTES + 1))
    with pytest.raises((ValueError, OSError)):
        probe.document(path)


def test_command_time_and_output_limits_apply_to_real_processes() -> None:
    started = time.monotonic()
    assert (
        probe.bounded_command([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.1)
        is None
    )
    assert time.monotonic() - started < COMMAND_DEADLINE_TEST_SECONDS
    assert probe.bounded_command([sys.executable, "-c", "print('x' * 100000)"]) is None
    assert probe.bounded_command([sys.executable, "-c", "print('bounded')"]) == b"bounded\n"
    assert probe.bounded_command([sys.executable, "-c", "raise SystemExit(7)"]) is None


def test_host_deadline_terminates_even_when_optional_probe_swallows_exceptions() -> None:
    code = """
import signal, time
from scripts import qualification_probe as probe
alarm = signal.alarm
probe.signal.alarm = lambda seconds: alarm(1)
def stalled(correlation):
    try:
        time.sleep(30)
    except Exception:
        time.sleep(30)
probe.probe = stalled
probe.main()
"""
    result = subprocess.run(  # noqa: S603 - fixed deadline regression in an isolated process
        [sys.executable, "-c", code],
        cwd=failure.ROOT,
        capture_output=True,
        check=False,
        timeout=5,
    )
    assert result.returncode == -signal.SIGALRM
    assert result.stdout == b""


def test_provider_errors_and_configuration_errors_have_fixed_categories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing() -> None:
        raise archive_configuration.ArchiveConfigurationError(CANARY)

    monkeypatch.setattr(archive_configuration, "load_archive_configuration", missing)
    assert probe.remote_observation()["category"] == "archive_configuration"

    def denied() -> None:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": CANARY}}, "ListObjectVersions"
        )

    monkeypatch.setattr(archive_configuration, "load_archive_configuration", denied)
    observed = probe.remote_observation()
    assert observed["category"] == "provider_response"
    assert observed["code"] == "access_denied"
    assert observed["operation"] == "list_object_versions"
    assert CANARY not in json.dumps(observed)


def test_unknown_provider_labels_are_not_copied() -> None:
    result = probe.diagnostic(
        f"archive_construction_service_failed category=provider_response operation={CANARY} "
        f"code={CANARY} http_status={CANARY}"
    )
    assert result == {
        "category": "provider_response",
        "operation": "unknown",
        "code": "unknown",
        "http_status": "unknown",
    }


@pytest.mark.parametrize("current", [False, True])
def test_job_observation_uses_contracts_and_checks_result_provenance(
    monkeypatch: pytest.MonkeyPatch,
    current: bool,
) -> None:
    fixture = failure.ROOT / "tests/static-publication/fixtures/accepted"
    job = json.loads((fixture / "authorization-job.json").read_text())
    result = json.loads((fixture / "operation-result.json").read_text())
    if current:
        job.update(
            compatibilityVersion="static-job-v2", executionValidated=True, sourceAuthority=None
        )
    binding = json.loads(json.dumps(job))
    if current:
        binding["executionValidated"] = False
    job["phase"] = "completed"

    def read(path: Path) -> dict[str, object]:
        value = {"correlations": binding, "jobs": job, "results": result}[path.parent.name]
        assert isinstance(value, dict)
        return value

    monkeypatch.setattr(probe, "document", read)
    observed = probe.job_observation(job["request"]["correlationId"])
    assert observed["job_id"] == job["jobId"]
    assert observed["phase"] == "completed"
    assert observed["result_status"] == "succeeded"
    # Legacy records without the execution marker must not imply validation.
    assert observed["execution_validated"] is (True if current else None)
    if current:
        assert failure.disposition(probe.sanitize({"job": observed})) == "operation-succeeded"
    result["provenance"]["jobId"] = JOB
    with pytest.raises(ValueError, match="provenance"):
        probe.job_observation(job["request"]["correlationId"])


def test_directory_inventory_is_bounded_and_refuses_a_symlink(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory"
    inventory.mkdir()
    (inventory / CANARY).touch()
    assert probe.directory_count(inventory) == 1
    link = tmp_path / "link"
    link.symlink_to(inventory, target_is_directory=True)
    with pytest.raises(OSError):
        probe.directory_count(link)


def test_host_probe_drops_raw_journal_and_configuration_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe, "filesystem", lambda path: "ext4")
    monkeypatch.setattr(probe, "directory_count", lambda path: 0)
    monkeypatch.setattr(
        probe,
        "bounded_command",
        lambda *args, **kwargs: (
            f"{CANARY}\narchive_construction_service_failed category=provider_response "
            f"operation=put_object code=access_denied http_status=403 private={CANARY}\n"
        ).encode(),
    )
    selected = Path("/opt/lowerduckpond/static-host-agent") / ("b" * 64)
    monkeypatch.setattr(Path, "resolve", lambda *args, **kwargs: selected)
    monkeypatch.setattr(probe, "job_observation", lambda correlation: observation()["job"])

    def unavailable() -> dict[str, object]:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(probe, "remote_observation", unavailable)
    observed = probe.probe(CORRELATION)
    assert observed["service"] == {
        "category": "provider_response",
        "operation": "put_object",
        "code": "access_denied",
        "http_status": 403,
    }
    assert observed["remote"] == {
        "category": "archive_configuration",
        "versions_and_markers": "unknown",
        "multipart_uploads": "unknown",
        "diagnostic": {
            "category": "archive_configuration",
            "operation": "unknown",
            "code": "unknown",
            "http_status": "unknown",
        },
    }
    assert CANARY not in json.dumps(observed)


@pytest.mark.parametrize("helper", ["missing", "unavailable", "available"])
def test_docker_helper_check_discards_account_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, helper: str
) -> None:
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
    (tmp_path / "config.json").write_text(
        json.dumps({"credsStore": "test", "auths": {CANARY: CANARY}})
    )
    monkeypatch.setattr(
        "scripts.qualification_failure.shutil.which",
        lambda name: None if helper == "missing" else "/fake/helper",
    )
    monkeypatch.setattr(
        failure,
        "bounded_command",
        lambda *args, **kwargs: None if helper == "unavailable" else CANARY.encode(),
    )
    assert failure.helper_check() == helper


@pytest.mark.parametrize("status", [0, 7])
def test_broken_failure_reporter_preserves_command_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    monkeypatch.setattr(timing, "start_run", lambda *args: None)
    monkeypatch.setattr(timing, "finish_run", lambda *args: None)

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(failure, "collect", broken)
    assert (
        timing.run_command([sys.executable, "-c", f"raise SystemExit({status})"], tmp_path)
        == status
    )


def test_standalone_collection_command_accepts_retained_directory(directory: Path) -> None:
    # No fixture binding: this exercises the real command without touching a host.
    (directory / "failure-fixture.json").unlink()
    (directory / "failure-exit.json").write_text('{"exit_status":2}')
    result = subprocess.run(  # noqa: S603 - fixed diagnostic command and disposable inputs
        [
            sys.executable,
            str(failure.ROOT / "scripts/qualification_failure.py"),
            "collect",
            str(directory),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0
    assert "Last submission: unknown; host: unbound" in result.stdout
    assert CANARY not in result.stdout + result.stderr


@pytest.mark.parametrize("status", [0, -1, 256])
def test_failure_report_rejects_non_failure_exit_status(directory: Path, status: int) -> None:
    with pytest.raises(ValueError, match="nonzero"):
        failure.collect(directory, status)


@pytest.mark.parametrize("unavailable", [False, True])
def test_required_tool_presence_omits_paths_and_lookup_errors(
    monkeypatch: pytest.MonkeyPatch, unavailable: bool
) -> None:
    def lookup(name: str) -> str | None:
        if unavailable:
            raise OSError(CANARY)
        return None if name == "rsync" else "/" + CANARY + "/" + name

    monkeypatch.setattr(shutil, "which", lookup)
    tools = failure.required_tools()
    assert set(tools) == set(failure.REQUIRED_TOOLS)
    assert tools == {
        name: "unknown" if unavailable else "missing" if name == "rsync" else "present"
        for name in failure.REQUIRED_TOOLS
    }
    assert CANARY not in json.dumps(tools)
