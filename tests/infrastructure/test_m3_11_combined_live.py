"""The live envelope requires original complete assertions and actual teardown."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import m3_11_combined_live as live
from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_10_qualification_report import EMPTY_ACCOUNTING
from scripts.m3_11_combined_inputs import allocate
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_owned_teardown import nodes
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.qualification_context import ARTIFACT_ENV, HOST_ENV, RUN_ENV
from scripts.qualification_group_runner import SCENARIO, Completion


@pytest.fixture
def inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Mock:
    tmp_path.chmod(0o700)
    environment = allocate(tmp_path, {"DOCKER_HOST": "unix:///var/run/docker.sock"})
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    artifact = Path(environment[ARTIFACT_ENV])
    artifact.write_bytes(b"original selected artifact")
    storage = Mock()
    storage.environment = dict(os.environ)
    storage.target.run_id = str(uuid.UUID(environment[RUN_ENV]))
    storage.binding = {
        **dict.fromkeys(evidence.BINDING_FIELDS, "a" * 64),
        "source_revision": "b" * 40,
        "storage_run_id": str(uuid.uuid7()),
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
    }
    nonce = str(uuid.uuid7())
    context = {
        "format": evidence.CONTEXT_FORMAT,
        "run_id": storage.target.run_id,
        "captured_at": (datetime.now(UTC) - timedelta(seconds=1))
        .isoformat()
        .replace("+00:00", "Z"),
        **storage.binding,
        **{key: hashlib.sha256(key.encode()).hexdigest() for key in evidence.IDENTITY_FIELDS},
        "subject_set_sha256": evidence.subject_digest(nonce),
    }
    write_private(tmp_path / "combined-context.json", context)
    write_private(
        tmp_path / "combined-names.json",
        {
            "format": evidence.NAMES_FORMAT,
            "run_id": storage.target.run_id,
            "nonce": nonce,
            "subjects": list(evidence.subjects(nonce)),
        },
    )
    write_private(
        tmp_path / "installed.json",
        {
            "artifact_sha256": storage.binding["artifact_sha256"],
            **EMPTY_ACCOUNTING,
        },
    )
    for phase in ("create", "prepare", "converge", "idempotence"):
        (tmp_path / f"{phase}.passed").write_bytes(b"passed\n")
    monkeypatch.setattr(LiveStorage, "load", Mock(return_value=storage))
    return storage


def assertions(attempt: live.Attempt) -> None:
    for phase in tuple(evidence.PHASE_CHECKS)[:-1]:
        with attempt.recorder.phase(phase) as details:
            details["actual_fixture_observations"] = "private component test data"
    witness = Mock(context_sha256=attempt.recorder.context_sha256)
    attempt.record(
        witness,
        {
            **dict.fromkeys(evidence.RECOVERY_FIELDS, "c" * 64),
            "protected_segments": 2,
            "retained_releases": 4,
            "tenant_states": dict.fromkeys(("active", "suspended", "archived", "undeployed"), 1),
        },
        {
            "issuer": evidence.ISSUER,
            "trust": "system-public-roots",
            "subject_count": 4,
            "zone_count": 2,
            "certificates_sha256": "d" * 64,
        },
        {
            **dict.fromkeys(evidence.ZERO_ACCOUNTING, 0),
            "source_state": "fenced",
            "source_fence_sha256": "e" * 64,
            "source_pending_inputs_sha256": "f" * 64,
            "destination_quarantine": False,
        },
    )


def execute(fault: str) -> object:
    def pytest_main(arguments: list[str], *, plugins: list[object]) -> int:
        completion, attempt = plugins
        assert isinstance(completion, Completion) and isinstance(attempt, live.Attempt)
        assert all(f"{SCENARIO}/{node}" in arguments for node in completion.expected)
        if fault != "no-assertions":
            assertions(attempt)
        completion.collected = list(completion.expected)
        completion.reports = {
            node: [(phase, "passed", False) for phase in ("setup", "call", "teardown")]
            for node in completion.expected
        }
        if fault in {"skipped", "xfail", "missing-teardown"}:
            reports = completion.reports[completion.expected[0]]
            if fault == "missing-teardown":
                reports.pop()
            else:
                reports[1] = (
                    "call",
                    "skipped" if fault == "skipped" else "passed",
                    fault == "xfail",
                )
        if fault == "legacy":
            (attempt.directory / "installed.json").write_bytes(b"{}\n")
        elif fault == "assertions":
            (attempt.directory / "combined-assertions.json").write_bytes(b"{}\n")
        elif fault == "context":
            (attempt.directory / "combined-context.json").write_bytes(b"{}\n")
        return 1 if fault == "failed" else 0

    return pytest_main


def retirement(monkeypatch: pytest.MonkeyPatch) -> Mock:
    result = Mock()
    result.run.return_value = {
        "intent_sha256": "e" * 64,
        "dns_sha256": "f" * 64,
        "teardown": dict.fromkeys(evidence.ZERO_TEARDOWN, 0),
    }
    monkeypatch.setattr(live, "Teardown", Mock(return_value=result))
    return result


def test_envelope_is_original_ordered_and_created_only_after_teardown(
    inputs: Mock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pytest, "main", execute("passed"))
    removal = retirement(monkeypatch)
    assert live.run() == 0
    removal.authorize.assert_called_once()
    removal.run.assert_called_once()
    original = (tmp_path / "combined.json").read_bytes()
    envelope = read_private(tmp_path / "combined.json")
    times = evidence.validate(envelope, binding=inputs.binding, maximum_age=timedelta(hours=24))
    assert (
        datetime.fromtimestamp((tmp_path / "combined.json").stat().st_mtime, tz=UTC)
        >= times.completed_at
    )
    assert set(envelope) == {
        "format",
        "environment",
        "context",
        "phases",
        "recovery",
        "public_ca",
        "accounting",
        "teardown",
    }
    with pytest.raises(FileExistsError):
        live.run()
    assert (tmp_path / "combined.json").read_bytes() == original
    removal.run.assert_called_once()


@pytest.mark.parametrize("fault", ["failed", "skipped", "xfail", "missing-teardown"])
def test_incomplete_pytest_result_retains_resources_and_cannot_restart(
    inputs: Mock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.setattr(pytest, "main", execute(fault))
    removal = retirement(monkeypatch)
    assert live.run() == (1 if fault == "failed" else 2)
    removal.authorize.assert_not_called()
    removal.run.assert_not_called()
    assert not (tmp_path / "combined.json").exists()
    with pytest.raises(FileExistsError):
        live.run()


@pytest.mark.parametrize(
    "fault", ["no-assertions", "legacy", "assertions", "context", "authorize", "cleanup", "nonzero"]
)
def test_changed_evidence_or_failed_teardown_never_emits_a_passing_envelope(
    inputs: Mock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.setattr(pytest, "main", execute(fault))
    removal = retirement(monkeypatch)
    if fault == "authorize":
        removal.authorize.side_effect = ValueError("not authorized")
    elif fault == "cleanup":
        removal.run.side_effect = ValueError("not removed")
    elif fault == "nonzero":
        removal.run.return_value["teardown"]["remaining_owned_resources"] = 1
    with pytest.raises(ValueError):
        live.run()
    assert not (tmp_path / "combined.json").exists()
    if fault not in {"authorize", "cleanup", "nonzero"}:
        removal.run.assert_not_called()


@pytest.mark.parametrize("filename", ["installed.json", "idempotence.passed"])
def test_live_assertions_cannot_precede_complete_legacy_evidence(
    inputs: Mock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    (tmp_path / filename).unlink()
    execute_tests = Mock()
    monkeypatch.setattr(pytest, "main", execute_tests)
    with pytest.raises(FileNotFoundError):
        live.run()
    execute_tests.assert_not_called()
    assert not (tmp_path / "combined-phases").exists()


def test_fixed_live_node_collects_without_contacting_a_host(inputs: Mock) -> None:
    environment = dict(os.environ)
    expected = nodes(environment)
    result = subprocess.run(  # noqa: S603 - collection only, fixed repository node
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            f"--hosts=docker://{environment[HOST_ENV]}",
            *(f"{SCENARIO}/{node}" for node in expected),
        ],
        cwd=SCENARIO.parents[3],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    collected = [
        Completion.relative(line) for line in result.stdout.splitlines() if "::test_" in line
    ]
    assert collected == list(expected)
