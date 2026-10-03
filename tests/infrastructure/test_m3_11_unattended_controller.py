"""Exercise actual persistent state, worker terminal paths and private delivery."""

from __future__ import annotations

import dataclasses
import json
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import approval, cleanup, evidence, setup, worker
from scripts.m3_11_unattended.config import Bootstrap, Configuration
from scripts.m3_11_unattended.journal import OpJournal, event
from scripts.m3_11_unattended.model import Credential, LifecycleError, stamp
from scripts.m3_11_unattended.state import RunState, replace_private

from .test_m3_11_unattended_lifecycle import CANARY, TARGETS, Case


def configuration() -> Configuration:
    return Configuration(TARGETS, "a" * 26, Bootstrap({}), Bootstrap({}), {})


def bound(case: Case) -> dict[str, object]:
    return {
        "managed_run_id": case.run_id,
        "source_revision": "e" * 40,
        "helper_revision": "f" * 40,
        "artifact_sha256": "a" * 64,
        "qualification_inputs_sha256": "b" * 64,
        "storage_target_sha256": TARGETS.storage_digest,
    }


def subject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[worker.Worker, Case]:
    directory = tmp_path / "run"
    directory.mkdir(mode=0o700)
    case = Case(tmp_path / "journal")
    write_private(
        directory / "request.json",
        {
            "format": "lowerduckpond-m3-11-unattended-request-v1",
            "binding": bound(case),
            "mode": "qualification",
            "approval_sha256": "c" * 64,
            "controller_image": "sha256:" + "d" * 64,
        },
    )
    selected = worker.Worker(directory, configuration(), tmp_path / "source")
    monkeypatch.setattr(selected, "_verify_source", lambda: None)
    monkeypatch.setattr(cleanup, "connect_cleanup", lambda *_args: case.lifecycle)
    return selected, case


def test_restart_revokes_original_attempt_without_replaying_and_preserves_failed_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected, case = subject(tmp_path, monkeypatch)
    selected.state.begin(selected.binding)
    for name in ("credential-intents", "credential-cleanup"):
        (selected.directory / name).mkdir(mode=0o700)
    case.lifecycle.remember = selected.remember
    case.lifecycle.remember_intent = selected.remember_intent
    _, _credential = case.create()
    retained = selected.directory / "private.log"
    retained.write_text(CANARY)
    # Model SIGKILL after provider creation: no terminal callback ran. A fresh
    # worker uses the immutable attempt and independent provider inventory.
    assert selected.run() == 1
    assert case.provider.creates == 1
    assert case.provider.deletes == ["credential00000001"]
    assert selected.state.status()["qualification"] == "interrupted"
    assert selected.state.status()["credential_cleanup"] == "verified"
    assert selected.state.status()["closure"] == "unresolved"
    assert retained.read_text() == CANARY
    result = (selected.directory / "journey-result.json").read_bytes()
    assert selected.run() == 1
    assert (selected.directory / "journey-result.json").read_bytes() == result
    assert case.provider.creates == 1
    exported = evidence.export(selected.directory, repository=selected.source, include_report=True)
    assert CANARY not in json.dumps(exported)
    assert exported["revocation"]


@pytest.mark.parametrize("fault", ["delivery", "cancel", "revocation"])
def test_real_worker_terminal_paths_separate_test_outcome_from_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    selected, case = subject(tmp_path, monkeypatch)

    def provision() -> tuple[dict[str, Credential], dict[str, object]]:
        case.lifecycle.remember = selected.remember
        case.lifecycle.remember_intent = selected.remember_intent
        _, credential = case.create()
        return {"archive": credential}, {}

    def deliver(*_args: object) -> dict[str, str]:
        (selected.directory / "runtime-inputs.json").write_text(CANARY)
        if fault == "cancel":
            selected.state.cancel()
        if fault == "revocation":
            case.provider.fail_delete = True
        raise LifecycleError(CANARY)

    monkeypatch.setattr(selected, "_provision", provision)
    monkeypatch.setattr(selected, "_production", lambda _credentials: {})
    monkeypatch.setattr(selected, "_deliver", deliver)
    assert selected.run() == 1
    status = selected.state.status()
    assert status["qualification"] == ("interrupted" if fault == "cancel" else "failed")
    assert status["credential_cleanup"] == ("unresolved" if fault == "revocation" else "verified")
    assert status["closure"] == "unresolved"
    assert not (selected.directory / "runtime-inputs.json").exists()
    original = read_private(selected.directory / "journey-result.json")
    case.provider.fail_delete = False
    assert selected.revoke()
    assert read_private(selected.directory / "journey-result.json") == original


def test_private_spool_is_durable_before_remote_creation_acknowledgement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected, case = subject(tmp_path, monkeypatch)
    for name in ("credential-intents", "credential-cleanup"):
        (selected.directory / name).mkdir(mode=0o700)
    case.lifecycle.remember, case.lifecycle.remember_intent = (
        selected.remember,
        selected.remember_intent,
    )
    append = case.journal.append

    def lose_ack(record: dict[str, object]) -> None:
        if record["kind"] == "created":
            raise LifecycleError("journal unavailable")
        append(record)

    monkeypatch.setattr(case.journal, "append", lose_ack)
    with pytest.raises(LifecycleError):
        case.create()
    available = worker.retained_credentials(selected.directory)
    assert len(available) == 1
    assert next(iter(available.values())).secret == CANARY
    monkeypatch.setattr(case.journal, "append", append)
    assert selected.revoke()
    assert not worker.retained_credentials(selected.directory)


@pytest.mark.parametrize("age", [timedelta(minutes=46), timedelta(days=1)])
def test_stale_independent_cleanup_blocks_admission(tmp_path: Path, age: timedelta) -> None:
    case = Case(tmp_path)
    case.journal.append(
        event(
            "heartbeat",
            case.run_id,
            {
                "actor": "github",
                "helper_revision": "f" * 40,
                "observed_at": stamp(datetime.now(UTC) - age),
                "status": "ready",
                "overdue": 0,
                "results": [],
            },
        )
    )
    with pytest.raises(LifecycleError, match="stale"):
        cleanup.require_independent_ready(
            cast(OpJournal, case.journal), helper="f" * 40, now=datetime.now(UTC)
        )
    status = cleanup.status_document(case.journal, helper="f" * 40, now=datetime.now(UTC))
    assert status["new_start"] == "blocked"
    github = status["github"]
    assert isinstance(github, dict) and github["status"] == "stale-or-unresolved"


@pytest.mark.parametrize("field", ["status", "outcome", "observed_at", "format"])
def test_failure_export_rejects_canary_in_every_scalar(tmp_path: Path, field: str) -> None:
    tmp_path.chmod(0o700)
    state = RunState(tmp_path)
    state.begin({"managed_run_id": Case(tmp_path / "journal").run_id})
    state.finish_journey("failed", 1)
    value = read_private(tmp_path / "journey-result.json")
    value[field] = CANARY
    replace_private(tmp_path / "journey-result.json", value)
    with pytest.raises((ValueError, RuntimeError)):
        state.status()


def test_untrusted_ambient_bootstrap_is_excluded_from_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "OP_SERVICE_ACCOUNT_TOKEN",
        "GITHUB_TOKEN",
        "OPENTOFU_ENCRYPTION_PASSPHRASE",
        "AWS_SECRET_ACCESS_KEY",
    ):
        monkeypatch.setenv(name, CANARY)
    assert CANARY not in worker.safe_environment().values()


def test_setup_creates_private_configuration_and_cleanup_excludes_production(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = setup.template()
    manifest["targets"], manifest["journal_vault"] = dataclasses.asdict(TARGETS), "a" * 26
    for role in ("provision", "cleanup", "production"):
        section = manifest[role]
        assert isinstance(section, dict)
        section["service_account_expires_at"] = stamp(datetime.now(UTC) + timedelta(days=7))
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    token_file = tmp_path / "tokens.json"
    write_private(
        token_file, {role: CANARY + role for role in ("provision", "cleanup", "production")}
    )
    monkeypatch.setattr(setup, "validate", lambda _config: None)
    output = tmp_path / "controller.json"
    setup.configure(path, output, token_file=token_file)
    assert output.stat().st_mode & 0o777 == 0o600  # noqa: PLR2004 - private mode
    config = Configuration.load(output)
    independent = json.dumps(config.cleanup_document())
    assert CANARY + "cleanup" in independent
    assert CANARY + "production" not in independent
    assert CANARY + "provision" not in independent
    assert "OPENTOFU_ENCRYPTION_PASSPHRASE" not in independent
    assert CANARY not in repr(config)
    with pytest.raises(LifecycleError, match="overwrite"):
        setup.configure(path, output, token_file=token_file)


def test_failed_setup_removes_incomplete_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = setup.template()
    manifest["targets"], manifest["journal_vault"] = dataclasses.asdict(TARGETS), "a" * 26
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    tokens = tmp_path / "tokens.json"
    write_private(tokens, dict.fromkeys(("provision", "cleanup", "production"), CANARY))
    output = tmp_path / "controller.json"
    with pytest.raises(LifecycleError):
        setup.configure(path, output, token_file=tokens)
    assert not output.exists()


def test_live_approval_is_exact_and_short_lived(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    value = {
        "format": approval.FORMAT,
        "prepared": {
            "source_revision": "e" * 40,
            "helper_revision": "e" * 40,
            "controller_image": "sha256:" + "a" * 64,
            "artifact_sha256": "b" * 64,
            "daemon": dict.fromkeys(("ID", "Name", "DockerRootDir", "ServerVersion"), "test"),
        },
        "targets": dataclasses.asdict(TARGETS),
        "qualification_inputs_sha256": "c" * 64,
        "modes": ["rehearsal"],
        "approved_at": stamp(now),
        "expires_at": stamp(now + timedelta(hours=4)),
        "credential_lifetime_hours": 14,
        "approval_reference": "test operator approval",
    }
    assert approval.validate(value, mode="rehearsal", now=now) == value
    with pytest.raises(LifecycleError):
        approval.validate(value, mode="qualification", now=now)
    with pytest.raises(LifecycleError):
        approval.validate(value, mode="rehearsal", now=now + timedelta(hours=5))


def test_preparation_process_is_cancelled_without_leaking_pipe_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected, _ = subject(tmp_path, monkeypatch)
    selected.source.mkdir()
    timer = threading.Timer(0.2, selected.state.cancel)
    timer.start()
    try:
        with pytest.raises(LifecycleError, match="cancelled"):
            selected._command(
                [sys.executable, "-c", "import sys,time; sys.stdin.buffer.read(); time.sleep(60)"],
                stdin=CANARY.encode(),
                log="preparation.log",
                seconds=5,
            )
    finally:
        timer.join()
    assert CANARY not in (selected.directory / "preparation.log").read_text()


def test_bootstrap_time_consumes_the_original_run_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected, _case = subject(tmp_path, monkeypatch)
    selected.ends_at = time.monotonic() - 1

    def provision() -> None:
        selected.check_cancelled()

    monkeypatch.setattr(selected, "_provision", provision)
    assert selected.run() == 1
    status = selected.state.status()
    assert status["qualification"] == "failed"
    assert status["exit_status"] == 124  # noqa: PLR2004 - deadline status
