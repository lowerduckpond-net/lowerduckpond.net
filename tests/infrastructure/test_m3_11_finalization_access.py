"""Finalization holds the failed attempt's owner and original issued identities."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import m3_11_finalization_access as recovery
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.model import digest
from scripts.m3_11_unattended.state import RunState, replace_private

from . import test_m3_11_connect_action as managed
from .test_m3_11_connect_action import Case, attempt
from .test_m3_11_lease_configuration import document
from .test_m3_11_unattended_inputs import pair


def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Case]:
    case = Case(tmp_path, monkeypatch)
    case.execute()
    case.issue()
    directory, binding = attempt(case)
    state = RunState(directory)
    state.begin(binding)
    state.finish_journey("failed", 1)
    with case.state.use_lock():
        case.state.acquire_use(
            attempt_id=directory.name, binding_sha256=digest(binding), kind="attempt"
        )
    write_private(
        directory / "attempt-started.json",
        {"binding_sha256": digest(binding), "manifest_sha256": case.manifest.sha256},
    )
    write_private(
        directory / "host-drained.json", {"binding_sha256": digest(binding), "drained": True}
    )
    fixture = directory / "qualification/synthetic"
    fixture.mkdir(mode=0o700, parents=True)
    _, checked = case.lifecycle.credentials(binding=binding)
    receipts = {**pair(binding), "fixture": checked}
    write_private(
        fixture / "managed-credentials.json",
        {
            "format": "lowerduckpond-m3-11-managed-credentials-v1",
            **binding,
            "receipts": receipts,
            "receipts_sha256": digest(receipts),
        },
    )
    write_private(
        fixture / "combined-context.json",
        {
            key: binding[key]
            for key in (
                "source_revision",
                "artifact_sha256",
                "qualification_inputs_sha256",
                "storage_target_sha256",
            )
        },
    )
    monkeypatch.setattr(recovery, "Docker", lambda: SimpleNamespace(info=dict))
    return fixture, case


def test_reacquisition_holds_locks_without_reissuing_or_replacing_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory, case = prepared(tmp_path, monkeypatch)
    attempt = directory.parent.parent
    failure = (attempt / "journey-result.json").read_bytes()
    creates = sum(p.creates for p in case.providers["provision"].values())
    with recovery.access(directory) as environment:
        assert environment["SPACES_REGION"] == case.config.targets.region
        assert "OP_SERVICE_ACCOUNT_TOKEN" not in environment
        with pytest.raises(BlockingIOError), RunState(attempt).lock():
            pytest.fail("another controller acquired the owner")
        with pytest.raises(RuntimeError, match="already owned"), case.state.use_lock():
            pytest.fail("another consumer acquired the lease")
    assert sum(p.creates for p in case.providers["provision"].values()) == creates
    assert (attempt / "journey-result.json").read_bytes() == failure
    assert not (attempt / "runtime-inputs.json").exists()


@pytest.mark.parametrize(
    "fault", ["cancel", "close", "released", "drain", "binding", "identity", "expired"]
)
def test_recovery_refuses_lost_ownership_or_changed_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    directory, case = prepared(tmp_path, monkeypatch)
    attempt = directory.parent.parent
    if fault == "cancel":
        RunState(attempt).cancel()
    elif fault == "close":
        write_private(case.state.directory / "close-cancel.json", {"requested": True})
    elif fault == "released":
        write_private(case.state.directory / f"released-{attempt.name}.json", {"released": True})
    elif fault == "drain":
        replace_private(
            attempt / "host-drained.json", {"binding_sha256": "0" * 64, "drained": True}
        )
    elif fault == "binding":
        value = read_private(directory / "combined-context.json")
        value["artifact_sha256"] = "0" * 64
        replace_private(directory / "combined-context.json", value)
    elif fault == "identity":
        path = case.state.directory / "credential-backup.json"
        value = read_private(path)
        value["identifier"] = "substituted"
        replace_private(path, value)
    else:
        future = datetime.now(UTC) + timedelta(days=8)
        monkeypatch.setattr(recovery, "datetime", SimpleNamespace(now=lambda _zone: future))
    with pytest.raises((ValueError, RuntimeError)), recovery.access(directory):
        pytest.fail("invalid recovery acquired credentials")


def test_cancellation_during_recovery_is_seen_by_next_mutation_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory, _ = prepared(tmp_path, monkeypatch)
    with recovery.access(directory):
        RunState(directory.parent.parent).cancel()
        with pytest.raises(ValueError, match="cancelled"):
            recovery.require_live(directory)


def test_failed_attempt_cannot_recover_without_approved_retention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def configuration() -> dict[str, object]:
        value = document()
        policy = cast(dict[str, object], value["policy"])
        policy["retain_after_failure"] = False
        value["approved_policy_sha256"] = digest(policy)
        return value

    monkeypatch.setattr(managed, "document", configuration)
    directory, case = prepared(tmp_path, monkeypatch)
    assert not list(case.state.directory.glob("close-*.json"))
    with (
        pytest.raises(ValueError, match="ownership or valid credentials"),
        recovery.access(directory),
    ):
        pytest.fail("unretained failed attempt reacquired runtime credentials")
