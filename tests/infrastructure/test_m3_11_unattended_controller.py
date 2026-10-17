"""Actual worker terminal/restart paths with synthetic lease and provider endpoints."""

from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import approval, evidence, production, worker
from scripts.m3_11_unattended.config import LeaseBootstrap, LeaseConfiguration
from scripts.m3_11_unattended.docker import OWNER, SOCKET, controller_name
from scripts.m3_11_unattended.inventory import ConnectInventory
from scripts.m3_11_unattended.lifecycle import LeaseLifecycle, Provider
from scripts.m3_11_unattended.model import ROLES, LifecycleError, ProviderKind, digest, stamp
from scripts.m3_11_unattended.state import RunState, cleanup_lock, replace_private

from .operator_process_support import Child
from .test_m3_11_lease_configuration import document
from .test_m3_11_lease_inventory import TARGETS, LeaseCase
from .test_m3_11_unattended_lifecycle import CANARY

DAEMON = dict.fromkeys(("ID", "Name", "DockerRootDir", "ServerVersion"), "approved-daemon")


def configuration() -> LeaseConfiguration:
    return LeaseConfiguration.parse(document())


def subject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[worker.Worker, LeaseCase]:
    root = tmp_path / "evidence"
    case = LeaseCase(tmp_path / "case")
    # The worker and lifecycle must observe the same synthetic lease timeline.
    monkeypatch.setattr(
        worker, "datetime", SimpleNamespace(now=lambda _zone: case.lifecycle.clock())
    )
    directory = root / "runs" / case.manifest.lease_id
    directory.mkdir(mode=0o700, parents=True)
    (root / "runs").chmod(0o700)
    root.chmod(0o700)
    write_private(
        directory / "request.json",
        {
            "format": "lowerduckpond-m3-11-unattended-request-v2",
            "binding": bound(case),
            "mode": "qualification",
            "approval_sha256": "c" * 64,
            "controller_image": "sha256:" + "d" * 64,
            "daemon": DAEMON,
            "lease_id": case.manifest.lease_id,
        },
    )
    config = configuration()
    roles = config.generations[config.active_generation]
    config = dataclasses.replace(
        config,
        policy=case.manifest.policy,
        approved_policy_sha256=case.manifest.policy.sha256,
        active_generation=case.manifest.creator.generation_id,
        generations={
            case.manifest.creator.generation_id: {
                "provision": dataclasses.replace(
                    roles["provision"], generation=case.manifest.creator
                ),
                "cleanup": dataclasses.replace(roles["cleanup"], generation=case.manifest.cleanup),
            }
        },
    )
    selected = worker.Worker(directory, config, tmp_path / "source")
    case.state = selected.lease_state
    case.lifecycle = LeaseLifecycle(
        case.manifest,
        case.inventory,
        case.state,
        providers=case.providers,
        clock=case.lifecycle.clock,
    )
    selected.lifecycle = case.lifecycle
    monkeypatch.setattr(selected, "_inventory", lambda: cast(ConnectInventory, case.inventory))
    monkeypatch.setattr(selected, "_verify_source", lambda: None)
    monkeypatch.setattr(
        worker,
        "Docker",
        lambda: SimpleNamespace(
            endpoint="unix://" + SOCKET,
            info=lambda: DAEMON,
            owned=lambda _name: {
                "Id": "a" * 64,
                "Name": "/" + controller_name(selected.run_id),
                "Image": selected.request["controller_image"],
                "Config": {"Labels": {OWNER + ".source": selected.helper}},
            },
        ),
    )
    monkeypatch.setattr(
        LeaseBootstrap,
        "providers",
        lambda self, **_kwargs: cast(
            dict[ProviderKind, Provider],
            case.providers if self.generation.role == "provision" else case.cleanup_providers,
        ),
    )
    return selected, case


def bound(case: LeaseCase) -> dict[str, object]:
    return {
        "managed_run_id": case.manifest.lease_id,
        "source_revision": "e" * 40,
        "helper_revision": "f" * 40,
        "artifact_sha256": "a" * 64,
        "qualification_inputs_sha256": "b" * 64,
        "storage_target_sha256": TARGETS.storage_digest,
    }


@pytest.mark.parametrize("field", ["ID", "Name", "DockerRootDir", "ServerVersion", "endpoint"])
def test_mounted_socket_must_reach_approved_daemon_before_provisioning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    selected, case = subject(tmp_path, monkeypatch)
    selected._verify_daemon()
    daemon = {**DAEMON, **({field: "unapproved-daemon"} if field != "endpoint" else {})}
    monkeypatch.setattr(
        worker,
        "Docker",
        lambda: SimpleNamespace(
            endpoint="unix:///other.sock" if field == "endpoint" else "unix://" + SOCKET,
            info=lambda: daemon,
        ),
    )
    monkeypatch.setattr(selected, "_provision", lambda: pytest.fail("must not provision"))
    assert selected.run() == 1
    assert selected.state.status()["qualification"] == "failed"
    assert all(provider.creates == 0 for provider in case.providers.values())


@pytest.mark.parametrize("field", ["status", "outcome", "observed_at", "format"])
def test_failure_export_rejects_canary_in_every_scalar(tmp_path: Path, field: str) -> None:
    tmp_path.chmod(0o700)
    state = RunState(tmp_path)
    state.begin({"managed_run_id": str(uuid.uuid7())})
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
        "policy_sha256": "d" * 64,
        "lease_id": None,
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


def test_status_exposes_real_supervisor_phase_but_never_raw_failure_payloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected, _ = subject(tmp_path, monkeypatch)
    selected.state.begin(selected.binding)
    supervisor = selected.directory / "supervisor"
    supervisor.mkdir(mode=0o700)
    fixture = selected.directory / "qualification/example"
    fixture.mkdir(mode=0o700, parents=True)
    write_private(
        supervisor / "context.json",
        {
            "directory": str(fixture),
            "phase": "verify",
            "docker_host": "unix:///var/run/docker.sock",
        },
    )
    write_private(
        fixture / "failure-controller.json",
        {"stage": CANARY, "category": CANARY, "return_code": CANARY, "provider_response": CANARY},
    )
    result = evidence.export(selected.directory, repository=selected.source, include_report=False)
    assert result["last_qualification_phase"] == "verify"
    assert CANARY not in json.dumps(result)


@pytest.mark.parametrize(
    "field", ["binding", "stage", "category", "path", "function", "line", "extra"]
)
def test_worker_diagnostic_canaries_and_transplants_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    selected, _case = subject(tmp_path, monkeypatch)
    selected.request["daemon"] = {**DAEMON, "ID": CANARY}
    assert selected.run() == 1
    path = selected.directory / "worker-failure.json"
    value = json.loads(path.read_text())
    if field in {"binding", "stage", "extra"}:
        value[field] = CANARY
    elif field == "category":
        value["failure"][field] = CANARY
    else:
        value["failure"]["origin"][field] = CANARY
    replace_private(path, value)
    with pytest.raises((LifecycleError, ValueError)):
        evidence.export(selected.directory, repository=selected.source, include_report=False)


@pytest.mark.parametrize("action", ["bootstrap", "validate"])
def test_short_production_process_retains_only_bound_static_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], action: str
) -> None:
    selected, _case = subject(tmp_path, monkeypatch)
    selected.state.begin(selected.binding)
    request = {
        "binding": selected.binding,
        "output": str(selected.directory / "production-check.json"),
    }
    monkeypatch.setattr(production, "_request", lambda: request)
    monkeypatch.setattr(sys, "argv", ["production", action])

    def rejected(*_args: object) -> None:
        raise LifecycleError(CANARY)

    monkeypatch.setattr(production, action, rejected)
    assert production.main() == 1
    exported = json.loads(
        json.dumps(
            evidence.export(selected.directory, repository=selected.source, include_report=False)
        )
    )
    assert exported["production_diagnostic"]["stage"] == action
    assert exported["production_diagnostic"]["failure"]["origin"]["function"] == "main"
    captured = capsys.readouterr()
    assert CANARY not in json.dumps(exported) + captured.out + captured.err


@pytest.mark.parametrize("fault", ["delivery", "cancel", "revocation"])
def test_worker_terminal_failure_keeps_outcome_and_revokes_all_owned_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    selected, case = subject(tmp_path, monkeypatch)

    def provision() -> tuple[dict[str, object], dict[str, object]]:
        case.confirm()
        return cast(dict[str, object], case.issue()), {}

    def deliver(*_args: object) -> dict[str, str]:
        write_private(selected.directory / "runtime-inputs.json", {"private": CANARY})
        if fault == "cancel":
            selected.state.cancel()
        if fault == "revocation":
            for provider in case.cleanup_providers.values():
                provider.fail_delete = True
        raise LifecycleError(CANARY)

    monkeypatch.setattr(selected, "_provision", provision)
    monkeypatch.setattr(selected, "_production", lambda _credentials, _fixture: {})
    monkeypatch.setattr(selected, "_deliver", deliver)
    assert selected.run() == 1
    status = selected.state.status()
    assert status["qualification"] == ("interrupted" if fault == "cancel" else "failed")
    assert status["credential_cleanup"] == ("unresolved" if fault == "revocation" else "verified")
    original = read_private(selected.directory / "journey-result.json")
    for provider in case.cleanup_providers.values():
        provider.fail_delete = False
    assert selected.revoke()
    assert read_private(selected.directory / "journey-result.json") == original
    assert all(not provider.items for provider in case.providers.values())
    assert CANARY not in json.dumps(
        evidence.export(selected.directory, repository=selected.source, include_report=False)
    )


def test_restart_reconciles_without_replaying_creation_or_rewriting_failed_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected, case = subject(tmp_path, monkeypatch)
    selected.state.begin(selected.binding)
    case.confirm()
    case.issue()
    (selected.directory / "private.log").write_text(CANARY)
    assert selected.run() == 1
    assert sum(provider.creates for provider in case.providers.values()) == len(ROLES)
    assert all(not provider.items for provider in case.providers.values())
    assert selected.state.status()["qualification"] == "interrupted"
    assert selected.state.status()["credential_cleanup"] == "verified"
    original = read_private(selected.directory / "journey-result.json")
    assert selected.run() == 1
    assert read_private(selected.directory / "journey-result.json") == original
    assert (selected.directory / "private.log").read_text() == CANARY


@pytest.mark.parametrize("restore", [False, True])
def test_restarted_attempt_with_lost_or_old_lease_volume_cannot_issue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore: bool
) -> None:
    selected, case = subject(tmp_path, monkeypatch)
    selected.state.begin(selected.binding)
    selected.state.finish_journey("failed", 1)
    original = (selected.directory / "journey-result.json").read_bytes()
    snapshot = tmp_path / "synthetic-pre-issuance-snapshot"
    shutil.copytree(case.state.directory, snapshot)
    case.confirm()
    case.issue()
    shutil.rmtree(case.state.directory)
    if restore:
        shutil.copytree(snapshot, case.state.directory)
    restarted = worker.Worker(selected.directory, selected.config, selected.source)
    monkeypatch.setattr(restarted, "_inventory", lambda: cast(ConnectInventory, case.inventory))
    monkeypatch.setattr(restarted, "_verify_source", lambda: None)
    monkeypatch.setattr(restarted, "_provision", lambda: pytest.fail("restored attempt issued"))
    assert restarted.run() == 1
    assert sum(provider.creates for provider in case.providers.values()) == len(ROLES)
    assert (selected.directory / "journey-result.json").read_bytes() == original


def test_close_publication_precedes_busy_cleanup_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:

    selected, case = subject(tmp_path, monkeypatch)
    selected.state.begin(selected.binding)
    selected.state.finish_journey("failed", 1)
    case.confirm()
    case.issue()
    with cleanup_lock(selected.directory.parent):
        assert not selected.revoke()
    assert "close-finish" in case.lifecycle.records()
    assert sum(len(provider.items) for provider in case.providers.values()) == len(ROLES)
    assert selected.revoke()


@pytest.mark.parametrize("restarted", [False, True])
@pytest.mark.parametrize("cleanup_reason", ["cancel", "expiry-boundary", "expiry"])
def test_released_creator_cannot_revoke_successor_but_global_cleanup_still_applies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    restarted: bool,
    cleanup_reason: str,
) -> None:
    selected, case = subject(tmp_path, monkeypatch)
    selected.state.begin(selected.binding)
    selected.state.finish_journey("failed", 1)
    original = (selected.directory / "journey-result.json").read_bytes()
    case.confirm()
    case.issue()
    successor = str(uuid.uuid7())
    with case.state.use_lock():
        case.state.acquire_use(
            attempt_id=selected.run_id, binding_sha256=digest(selected.binding), kind="attempt"
        )
        assert bool(selected.owns_lease)
        case.state.release_use(
            attempt_id=selected.run_id,
            quiescence={
                "host_commands_drained": True,
                "complete": True,
                "containers": [
                    {
                        "id": "a" * 64,
                        "name": "synthetic-stopped-consumer",
                        "image": "sha256:" + "b" * 64,
                        "owner": selected.run_id,
                        "running": False,
                        "restart_policy": "no",
                    }
                ],
            },
        )
        assert not bool(selected.owns_lease)
        case.state.acquire_use(attempt_id=successor, binding_sha256="c" * 64, kind="attempt")
    successor_path = case.state.directory / ("use-" + successor + ".json")
    successor_use = successor_path.read_bytes()
    if restarted:
        selected = worker.Worker(selected.directory, selected.config, selected.source)
        monkeypatch.setattr(selected, "_inventory", lambda: cast(ConnectInventory, case.inventory))
        monkeypatch.setattr(selected, "_verify_source", lambda: None)
        assert selected.run() == 1
    else:
        assert not selected.revoke()
    assert not selected.owns_lease
    assert not any(str(row["slot"]).startswith("close-") for row in case.inventory.records())
    assert all(not provider.deletes for provider in case.cleanup_providers.values())
    assert sum(len(provider.items) for provider in case.providers.values()) == len(ROLES)
    assert (selected.directory / "journey-result.json").read_bytes() == original
    assert successor_path.read_bytes() == successor_use

    if cleanup_reason == "cancel":
        selected.state.cancel()
    else:
        expired = case.manifest.policy.deadline(
            datetime.fromisoformat(case.manifest.created_at)
        ) + timedelta(seconds=0 if cleanup_reason == "expiry-boundary" else 1)
        monkeypatch.setattr(worker, "datetime", SimpleNamespace(now=lambda _zone: expired))
    assert selected.revoke()
    assert all(not provider.items for provider in case.providers.values())
    assert (selected.directory / "journey-result.json").read_bytes() == original


def test_failed_close_publication_does_not_suppress_immediate_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected, case = subject(tmp_path, monkeypatch)
    selected.state.begin(selected.binding)
    selected.state.finish_journey("passed", 0)
    case.confirm()
    case.issue()
    publish = case.inventory.publish

    def unavailable(record: dict[str, object]) -> None:
        if str(record["slot"]).startswith("close-"):
            raise LifecycleError("synthetic persistence failure")
        publish(record)

    monkeypatch.setattr(case.inventory, "publish", unavailable)
    assert not selected.revoke()
    assert all(not provider.items for provider in case.providers.values())
    assert selected.state.status()["credential_cleanup"] == "unresolved"
    monkeypatch.setattr(case.inventory, "publish", publish)
    assert selected.revoke()
    assert selected.state.status()["closure"] == "complete"


def test_only_started_failed_attempt_may_retain_and_explicit_cancel_revokes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected, case = subject(tmp_path, monkeypatch)
    selected.state.begin(selected.binding)
    selected.state.finish_journey("failed", 1)
    case.confirm()
    case.issue()
    write_private(selected.directory / "runtime-inputs.json", {"private": CANARY})
    write_private(
        selected.directory / "attempt-started.json",
        {
            "binding_sha256": digest(selected.binding),
            "manifest_sha256": case.manifest.sha256,
        },
    )
    selected.attempt_started = True
    selected._terminal()
    assert sum(len(provider.items) for provider in case.providers.values()) == len(ROLES)
    assert selected.state.status()["credential_cleanup"] == "pending"
    selected.state.cancel()
    selected._terminal()
    assert all(not provider.items for provider in case.providers.values())
    assert selected.state.status()["qualification"] == "failed"


@pytest.mark.parametrize(
    "fault", ["missing-command", "log-open", "spawn", "bookkeeping", "monitor"]
)
def test_actual_journey_spawn_boundary_controls_retention_and_drains_before_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:

    selected, case = subject(tmp_path, monkeypatch)
    selected.state.begin(selected.binding)
    case.confirm()
    case.issue()
    write_private(selected.directory / "runtime-inputs.json", {"private": CANARY})
    selected.source.mkdir()
    spawned: list[Child] = []
    waited: list[int] = []

    def spawn(*_args: object, **_kwargs: object) -> Child:
        if fault == "spawn":
            raise OSError("synthetic spawn failure")
        child = Child(lambda _value: 1, status=1)
        spawned.append(child)
        return child

    original_wait = Child.wait

    def wait(child: Child, timeout: float | None = None) -> int:
        waited.append(child.pid)
        return original_wait(child, timeout)

    original_write = write_private

    def store(path: Path, value: dict[str, object]) -> None:
        if path.name == "attempt-started.json" and fault == "bookkeeping":
            raise OSError("synthetic post-spawn bookkeeping failure")
        original_write(path, value)

    def persist(path: Path, value: dict[str, object]) -> None:
        if path.name == "status.json" and value.get("phase") == "running" and fault == "monitor":
            raise OSError("synthetic progress storage failure")
        replace_private(path, value)

    monkeypatch.setattr(subprocess, "Popen", spawn)
    monkeypatch.setattr(Child, "wait", wait)
    monkeypatch.setattr(worker, "write_private", store)
    monkeypatch.setattr("scripts.m3_11_unattended.state.replace_private", persist)
    monkeypatch.setattr(
        shutil, "which", lambda _name: None if fault == "missing-command" else "/synthetic/just"
    )
    if fault == "log-open":
        (selected.directory / "controller.log").mkdir()
    if fault == "monitor":
        monkeypatch.setattr(Child, "poll", lambda _self: None)
    with pytest.raises((OSError, LifecycleError)):
        selected._journey({"DOCKER_HOST": "unix://" + SOCKET})
    assert selected.attempt_started is bool(spawned)
    assert bool(waited) is bool(spawned)
    assert (selected.directory / "host-drained.json").exists() is bool(spawned)
    selected.state.finish_journey("failed", 1)
    # A successful spawn without its durable receipt still cannot retain.
    selected._terminal()
    if fault == "monitor":
        assert selected.state.status()["credential_cleanup"] == "pending"
        selected.state.cancel()
        selected._terminal()
    assert all(not provider.items for provider in case.providers.values())
    assert selected.state.status()["credential_cleanup"] == "verified"


def test_worker_cleanup_shares_visibility_allowance_and_deletes_before_it_can_renew(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.m3_11_unattended import connect_api  # noqa: PLC0415
    from scripts.m3_11_unattended.connect_api import Response  # noqa: PLC0415

    from .test_m3_11_lease_inventory import (  # noqa: PLC0415
        PublicationConnect,
        VisibilityClock,
    )

    selected, case = subject(tmp_path, monkeypatch)
    selected.state.begin(selected.binding)
    selected.state.finish_journey("failed", 1)
    case.confirm()
    case.issue()
    client = PublicationConnect()
    inventory = ConnectInventory(client, client.vault, spool=tmp_path / "pending")
    for record in sorted(case.inventory.records(), key=lambda row: row["slot"] != "manifest"):
        inventory.publish(record)
    monkeypatch.setattr(case, "inventory", inventory)
    case.lifecycle.inventory = inventory
    clock = VisibilityClock()
    monkeypatch.setattr(connect_api, "time", clock)
    client.hidden, client.repeated_response = True, Response(404, None)
    assert not selected.revoke()
    assert 0 < clock.seconds <= connect_api.VISIBILITY_SECONDS
    assert all(not provider.items for provider in case.providers.values())
    assert sum(len(provider.deletes) for provider in case.cleanup_providers.values()) == len(ROLES)
    assert selected.state.status()["credential_cleanup"] == "unresolved"
    assert len(list(case.state.directory.glob("credential-*.json"))) == len(ROLES)
    pending = {path: path.read_bytes() for path in inventory.spool.iterdir()}
    client.hidden, client.repeated_response = False, None
    assert selected.revoke()
    # Denial and closure facts may now be posted. Every earlier uncertain fact
    # reconciles without another POST for its original title.
    assert len({item["title"] for item in client.items.values()}) == client.posts
    assert all(path.read_bytes() == data for path, data in pending.items())
