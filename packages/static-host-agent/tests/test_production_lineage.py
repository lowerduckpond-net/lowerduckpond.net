"""Actual local identity transitions with a separately observed repository model."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import (
    audit_archive_local,
    backup_restic,
    production_lineage,
    production_namespace,
)
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.durable import StatePathError
from test_audit_archive_admission import available_capacity
from test_backup_genesis import ENVIRONMENT, Repository
from test_backup_identity import IDENTITY
from test_production_namespace import NAMESPACE, snapshot
from test_production_namespace import state as state  # noqa: PLC0414 - complete empty static tree

OWNER = os.geteuid()


@pytest.fixture
def repository(state: Path, monkeypatch: pytest.MonkeyPatch) -> Repository:
    production_namespace.initialize_namespace(state, NAMESPACE, expected_owner=OWNER)
    result = Repository(state)
    monkeypatch.setattr(backup_restic, "_restic", result.run)
    monkeypatch.setattr(
        audit_archive_local, "measure_filesystem_capacity_descriptor", available_capacity
    )
    return result


def initialize(root: Path) -> dict[str, str]:
    return production_lineage.initialize(
        root, NAMESPACE, IDENTITY.binding()["value"], ENVIRONMENT, owner=OWNER
    )


def test_initialization_and_lost_acknowledgement_preserve_exact_local_and_remote_identity(
    state: Path, repository: Repository
) -> None:
    result = initialize(state)
    assert result == {
        "repository_binding": IDENTITY.binding()["value"],
        "lineage_sha256": hashlib.sha256(repository.raw).hexdigest(),
        "genesis_snapshot_id": "c" * 64,
        "audit_head_sha256": hashlib.sha256(
            (state / "audit/archive/head.json").read_bytes()
        ).hexdigest(),
    }
    previous = snapshot(state)
    assert initialize(state) == result
    assert snapshot(state) == previous
    assert repository.writes == 1


@pytest.mark.parametrize("fault", ["before-snapshot", "lost-response"])
def test_retry_uses_original_genesis_proposal_after_repository_interruption(
    state: Path, repository: Repository, fault: str
) -> None:
    repository.fault = fault
    with pytest.raises(BackupIdentityError):
        initialize(state)
    genesis = (state / "locks/audit-lineage-genesis.json").read_bytes()
    assert not (state / "audit/archive/head.json").exists()
    repository.fault = ""
    initialize(state)
    assert (state / "platform/audit-lineage.json").read_bytes() == genesis == repository.raw
    assert repository.writes == 1


@pytest.mark.parametrize(
    "name",
    [
        "tenants/existing",
        "authorization/jobs/existing",
        "intents/existing",
        "intake/existing",
        "exports/existing",
        "platform/launch.json",
        "locks/authorization-recovery.cursor",
        "audit/segment-00000000000000000000.jsonl",
    ],
)
def test_unexpected_history_prevents_any_new_repository_or_local_authority(
    state: Path, repository: Repository, name: str
) -> None:
    (state / name).write_bytes(b"original retained history")
    before = snapshot(state)
    with pytest.raises(StatePathError):
        initialize(state)
    assert snapshot(state) == before and repository.writes == 0


@pytest.mark.parametrize("fault", ["binding", "namespace", "genesis", "index", "remote-rotation"])
def test_resumption_refuses_changed_authority_without_replacing_any_evidence(
    state: Path, repository: Repository, fault: str
) -> None:
    initialize(state)
    binding, namespace = IDENTITY.binding()["value"], NAMESPACE
    if fault == "binding":
        binding = "0" * 64
    elif fault == "namespace":
        namespace = NAMESPACE.replace(b"T00:00:00Z", b"T00:01:00Z")
    elif fault == "genesis":
        (state / "locks/audit-lineage-genesis.json").unlink()
    elif fault == "index":
        path = state / "audit/archive/head.json"
        path.write_bytes(path.read_bytes().replace(b'"entryCount":0', b'"entryCount":1'))
    else:
        repository.snapshots.append(
            {"id": "d" * 64, "hostname": IDENTITY.node_name, "tags": ["rotation-original"]}
        )
    before = snapshot(state)
    with pytest.raises(BackupIdentityError):
        production_lineage.initialize(state, namespace, binding, ENVIRONMENT, owner=OWNER)
    assert snapshot(state) == before and repository.writes == 1


def test_changed_repository_before_first_initialization_never_creates_local_genesis(
    state: Path, repository: Repository
) -> None:
    before = snapshot(state)
    with pytest.raises(BackupIdentityError, match="original migration binding"):
        production_lineage.initialize(state, NAMESPACE, "0" * 64, ENVIRONMENT, owner=OWNER)
    assert snapshot(state) == before and repository.writes == 0
