"""The rollout protection gate checks real local history without rewriting it."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import production_rollout_backup as rollout
from lowerduckpond_static_host_agent.backup_coordinator import CapturePaths
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.durable import StatePathError
from lowerduckpond_static_host_agent.production_backup import BackupAuthority
from test_audit_archive_admission import available_capacity
from test_backup_genesis import ENVIRONMENT, Repository
from test_production_lineage import OWNER, initialize
from test_production_lineage import repository as repository  # noqa: PLC0414
from test_production_namespace import NAMESPACE, snapshot
from test_production_namespace import state as state  # noqa: PLC0414


@pytest.fixture
def authority(state: Path, repository: Repository) -> BackupAuthority:
    observed = initialize(state)
    return BackupAuthority(
        "1" * 64,
        "2" * 64,
        "3" * 64,
        "4" * 64,
        observed["repository_binding"],
        observed["lineage_sha256"],
        json.loads(NAMESPACE),
        None,
    )


def protect(
    state: Path, authority: BackupAuthority, *, genesis: str = "c" * 64, head: str | None = None
) -> None:
    rollout._protect(
        CapturePaths(state=state),
        state.parent,
        ENVIRONMENT,
        authority,
        genesis_snapshot_id=genesis,
        audit_head_sha256=head
        or hashlib.sha256((state / "audit/archive/head.json").read_bytes()).hexdigest(),
        owner=OWNER,
    )


def test_fresh_protection_is_readonly_and_preserves_original_capture_source(
    state: Path, repository: Repository, authority: BackupAuthority
) -> None:
    original = snapshot(state)
    protect(state, authority)
    protect(state, authority)
    assert snapshot(state) == original
    assert repository.writes == 1


@pytest.mark.parametrize(
    "fault", ["binding", "lineage", "namespace", "genesis", "head", "missing", "duplicate"]
)
def test_protection_refuses_changed_original_authority(
    state: Path, repository: Repository, authority: BackupAuthority, fault: str
) -> None:
    genesis, head = "c" * 64, None
    if fault == "binding":
        authority = replace(authority, repository_binding="0" * 64)
    elif fault == "lineage":
        authority = replace(authority, lineage_sha256="0" * 64)
    elif fault == "namespace":
        authority = replace(
            authority, namespace={**authority.namespace, "initializedAt": "2026-09-24T00:00:00Z"}
        )
    elif fault == "genesis":
        genesis = "d" * 64
    elif fault == "head":
        head = "0" * 64
    elif fault == "missing":
        repository.snapshots.pop()
    else:
        repository.snapshots.append({**repository.snapshots[-1], "id": "d" * 64})
    original = snapshot(state)
    with pytest.raises(BackupIdentityError):
        protect(state, authority, genesis=genesis, head=head)
    assert snapshot(state) == original and repository.writes == 1


@pytest.mark.parametrize(
    "name",
    [
        "intake",
        "exports",
        "intents",
        "authorization/jobs",
        "authorization/results",
        "authorization/correlations",
    ],
)
def test_transient_or_queued_history_is_not_an_unlaunched_rollout(
    state: Path, repository: Repository, authority: BackupAuthority, name: str
) -> None:
    (state / name / "pending").write_bytes(b"original pending work")
    (state / name / "pending").chmod(0o600)
    original = snapshot(state)
    with pytest.raises((StatePathError, BackupIdentityError)):
        protect(state, authority)
    assert snapshot(state) == original and repository.writes == 1


def test_private_workspace_refuses_symlink_without_touching_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rollout, "measure_filesystem_capacity_descriptor", available_capacity)
    target = tmp_path / "outside"
    target.mkdir(mode=0o700)
    (tmp_path / "proof").symlink_to(target, target_is_directory=True)
    with pytest.raises((StatePathError, OSError)):
        rollout._private(tmp_path / "proof", os.geteuid())
    assert not list(target.iterdir())
