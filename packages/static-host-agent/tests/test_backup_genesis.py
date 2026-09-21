from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Mapping
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import DurabilityBoundary
from lowerduckpond_static_host_agent import backup_restic as restic
from lowerduckpond_static_host_agent.audit import AuditError
from lowerduckpond_static_host_agent.backup_entrypoint import ensure_lineage
from lowerduckpond_static_host_agent.backup_identity import (
    GENESIS_PATH,
    LINEAGE_PATH,
    BackupIdentityError,
)
from test_backup_identity import IDENTITY, _append
from test_backup_identity import state as state  # noqa: PLC0414 - re-export pytest fixture

ENVIRONMENT = {
    "RESTIC_REPOSITORY": IDENTITY.locator,
    "LOWERDUCKPOND_BACKUP_NODE_NAME": IDENTITY.node_name,
}


class Repository:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.raw = b""
        self.writes = 0
        self.fault = ""
        self.snapshots: list[dict[str, object]] = [
            {"id": "b" * 64, "hostname": IDENTITY.node_name, "tags": ["scheduled", "scope-old"]}
        ]

    def run(
        self,
        arguments: tuple[str, ...],
        _environment: Mapping[str, str],
        _limit: int,
        payload: bytes | None = None,
    ) -> bytes:
        # Every network operation must occur outside the exclusive state lease.
        with (self.root / "locks/tenant-state.lock").open("rb") as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        match arguments:
            case ("cat", "config"):
                return json.dumps({"id": IDENTITY.config_id, "version": 2}).encode()
            case ("snapshots", "--json"):
                return json.dumps(self.snapshots).encode()
            case ("dump", _, "/audit-lineage-genesis.json"):
                if self.fault == "unavailable":
                    raise BackupIdentityError("unavailable")
                return self.raw
            case ("ls", "--json", snapshot):
                return self.listing(snapshot)
            case ("backup", *_):
                assert payload is not None
                assert not self.root.joinpath(*LINEAGE_PATH).exists()
                if self.fault == "before-snapshot":
                    raise BackupIdentityError("interrupted before commit")
                self.writes += 1
                self.raw = payload
                self.snapshots.append(
                    {
                        "id": "c" * 64,
                        "hostname": IDENTITY.node_name,
                        "tags": [
                            arguments[index + 1]
                            for index, argument in enumerate(arguments)
                            if argument == "--tag"
                        ],
                    }
                )
                if self.fault == "lost-response":
                    raise BackupIdentityError("lost response after snapshot commit")
                if self.fault == "audit-advance":
                    _append(self.root, 1)
                if self.fault == "audit-loss":
                    (self.root / "audit/segment-00000000000000000000.jsonl").unlink()
                return b"{}\n"
            case _:
                pytest.fail(f"unexpected operation {arguments}")

    def listing(self, snapshot: str) -> bytes:
        entries: list[dict[str, object]] = [
            {"struct_type": "snapshot", "id": snapshot},
            {
                "struct_type": "node",
                "type": "file",
                "path": "/audit-lineage-genesis.json",
                "size": len(self.raw),
            },
        ]
        if self.fault == "extra-file":
            entries.append(dict(entries[1]))
        if self.fault in {"symlink", "wrong-size", "wrong-path", "wrong-header"}:
            field, value = {
                "symlink": ("type", "symlink"),
                "wrong-size": ("size", 0),
                "wrong-path": ("path", "/other"),
                "wrong-header": ("struct_type", "unknown"),
            }[self.fault]
            entries[1][field] = value
        return b"".join(canonical_json_bytes(entry) for entry in entries)


@pytest.fixture
def repository(state: Path, monkeypatch: pytest.MonkeyPatch) -> Repository:
    repository = Repository(state)
    monkeypatch.setattr(restic, "_restic", repository.run)
    return repository


def _initialize(root: Path) -> dict[str, object]:
    return ensure_lineage(root, ENVIRONMENT, initialize=True, expected_owner=os.geteuid())


@pytest.mark.parametrize("fault", ["before-snapshot", "lost-response", "audit-advance"])
def test_repository_publication_interruptions_resume_without_duplicate_snapshot(
    state: Path,
    repository: Repository,
    fault: str,
) -> None:
    repository.fault = fault
    if fault == "audit-advance":
        original = _initialize(state)
    else:
        with pytest.raises(BackupIdentityError):
            _initialize(state)
        assert not state.joinpath(*LINEAGE_PATH).exists()
        original = json.loads(state.joinpath(*GENESIS_PATH).read_bytes())
    repository.fault = ""
    assert _initialize(state) == original
    assert repository.writes == 1
    assert (
        ensure_lineage(state, ENVIRONMENT, initialize=False, expected_owner=os.geteuid())
        == original
    )
    assert repository.writes == 1


def test_interruption_after_repository_commit_before_primary_resumes_original_identity(
    state: Path,
    repository: Repository,
) -> None:
    def interrupt(boundary: DurabilityBoundary) -> None:
        if boundary is DurabilityBoundary.FILE_SYNC:
            raise InterruptedError("primary publication interrupted")

    with pytest.raises(InterruptedError):
        ensure_lineage(
            state, ENVIRONMENT, initialize=True, expected_owner=os.geteuid(), failure_hook=interrupt
        )
    original = json.loads(repository.raw)
    assert not state.joinpath(*LINEAGE_PATH).exists()
    assert _initialize(state) == original
    assert repository.writes == 1


def test_restoring_pre_migration_tree_cannot_fork_completed_repository_lineage(
    state: Path,
    repository: Repository,
) -> None:
    _initialize(state)
    original = repository.raw
    state.joinpath(*LINEAGE_PATH).unlink()
    state.joinpath(*GENESIS_PATH).unlink()
    with pytest.raises(BackupIdentityError, match="existing audit lineage"):
        _initialize(state)
    assert not state.joinpath(*LINEAGE_PATH).exists()
    assert not state.joinpath(*GENESIS_PATH).exists()
    assert repository.writes == 1 and repository.raw == original


@pytest.mark.parametrize(
    "fault",
    [
        "unavailable",
        "corrupt",
        "missing",
        "duplicate",
        "wrong-host",
        "wrong-binding",
        "scheduled",
        "extra-file",
        "symlink",
        "wrong-size",
        "wrong-path",
        "wrong-header",
    ],
)
def test_repository_proof_damage_never_authorizes_reinitialization(
    state: Path,
    repository: Repository,
    fault: str,
) -> None:
    _initialize(state)
    original = state.joinpath(*LINEAGE_PATH).read_bytes()
    repository.fault = fault
    if fault == "corrupt":
        repository.raw = b"{}\n"
    elif fault == "missing":
        repository.snapshots.pop()
    elif fault == "duplicate":
        repository.snapshots.append({**repository.snapshots[-1], "id": "d" * 64})
    elif fault == "wrong-host":
        repository.snapshots[-1]["hostname"] = "other"
    elif fault == "wrong-binding":
        record = json.loads(repository.raw)
        record["repository"]["nodeName"] = "other"
        repository.raw = canonical_json_bytes(record)
    elif fault == "scheduled":
        repository.snapshots[-1]["tags"] = [
            *restic.lineage_tags(json.loads(repository.raw)),
            "scheduled",
        ]
    with pytest.raises(BackupIdentityError):
        _initialize(state)
    assert repository.writes == 1
    assert state.joinpath(*LINEAGE_PATH).read_bytes() == original


def test_audit_revalidated_after_remote_publication_before_primary_commit(
    state: Path,
    repository: Repository,
) -> None:
    repository.fault = "audit-loss"
    with pytest.raises((BackupIdentityError, AuditError)):
        _initialize(state)
    assert repository.writes == 1
    assert not state.joinpath(*LINEAGE_PATH).exists()
