from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import BinaryIO

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import backup_snapshot as snapshot_module
from lowerduckpond_static_host_agent.backup_descriptor import encode_backup_descriptor
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, RepositoryIdentity
from lowerduckpond_static_host_agent.backup_restic import RepositorySnapshot
from lowerduckpond_static_host_agent.backup_sources import EXCLUDE_PATHS, SOURCE_PATHS, STAGED_PATHS
from test_backup_descriptor import document as document  # noqa: PLC0414 - pytest fixture

SNAPSHOT_ID = "e" * 64
REPOSITORY = RepositoryIdentity("a" * 64, "node", "/private/backup")


@pytest.mark.parametrize(
    "damage",
    [
        None,
        "command",
        "no-summary",
        "partial-id",
        "wrong-node",
        "wrong-repository",
        "tags",
        "duplicate",
        "missing",
        "readback",
        "readback-error",
    ],
)
def test_capture_requires_successful_full_id_unique_binding_and_exact_readback(
    document: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    damage: str | None,
) -> None:
    raw = encode_backup_descriptor(document)
    capture_tag = f"capture-{document['captureId']}"
    lineage = document["lineage"]
    assert type(lineage) is dict
    tags = (
        "scheduled",
        "scope-" + "d" * 64,
        "lowerduckpond-static-backup",
        capture_tag,
        f"lineage-{lineage['lineageId']}",
        "repository-" + REPOSITORY.binding()["value"],
    )
    environment = {
        "LOWERDUCKPOND_BACKUP_STATUS_SCOPE": "d" * 64,
        "LOWERDUCKPOND_BACKUP_NODE_NAME": "node",
        "RESTIC_REPOSITORY": REPOSITORY.locator,
        "RESTIC_PASSWORD": "fake-backup-password",
    }
    invocations: list[tuple[str, ...]] = []

    def run(
        arguments: tuple[str, ...],
        passed: Mapping[str, str],
        limit: int,
        source: BinaryIO | None,
        *,
        timeout_seconds: int,
    ) -> bytes:
        invocations.append(arguments)
        assert passed is environment
        assert source is None
        assert limit == 32 * 1024
        assert timeout_seconds == 30 * 60
        assert arguments[:5] == ("backup", "--json", "--quiet", "--host", "node")
        assert arguments[-5:] == (*SOURCE_PATHS.values(), *STAGED_PATHS.values())
        excludes = tuple(
            arguments[index + 1] for index, value in enumerate(arguments) if value == "--exclude"
        )
        assert excludes == EXCLUDE_PATHS
        passed_tags = tuple(
            arguments[index + 1] for index, value in enumerate(arguments) if value == "--tag"
        )
        assert passed_tags == tags
        if damage == "command":
            raise BackupIdentityError("nonzero exit, including incomplete snapshot exit 3")
        return canonical_json_bytes(
            {
                "message_type": "status" if damage == "no-summary" else "summary",
                "snapshot_id": SNAPSHOT_ID[:8] if damage == "partial-id" else SNAPSHOT_ID,
            }
        )

    def discover(
        _environment: Mapping[str, str],
    ) -> tuple[RepositoryIdentity, tuple[RepositorySnapshot, ...]]:
        snapshot = RepositorySnapshot(SNAPSHOT_ID, "node", tags)
        if damage == "wrong-node":
            snapshot = replace(snapshot, hostname="other-node")
        if damage == "tags":
            snapshot = replace(snapshot, tags=tags[:-1])
        rows = (
            ()
            if damage == "missing"
            else (snapshot, snapshot)
            if damage == "duplicate"
            else (snapshot,)
        )
        identity = (
            replace(REPOSITORY, config_id="b" * 64) if damage == "wrong-repository" else REPOSITORY
        )
        return identity, rows

    def readback(arguments: tuple[str, ...], _environment: Mapping[str, str], limit: int) -> bytes:
        assert arguments == ("dump", SNAPSHOT_ID, STAGED_PATHS["descriptor"])
        assert limit == 256 * 1024
        if damage == "readback-error":
            raise BackupIdentityError("repository read failed")
        return b"wrong bytes" if damage == "readback" else raw

    monkeypatch.setattr(snapshot_module, "_run_restic", run)
    monkeypatch.setattr(snapshot_module, "discover_repository", discover)
    monkeypatch.setattr(snapshot_module, "_restic", readback)
    if damage is None:
        assert snapshot_module.create_coherent_snapshot(raw, environment) == SNAPSHOT_ID
    else:
        with pytest.raises(BackupIdentityError):
            snapshot_module.create_coherent_snapshot(raw, environment)
    assert len(invocations) == 1  # No retry can hide an uncertain remote outcome.


def test_unbound_configuration_never_starts_restic(
    document: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected(*_args: object, **_kwargs: object) -> bytes:
        pytest.fail("unbound configuration reached Restic")

    monkeypatch.setattr(snapshot_module, "_run_restic", unexpected)
    with pytest.raises(BackupIdentityError):
        snapshot_module.create_coherent_snapshot(encode_backup_descriptor(document), {})
