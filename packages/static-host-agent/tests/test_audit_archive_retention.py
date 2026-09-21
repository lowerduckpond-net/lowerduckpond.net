from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any

import pytest
from lowerduckpond_static_host_agent import audit_archive_restic as adapter
from lowerduckpond_static_host_agent.audit_archive_formats import ARCHIVE_TAG
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.backup_restic import (
    LINEAGE_TAG,
    MAX_SNAPSHOT_BYTES,
    RepositorySnapshot,
)
from test_audit_archive_formats import IDENTITY

KEEP = "1" * 64
REMOVE = "2" * 64
PROTECTED = "3" * 64
SNAPSHOTS = (
    RepositorySnapshot(KEEP, IDENTITY.node_name, ("scheduled",), ("/ordinary",)),
    RepositorySnapshot(REMOVE, IDENTITY.node_name, ("scheduled",), ("/ordinary",)),
    RepositorySnapshot(PROTECTED, IDENTITY.node_name, (ARCHIVE_TAG,), (adapter.SNAPSHOT_SOURCE,)),
)


def proposal() -> list[dict[str, Any]]:
    def record(snapshot_id: str) -> dict[str, object]:
        return {
            "id": snapshot_id,
            "hostname": IDENTITY.node_name,
            "tags": ["scheduled"],
            "paths": ["/ordinary"],
        }

    return [
        {
            "tags": None,
            "host": IDENTITY.node_name,
            "paths": ["/ordinary"],
            "keep": [record(KEEP)],
            "remove": [record(REMOVE)],
            "reasons": [],
        }
    ]


def select(
    monkeypatch: pytest.MonkeyPatch,
    response: bytes,
    snapshots: tuple[RepositorySnapshot, ...] = SNAPSHOTS,
) -> tuple[str, ...]:
    def restic(arguments: tuple[str, ...], _environment: Mapping[str, str], limit: int) -> bytes:
        assert arguments == (
            "forget",
            "--json",
            "--dry-run",
            "--host",
            IDENTITY.node_name,
            "--tag",
            "scheduled",
            "--group-by",
            "host,paths",
            "--keep-daily",
            "7",
            "--keep-weekly",
            "5",
            "--keep-monthly",
            "12",
        )
        assert limit == MAX_SNAPSHOT_BYTES
        return response

    monkeypatch.setattr(adapter, "_restic", restic)
    return adapter.ordinary_retention_ids(IDENTITY, snapshots, frozenset({PROTECTED}), {})


def test_selection_is_bound_to_full_independently_inventoried_ordinary_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert select(monkeypatch, json.dumps(proposal()).encode()) == (REMOVE,)


@pytest.mark.parametrize(
    "fault",
    [
        "protected",
        "unknown",
        "short-id",
        "missing",
        "duplicate",
        "cross-group",
        "host",
        "tags",
        "paths",
        "group-host",
        "group-paths",
        "group-tags",
        "no-keep",
        "extra-key",
        "empty",
        "wrong-shape",
        "duplicate-key",
    ],
)
def test_malformed_or_conflicting_selection_never_authorizes_forget(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    groups = proposal()
    group = groups[0]
    removed = group["remove"][0]
    if fault in {"protected", "unknown", "short-id"}:
        removed["id"] = {"protected": PROTECTED, "unknown": "9" * 64, "short-id": REMOVE[:8]}[fault]
    elif fault == "missing":
        group["remove"] = None
    elif fault == "duplicate":
        group["remove"].append(copy.deepcopy(removed))
    elif fault == "cross-group":
        groups.append(copy.deepcopy(group))
    elif fault in {"host", "tags", "paths"}:
        field = "hostname" if fault == "host" else fault
        removed[field] = "other-node" if fault == "host" else ["other"]
    elif fault == "group-host":
        group["host"] = "other-node"
    elif fault == "group-paths":
        group["paths"] = ["/other"]
    elif fault == "group-tags":
        group["tags"] = ["scheduled"]
    elif fault == "no-keep":
        group["keep"] = None
    elif fault == "extra-key":
        group["unknown"] = True
    raw = {
        "empty": b"",
        "wrong-shape": b"{}",
        "duplicate-key": b'[{"host":"one","host":"two"}]',
    }.get(fault, json.dumps(groups).encode())
    with pytest.raises(BackupIdentityError):
        select(monkeypatch, raw)


@pytest.mark.parametrize(
    "tags",
    [
        ("scheduled",),
        ("scheduled", ARCHIVE_TAG),
        ("scheduled", LINEAGE_TAG),
    ],
)
def test_scheduled_cannot_override_protected_inventory_or_reserved_tags(
    monkeypatch: pytest.MonkeyPatch, tags: tuple[str, ...]
) -> None:
    snapshot = RepositorySnapshot(PROTECTED, IDENTITY.node_name, tags, ("/ordinary",))
    with pytest.raises(BackupIdentityError, match="protected"):
        select(monkeypatch, b"", (snapshot,))


def test_empty_restic_output_is_valid_only_without_eligible_snapshots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert select(monkeypatch, b"", SNAPSHOTS[2:]) == ()
    with pytest.raises(BackupIdentityError):
        select(monkeypatch, b"")


def test_no_removals_is_still_a_complete_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    groups = proposal()
    groups[0]["keep"].extend(groups[0]["remove"])
    groups[0]["remove"] = None
    assert select(monkeypatch, json.dumps(groups).encode()) == ()


def test_destructive_phases_use_disjoint_fixed_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def restic(_arguments: tuple[str, ...], _environment: Mapping[str, str], _limit: int) -> bytes:
        pytest.fail("destructive maintenance must not use the shorter metadata deadline")

    def run(
        arguments: tuple[str, ...],
        _environment: Mapping[str, str],
        _limit: int,
        source: object,
        *,
        timeout_seconds: int,
    ) -> bytes:
        assert source is None and timeout_seconds == adapter.MAINTENANCE_TIMEOUT_SECONDS
        assert _limit == 32 * 1024
        calls.append(arguments)
        return b""

    monkeypatch.setattr(adapter, "_restic", restic)
    monkeypatch.setattr(adapter, "_run_restic", run)
    adapter.forget_exact_ids((), {})
    assert calls == []
    adapter.forget_exact_ids((REMOVE,), {})
    assert calls == [("forget", "--quiet", REMOVE)]
    adapter.prune_repository({})
    adapter.check_repository({})
    assert calls == [("forget", "--quiet", REMOVE), ("prune", "--quiet"), ("check", "--quiet")]
    for ids in (("latest",), (REMOVE, REMOVE), (REMOVE, KEEP)):
        with pytest.raises(BackupIdentityError):
            adapter.forget_exact_ids(ids, {})
    assert calls == [("forget", "--quiet", REMOVE), ("prune", "--quiet"), ("check", "--quiet")]
