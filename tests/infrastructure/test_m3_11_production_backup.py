"""The root backup action retains original authority across real kernel leases."""

from __future__ import annotations

import fcntl
import json
import sys
from pathlib import Path
from typing import cast

import pytest

from infrastructure.test_m3_11_production_initialize import LEASE_COUNT, OWNER, write
from infrastructure.test_m3_11_production_initialize import host as predecessor_host  # noqa: F401
from infrastructure.test_m3_11_production_journal import records as records  # noqa: PLC0414
from scripts import m3_11_production_backup as backup
from scripts import m3_11_production_fence as fence
from scripts import m3_11_production_initialize as initialize
from scripts import m3_11_production_probe as probe
from scripts import m3_11_production_records as wire


@pytest.fixture
def host(predecessor_host: Path, records: list[tuple[str, bytes]]) -> Path:  # noqa: F811
    for name, raw in records[4:10]:
        wire.operate(wire.ROOT, ["publish", name], raw, owner=OWNER)
    write(
        probe.BACKUP,
        probe.BACKUP.read_bytes()
        + b"LOWERDUCKPOND_BACKUP_STATIC_RECOVERY_ENABLED=true\n"
        + b"LOWERDUCKPOND_AUDIT_ROTATION_ENABLED=false\n"
        + b"LOWERDUCKPOND_BACKUP_STATUS_SCOPE="
        + b"e" * 64
        + b"\n",
        0o600,
    )
    return predecessor_host


@pytest.fixture
def calls(
    host: Path, records: list[tuple[str, bytes]], monkeypatch: pytest.MonkeyPatch
) -> list[str]:
    calls: list[str] = []

    def candidate(
        chain: list[tuple[str, bytes]], environment: dict[str, str], descriptors: tuple[int, int]
    ) -> dict[str, str]:
        assert (host / "verified").read_bytes() == b"yes"
        assert sys.path[0] == str(probe.SELECTION.resolve() / "site-packages")
        assert chain == records[:10]
        assert "UNRELATED_SECRET" not in environment
        assert environment["LOWERDUCKPOND_BACKUP_NODE_NAME"] == probe.NODE
        assert environment["LOWERDUCKPOND_BACKUP_STATUS_SCOPE"] == "e" * 64
        assert environment["RESTIC_CACHE_DIR"] == str(backup.CACHE / "restic-cache")
        assert len(descriptors) == LEASE_COUNT
        for path in (initialize.REPOSITORY_LOCK, initialize.SELECTION_LOCK):
            with path.open("rb") as rival, pytest.raises(BlockingIOError):
                fcntl.flock(rival, fcntl.LOCK_EX | fcntl.LOCK_NB)
        calls.append("backup")
        return cast(dict[str, str], json.loads(records[10][1])["observations"])

    monkeypatch.setattr(backup, "_candidate", candidate)
    monkeypatch.setenv("UNRELATED_SECRET", "fake-unrelated-secret")
    return calls


def test_backup_keeps_original_phase_locks_and_verifies_artifact_before_import(
    host: Path, calls: list[str], records: list[tuple[str, bytes]]
) -> None:
    before = sys.path[:]
    assert json.loads(backup.verify(owner=OWNER)) == json.loads(records[10][1])["observations"]
    assert calls == ["backup"] and sys.path == before
    for path in (initialize.REPOSITORY_LOCK, initialize.SELECTION_LOCK):
        with path.open("rb") as available:
            fcntl.flock(available, fcntl.LOCK_EX | fcntl.LOCK_NB)


@pytest.mark.parametrize(
    "fault",
    ["phase", "predecessor", "publication", "selection", "condition", "recovery", "rotation"],
)
def test_missing_or_changed_authority_prevents_backup(
    host: Path, calls: list[str], records: list[tuple[str, bytes]], fault: str
) -> None:
    if fault == "phase":
        wire.operate(wire.ROOT, ["publish", records[10][0]], records[10][1], owner=OWNER)
    elif fault == "predecessor":
        write(probe.COMPLETION, b"changed\n")
    elif fault == "publication":
        write(probe.PUBLICATION, probe.PUBLICATION.read_bytes().replace(b"false", b"true"))
    elif fault == "selection":
        probe.SELECTION.unlink()
        probe.SELECTION.symlink_to(host)
    elif fault == "condition":
        (fence.UNITS / (next(iter(fence.FENCES)) + ".d") / fence.NAME).unlink()
    else:
        raw = probe.BACKUP.read_bytes()
        raw = raw.replace(
            b"RECOVERY_ENABLED=true" if fault == "recovery" else b"ROTATION_ENABLED=false",
            b"RECOVERY_ENABLED=false" if fault == "recovery" else b"ROTATION_ENABLED=true",
        )
        write(probe.BACKUP, raw, 0o600)
    with pytest.raises((ValueError, OSError)):
        backup.verify(owner=OWNER)
    assert not calls


@pytest.mark.parametrize("fault", ["backup", "lock", "phase", "condition", "exception"])
def test_mid_backup_drift_cannot_emit_success(
    host: Path,
    calls: list[str],
    records: list[tuple[str, bytes]],
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    original = backup._candidate
    before = sys.path[:]

    def changed(
        chain: list[tuple[str, bytes]], environment: dict[str, str], descriptors: tuple[int, int]
    ) -> dict[str, str]:
        result = original(chain, environment, descriptors)
        if fault == "backup":
            write(probe.BACKUP, probe.BACKUP.read_bytes() + b"# changed\n", 0o600)
        elif fault == "lock":
            initialize.SELECTION_LOCK.rename(host / "original-selection.lock")
            write(initialize.SELECTION_LOCK, b"", 0o600)
        elif fault == "phase":
            wire.operate(wire.ROOT, ["publish", records[10][0]], records[10][1], owner=OWNER)
        elif fault == "condition":
            write(fence.UNITS / (next(iter(fence.FENCES)) + ".d") / fence.NAME, b"changed\n")
        else:
            raise ValueError("candidate failed")
        return result

    monkeypatch.setattr(backup, "_candidate", changed)
    with pytest.raises(ValueError):
        backup.verify(owner=OWNER)
    assert calls == ["backup"] and sys.path == before
