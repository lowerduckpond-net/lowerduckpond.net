"""The candidate is callable only inside the original, stopped migration phase."""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from infrastructure.test_m3_11_production_journal import (
    records as records,  # noqa: PLC0414 - original immutable phase-chain fixture
)
from infrastructure.test_m3_11_production_preflight import backup_environment
from scripts import m3_11_production_fence as fence
from scripts import m3_11_production_initialize as initialize
from scripts import m3_11_production_probe as probe
from scripts import m3_11_production_records as wire

OWNER = os.geteuid()
LEASE_COUNT = 2


def write(path: Path, raw: bytes, mode: int = 0o400) -> None:
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(mode)


@pytest.fixture
def host(tmp_path: Path, records: list[tuple[str, bytes]], monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    for name in ("convergence", "artifacts", "units"):
        (root / name).mkdir(mode=0o700)
    monkeypatch.setattr(wire, "ROOT", root / "convergence/m3-11")
    for name, raw in records[:4]:
        wire.operate(wire.ROOT, ["publish", name], raw, owner=OWNER)
    original = json.loads(records[0][1])
    artifact = root / "artifacts" / original["candidate"]["artifact_sha256"]
    artifact.mkdir(mode=0o555)
    monkeypatch.setattr(probe, "SELECTION", root / "artifacts/current")
    probe.SELECTION.symlink_to(artifact, target_is_directory=True)
    monkeypatch.setattr(probe, "COMPLETION", root / "convergence/m3-10")
    write(probe.COMPLETION, original["predecessor"].encode())
    monkeypatch.setattr(probe, "PUBLICATION", root / "publication.json")
    write(
        probe.PUBLICATION,
        b'{"format":"lowerduckpond-static-publication-gate-v1","static_publication_enabled":false}\n',
    )
    monkeypatch.setattr(probe, "BACKUP", root / "backup.env")
    write(probe.BACKUP, backup_environment(), 0o600)
    monkeypatch.setattr(initialize, "REPOSITORY_LOCK", root / "repository.lock")
    monkeypatch.setattr(initialize, "SELECTION_LOCK", root / "selection.lock")
    for path in (initialize.REPOSITORY_LOCK, initialize.SELECTION_LOCK):
        write(path, b"", 0o600)
    monkeypatch.setattr(fence, "UNITS", root / "units")
    for unit, phase in fence.FENCES.items():
        fence.publish(fence.UNITS / (unit + ".d"), fence.content(records[0][1], phase), owner=OWNER)

    def run(arguments: list[str], *, stop: bool = False) -> bytes:
        assert not stop
        if arguments[0].endswith("verify-static-host-agent-artifact"):
            assert arguments[1] == str(artifact)
            write(root / "verified", b"yes")
            return b""
        if "--property=LoadState" in arguments:
            return b"not-found\n"
        assert "list-units" in arguments
        return b"[]\n"

    def processes(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert arguments == ["/usr/bin/pgrep", "--full", "--", fence.PROCESS_PATTERN]
        return subprocess.CompletedProcess(arguments, 1, b"", b"")

    monkeypatch.setattr(fence, "run", run)
    monkeypatch.setattr(subprocess, "run", processes)
    return root


@pytest.fixture
def calls(host: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def candidate(
        phase: str,
        original: dict[str, object],
        environment: dict[str, str],
        descriptors: tuple[int, int],
    ) -> dict[str, str]:
        assert (host / "verified").read_bytes() == b"yes"
        assert sys.path[0] == str(probe.SELECTION.resolve() / "site-packages")
        assert "UNRELATED_SECRET" not in environment
        assert environment["LOWERDUCKPOND_BACKUP_NODE_NAME"] == probe.NODE
        assert original["repository_binding"] == "2" * 64
        assert len(descriptors) == LEASE_COUNT
        for path in (initialize.REPOSITORY_LOCK, initialize.SELECTION_LOCK):
            with path.open("rb") as rival, pytest.raises(BlockingIOError):
                fcntl.flock(rival, fcntl.LOCK_EX | fcntl.LOCK_NB)
        calls.append(phase)
        return {"observed": phase}

    monkeypatch.setattr(initialize, "_candidate", candidate)
    monkeypatch.setenv("UNRELATED_SECRET", "fake-unrelated-secret")
    return calls


@pytest.mark.parametrize("phase", ["namespace", "lineage"])
def test_exact_phase_holds_real_repository_and_selection_locks_across_candidate(
    host: Path, calls: list[str], records: list[tuple[str, bytes]], phase: str
) -> None:
    if phase == "lineage":
        for name, raw in records[4:6]:
            wire.operate(wire.ROOT, ["publish", name], raw, owner=OWNER)
    before = sys.path[:]
    assert json.loads(initialize.initialize(phase, owner=OWNER)) == {"observed": phase}
    assert calls == [phase] and sys.path == before
    for path in (initialize.REPOSITORY_LOCK, initialize.SELECTION_LOCK):
        with path.open("rb") as available:
            fcntl.flock(available, fcntl.LOCK_EX | fcntl.LOCK_NB)


@pytest.mark.parametrize(
    "fault",
    [
        "phase",
        "operation",
        "predecessor",
        "publication",
        "publication-zero",
        "selection",
        "condition",
        "lock-mode",
        "lock-link",
        "backup-mode",
    ],
)
def test_changed_or_missing_authority_never_invokes_candidate(
    host: Path, calls: list[str], fault: str
) -> None:
    phase = "namespace"
    if fault == "phase":
        phase = "lineage"
    elif fault == "operation":
        phase = "invented"
    elif fault == "predecessor":
        write(probe.COMPLETION, b"changed\n")
    elif fault == "publication":
        write(probe.PUBLICATION, probe.PUBLICATION.read_bytes().replace(b"false", b"true"))
    elif fault == "publication-zero":
        write(probe.PUBLICATION, probe.PUBLICATION.read_bytes().replace(b"false", b"0"))
    elif fault == "selection":
        probe.SELECTION.unlink()
        probe.SELECTION.symlink_to(host)
    elif fault == "condition":
        (fence.UNITS / (next(iter(fence.FENCES)) + ".d") / fence.NAME).unlink()
    elif fault == "lock-mode":
        initialize.REPOSITORY_LOCK.chmod(0o644)
    elif fault == "lock-link":
        initialize.REPOSITORY_LOCK.unlink()
        initialize.REPOSITORY_LOCK.symlink_to(initialize.SELECTION_LOCK)
    elif fault == "backup-mode":
        write(
            probe.BACKUP,
            probe.BACKUP.read_bytes() + b"LOWERDUCKPOND_BACKUP_STATIC_RECOVERY_ENABLED=true\n",
            0o600,
        )
    with pytest.raises((ValueError, OSError)):
        initialize.initialize(phase, owner=OWNER)
    assert not calls


@pytest.mark.parametrize("fault", ["backup", "lock", "phase", "exception"])
def test_mid_action_drift_cannot_emit_a_success_observation(
    host: Path,
    calls: list[str],
    records: list[tuple[str, bytes]],
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    original = initialize._candidate
    before = sys.path[:]

    def changed(
        phase: str,
        proposal: dict[str, object],
        environment: dict[str, str],
        descriptors: tuple[int, int],
    ) -> dict[str, str]:
        result = original(phase, proposal, environment, descriptors)
        if fault == "backup":
            write(probe.BACKUP, probe.BACKUP.read_bytes() + b"# changed\n", 0o600)
        elif fault == "lock":
            initialize.SELECTION_LOCK.rename(host / "original-selection.lock")
            write(initialize.SELECTION_LOCK, b"", 0o600)
        elif fault == "phase":
            wire.operate(wire.ROOT, ["publish", records[4][0]], records[4][1], owner=OWNER)
        else:
            raise ValueError("candidate failed")
        return result

    monkeypatch.setattr(initialize, "_candidate", changed)
    with pytest.raises(ValueError):
        initialize.initialize("namespace", owner=OWNER)
    assert calls == ["namespace"] and sys.path == before
