"""Resume observations read actual phase, configuration and empty-state authority."""

from __future__ import annotations

import fcntl
import json
from pathlib import Path

import pytest

from infrastructure.test_m3_11_production_initialize import OWNER, write
from infrastructure.test_m3_11_production_initialize import host as host  # noqa: PLC0414
from infrastructure.test_m3_11_production_journal import records as records  # noqa: PLC0414
from infrastructure.test_m3_11_production_preflight import backup_environment
from infrastructure.test_m3_11_production_replica import snapshot
from scripts import m3_11_production_fence as fence
from scripts import m3_11_production_initialize as initialize
from scripts import m3_11_production_journal as journal
from scripts import m3_11_production_observe as observe
from scripts import m3_11_production_probe as probe
from scripts import m3_11_production_records as wire

DRAINED = journal.RECORDS.index("drained") + 1
CONVERGING = journal.RECORDS.index("converged.started") + 1
ROTATING = journal.RECORDS.index("rotation-enabled.started") + 1


@pytest.fixture
def prepared(host: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(wire, "ROOT", host / "convergence/observed")
    monkeypatch.setattr(initialize, "STATIC", host / "static")
    for name in ("", "locks", "authorization", *observe.EMPTY):
        (initialize.STATIC / name).mkdir(mode=0o700, exist_ok=True)
    for name in observe.LOCKS:
        write(initialize.STATIC / "locks" / name, b"", 0o600)

    def run(arguments: list[str]) -> bytes:
        assert arguments == [
            "/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact",
            str(probe.SELECTION.resolve()),
        ]
        return b""

    def config(environment: dict[str, str]) -> bytes:
        for lock in (initialize.REPOSITORY_LOCK, initialize.SELECTION_LOCK):
            with lock.open("rb") as stream, pytest.raises(BlockingIOError):
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert "UNRELATED_SECRET" not in environment
        return json.dumps({"version": 2, "id": "a" * 64}).encode()

    monkeypatch.setattr(fence, "run", run)
    monkeypatch.setattr(probe, "repository_config", config)
    monkeypatch.setenv("UNRELATED_SECRET", "fixture-secret")
    return host


def select(records: list[tuple[str, bytes]], count: int, recovery: bool, rotation: bool) -> None:
    for name, raw in records[:count]:
        wire.operate(wire.ROOT, ["publish", name], raw, owner=OWNER)
    original = json.loads(records[0][1])
    artifact = (
        original["predecessor"].split()[0]
        if count <= DRAINED
        else original["candidate"]["artifact_sha256"]
    )
    selected = probe.SELECTION.parent / artifact
    selected.mkdir(mode=0o555, exist_ok=True)
    probe.SELECTION.unlink()
    probe.SELECTION.symlink_to(selected)
    write(
        probe.BACKUP,
        backup_environment()
        + f"LOWERDUCKPOND_BACKUP_STATIC_RECOVERY_ENABLED={str(recovery).lower()}\n".encode()
        + f"LOWERDUCKPOND_AUDIT_ROTATION_ENABLED={str(rotation).lower()}\n".encode(),
        0o600,
    )


@pytest.mark.parametrize("count", range(1, 16))
def test_each_original_phase_produces_fresh_readonly_authority(
    prepared: Path, records: list[tuple[str, bytes]], count: int
) -> None:
    select(records, count, recovery=count >= CONVERGING, rotation=count >= ROTATING)
    before = snapshot(wire.ROOT)
    result = json.loads(observe.observe(owner=OWNER))
    assert result["original_sha256"] == journal.digest(records[0][1])
    assert result["last_sha256"] == journal.digest(records[count - 1][1])
    assert result["repository_config_id"] == "a" * 64
    assert result["archive_authority"] == {
        "format": "lowerduckpond-m3-10-archive-authority-v1",
        "artifactSha256": "f" * 64 if count <= DRAINED else "b" * 64,
        "sourceRevision": "1" * 40 if count <= DRAINED else "a" * 40,
        "archives": [],
    }
    assert snapshot(wire.ROOT) == before


@pytest.mark.parametrize(("count", "recovery", "rotation"), [(8, False, False), (12, True, False)])
def test_interrupted_converge_observes_either_permitted_configuration(
    prepared: Path, records: list[tuple[str, bytes]], count: int, recovery: bool, rotation: bool
) -> None:
    select(records, count, recovery, rotation)
    assert json.loads(observe.observe(owner=OWNER))["archive_authority"]["archives"] == []


@pytest.mark.parametrize("name", observe.EMPTY)
def test_resume_refuses_existing_or_queued_tenant_authority(
    prepared: Path, records: list[tuple[str, bytes]], name: str
) -> None:
    select(records, 15, True, True)
    path = initialize.STATIC / name / "retained"
    write(path, b"original private authority")
    with pytest.raises(ValueError, match="retained tenant"):
        observe.observe(owner=OWNER)
    assert path.read_bytes() == b"original private authority"


@pytest.mark.parametrize(
    "fault", ["phase", "predecessor", "publication", "configuration", "directory", "lock"]
)
def test_changed_authority_is_refused_during_observation(
    prepared: Path,
    records: list[tuple[str, bytes]],
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    select(records, 14, True, True)
    original = probe.repository_config

    def changed(environment: dict[str, str]) -> bytes:
        result = original(environment)
        if fault == "phase":
            wire.operate(wire.ROOT, ["publish", *records[14][:1]], records[14][1], owner=OWNER)
        elif fault == "predecessor":
            write(probe.COMPLETION, b"changed\n")
        elif fault == "publication":
            write(probe.PUBLICATION, probe.PUBLICATION.read_bytes().replace(b"false", b"true"))
        elif fault == "configuration":
            write(probe.BACKUP, probe.BACKUP.read_bytes() + b"# changed\n", 0o600)
        elif fault == "directory":
            (initialize.STATIC / "tenants").chmod(0o755)
        else:
            initialize.REPOSITORY_LOCK.rename(prepared / "original.lock")
            write(initialize.REPOSITORY_LOCK, b"", 0o600)
        return result

    monkeypatch.setattr(probe, "repository_config", changed)
    with pytest.raises(ValueError):
        observe.observe(owner=OWNER)
