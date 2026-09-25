from __future__ import annotations

import fcntl
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import backup_coordinator as coordinator
from lowerduckpond_static_host_agent import host_restore_snapshot as selection
from lowerduckpond_static_host_agent import production_capture as capture_module
from lowerduckpond_static_host_agent.backup_descriptor import decode_backup_descriptor
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, RepositoryIdentity
from lowerduckpond_static_host_agent.backup_restic import RepositorySnapshot
from lowerduckpond_static_host_agent.backup_snapshot import STATIC_BACKUP_TAG
from lowerduckpond_static_host_agent.backup_sources import SOURCE_PATHS, STAGED_PATHS
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.host_restore_journal import RestoreStore
from lowerduckpond_static_host_agent.locks import LockName
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401 - shared fixture
from test_backup_capture import Capture
from test_backup_capture import capture as source_capture  # noqa: F401 - shared fixture
from test_backup_capture import fixture as fixture  # noqa: PLC0414
from test_production_backup import Proof
from test_production_backup import capture as capture  # noqa: PLC0414
from test_production_backup import proof as proof  # noqa: PLC0414
from test_production_backup import restic as restic  # noqa: PLC0414


@dataclass
class Network:
    proof: Proof
    source: Capture
    paths: coordinator.CapturePaths
    snapshots: list[RepositorySnapshot] = field(default_factory=list)
    raw: bytes = b""
    writes: int = 0
    fault: str | None = None

    def discover(
        self, environment: Mapping[str, str]
    ) -> tuple[RepositoryIdentity, tuple[RepositorySnapshot, ...]]:
        return self.proof.snapshot.identity, tuple(self.snapshots)

    def create(self, raw: bytes, environment: Mapping[str, str]) -> str:
        self.writes += 1
        assert (self.proof.store / "capture-proposal.json").read_bytes() == raw
        for name in (LockName.PUBLICATION, LockName.TENANT_STATE):
            with (
                (self.source.state.root / "locks" / name.filename).open("rb") as rival,
                pytest.raises(BlockingIOError),
            ):
                fcntl.flock(rival, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if self.fault == "before":
            raise RuntimeError("lost request before snapshot creation")
        descriptor = decode_backup_descriptor(raw)
        self.raw = raw
        self.snapshots.append(
            RepositorySnapshot(
                "d" * 64,
                "source-node",
                (
                    "scheduled",
                    STATIC_BACKUP_TAG,
                    "scope-" + "e" * 64,
                    f"capture-{descriptor['captureId']}",
                    f"lineage-{self.source.state.lineage['lineageId']}",
                    "repository-" + self.proof.authority.repository_binding,
                ),
                (*SOURCE_PATHS.values(), *STAGED_PATHS.values()),
            )
        )
        if self.fault == "after":
            raise RuntimeError("lost response after snapshot creation")
        return "d" * 64

    def run(self) -> str:
        with RestoreStore.locked(self.proof.store, owner=os.geteuid()) as store:
            return capture_module.capture_rollout_backup(
                self.paths,
                {"LOWERDUCKPOND_BACKUP_STATUS_SCOPE": "e" * 64},
                self.proof.authority,
                store,
                content_group=os.getegid(),
            )


@pytest.fixture
def network(proof: Proof, capture: Capture, monkeypatch: pytest.MonkeyPatch) -> Network:
    staging = proof.store.parent / "active-staging"
    staging.mkdir(mode=0o700)
    database = staging / "mariadb.sql.gz"
    database.write_bytes(b"original private SQL dump")
    database.chmod(0o600)
    paths = coordinator.CapturePaths(
        state=capture.state.root,
        content=capture.roots["content"],
        recovery=capture.roots["recovery"],
        staging=staging,
        workspace=capture.workspace,
        caddy=capture.caddy.root,
    )
    result = Network(proof, capture, paths)
    for module in (capture_module, coordinator, selection):
        monkeypatch.setattr(module, "discover_repository", result.discover)
        monkeypatch.setattr(module, "repository_genesis", lambda *args: capture.state.lineage)
    monkeypatch.setattr(capture_module, "create_coherent_snapshot", result.create)

    def read(arguments: tuple[str, ...], environment: Mapping[str, str], limit: int) -> bytes:
        assert arguments == ("dump", "d" * 64, STAGED_PATHS["descriptor"])
        assert len(result.raw) <= limit
        return result.raw

    monkeypatch.setattr(selection, "_restic", read)
    monkeypatch.setattr(
        coordinator,
        "measure_filesystem_capacity_descriptor",
        lambda descriptor: FilesystemCapacity(
            os.fstat(descriptor).st_dev,
            4096,
            8_000_000,
            7_000_000,
            2_000_000,
            1_500_000,
        ),
    )
    return result


@pytest.mark.parametrize("fault", [None, "before", "after"])
def test_original_capture_survives_lost_request_or_response_without_new_identity(
    network: Network,
    fault: str | None,
) -> None:
    network.fault = fault
    if fault is None:
        assert network.run() == "d" * 64
    else:
        with pytest.raises(RuntimeError, match="lost"):
            network.run()
        assert not (network.proof.store / "capture-result.json").exists()
    proposal = network.proof.store / "capture-proposal.json"
    original = (proposal.stat().st_ino, proposal.stat().st_mtime_ns, proposal.read_bytes())
    network.fault = None
    assert network.run() == "d" * 64
    assert network.run() == "d" * 64
    assert network.writes == (2 if fault == "before" else 1)
    assert len(network.snapshots) == 1
    assert (proposal.stat().st_ino, proposal.stat().st_mtime_ns, proposal.read_bytes()) == original
    assert original[2] == network.raw


def test_committed_capture_is_recovered_even_when_the_transient_dump_is_gone(
    network: Network,
) -> None:
    network.fault = "after"
    with pytest.raises(RuntimeError):
        network.run()
    (network.paths.staging / "mariadb.sql.gz").unlink()
    assert network.run() == "d" * 64
    assert network.writes == 1


@pytest.mark.parametrize("fault", ["source", "database"])
def test_missing_remote_capture_cannot_be_recreated_from_changed_live_bytes(
    network: Network, fault: str
) -> None:
    network.fault = "before"
    with pytest.raises(RuntimeError):
        network.run()
    if fault == "source":
        next((network.source.roots["content"] / "sites").rglob("index.html")).write_bytes(
            b"different"
        )
    else:
        (network.paths.staging / "mariadb.sql.gz").write_bytes(b"different")
    network.fault = None
    with pytest.raises((BackupIdentityError, ValueError, RuntimeError)):
        network.run()
    assert network.writes == 1 and not network.snapshots
    assert not (network.proof.store / "capture-result.json").exists()


@pytest.mark.parametrize("fault", ["ambiguous", "readback", "lost-acknowledged"])
def test_remote_ambiguity_or_loss_cannot_create_another_capture(
    network: Network, fault: str
) -> None:
    assert network.run() == "d" * 64
    if fault == "ambiguous":
        network.snapshots.append(replace(network.snapshots[0], snapshot_id="f" * 64))
    elif fault == "readback":
        descriptor = decode_backup_descriptor(network.raw)
        descriptor["capturedAt"] = "2026-09-25T01:00:00Z"
        network.raw = canonical_json_bytes(descriptor)
    else:
        network.snapshots.clear()
    with pytest.raises((BackupIdentityError, ValueError)):
        network.run()
    assert network.writes == 1


def test_failed_proposal_directory_sync_prevents_upload_and_preserves_original_on_retry(
    network: Network,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sync = capture_module._sync

    def interrupted(store: RestoreStore) -> None:
        if (network.proof.store / "capture-proposal.json").exists():
            raise OSError("directory sync failed")
        sync(store)

    monkeypatch.setattr(capture_module, "_sync", interrupted)
    with pytest.raises(OSError, match="directory sync"):
        network.run()
    proposal = (network.proof.store / "capture-proposal.json").read_bytes()
    assert network.writes == 0
    monkeypatch.setattr(capture_module, "_sync", sync)
    assert network.run() == "d" * 64
    assert network.writes == 1
    assert (network.proof.store / "capture-proposal.json").read_bytes() == proposal


def test_changed_original_binding_refuses_before_remote_capture(network: Network) -> None:
    network.proof.authority = replace(network.proof.authority, repository_binding="f" * 64)
    with pytest.raises(BackupIdentityError, match="repository"):
        network.run()
    assert network.writes == 0
    assert not (network.proof.store / "capture-proposal.json").exists()


def test_interruption_between_database_binding_and_descriptor_does_not_upload(
    network: Network,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    immutable = RestoreStore.immutable

    def interrupted(store: RestoreStore, name: str, raw: bytes) -> None:
        if name == "capture-proposal.json":
            raise OSError("descriptor publication interrupted")
        immutable(store, name, raw)

    monkeypatch.setattr(RestoreStore, "immutable", interrupted)
    with pytest.raises(OSError, match="descriptor publication"):
        network.run()
    database = network.proof.store / "capture-database.json"
    before = (database.stat().st_ino, database.stat().st_mtime_ns, database.read_bytes())
    assert not (network.proof.store / "capture-proposal.json").exists()
    assert network.writes == 0
    monkeypatch.setattr(RestoreStore, "immutable", immutable)
    assert network.run() == "d" * 64
    assert (database.stat().st_ino, database.stat().st_mtime_ns, database.read_bytes()) == before
    assert network.writes == 1
