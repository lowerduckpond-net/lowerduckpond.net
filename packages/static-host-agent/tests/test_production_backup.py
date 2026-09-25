from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import host_restore_materialize as materialize
from lowerduckpond_static_host_agent import production_backup as backup
from lowerduckpond_static_host_agent.audit_archive_store import head_for_indexes
from lowerduckpond_static_host_agent.backup_sources import SOURCE_PATHS, STAGED_PATHS
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError, RestoreStore
from lowerduckpond_static_host_agent.host_restore_snapshot import RestoreSnapshot
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401 - shared pytest fixture
from test_backup_capture import Capture
from test_backup_capture import capture as source_capture  # noqa: F401 - shared pytest fixture
from test_backup_capture import fixture as fixture  # noqa: PLC0414 - shared pytest fixture
from test_host_restore_snapshot import restic as restic  # noqa: PLC0414 - bounded Restic inventory


@pytest.fixture
def capture(source_capture: Capture) -> Capture:  # noqa: F811 - imported pytest fixture
    archive = source_capture.state.root / "audit/archive"
    archive.mkdir(mode=0o700)
    head = archive / "head.json"
    head.write_bytes(canonical_json_bytes(head_for_indexes(source_capture.state.lineage, ())))
    head.chmod(0o600)
    return source_capture


@dataclass
class Proof:
    store: Path
    paths: materialize.MaterializationPaths
    authority: backup.BackupAuthority
    snapshot: RestoreSnapshot
    calls: list[str]
    restore: Callable[..., bytes]

    def verify(self) -> dict[str, str]:
        return backup.verify_backup(
            self.snapshot.snapshot.snapshot_id,
            {},
            self.authority,
            self.store,
            self.paths,
            owner=os.geteuid(),
            content_group=os.getegid(),
        )


@pytest.fixture
def proof(
    capture: Capture,
    restic: tuple[RestoreSnapshot, dict[str, dict[str, object]]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Proof:
    snapshot, _ = restic
    store, private, workspace = (tmp_path / name for name in ("proof", "private", "scratch"))
    for path in (store, private, workspace):
        path.mkdir(mode=0o700)
    paths = materialize.MaterializationPaths(
        {label: private / label for label in SOURCE_PATHS}, private / "staging", workspace
    )
    monkeypatch.setattr(
        materialize,
        "measure_filesystem_capacity",
        lambda path: FilesystemCapacity(
            path.stat().st_dev, 4096, 8_000_000, 7_000_000, 2_000_000, 1_500_000
        ),
    )
    calls: list[str] = []

    def restore(arguments: tuple[str, ...], *args: object, **kwargs: object) -> bytes:
        assert arguments[:2] == ("--no-cache", "restore")
        assert arguments[3] == "--target" and arguments[5:] == ("--verify", "--quiet")
        source = arguments[2].removeprefix(snapshot.snapshot.snapshot_id + ":")
        target = Path(arguments[4])
        calls.append(source)
        if source in SOURCE_PATHS.values():
            label = next(label for label, path in SOURCE_PATHS.items() if path == source)
            shutil.copytree(
                capture.roots[label],
                target,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("intake", "exports", ".staging"),
            )
        else:
            assert source == str(Path(STAGED_PATHS["database"]).parent)
            for label, value in (("database", b"dump"), ("descriptor", snapshot.descriptor)):
                path = target / Path(STAGED_PATHS[label]).name
                path.write_bytes(value)
                path.chmod(0o600)
        return b""

    monkeypatch.setattr(materialize, "_run_restic", restore)
    authority = backup.BackupAuthority(
        original_sha256="1" * 64,
        phase_sha256="2" * 64,
        report_sha256="3" * 64,
        artifact_sha256="b" * 64,
        repository_binding=snapshot.identity.binding()["value"],
        lineage_sha256=hashlib.sha256(canonical_json_bytes(snapshot.lineage)).hexdigest(),
        namespace=json.loads((capture.state.root / "platform/namespace.json").read_bytes()),
        launch=None,
    )
    return Proof(store, paths, authority, snapshot, calls, restore)


def test_matching_backup_remeasures_actual_restored_authority_without_host_recovery(
    proof: Proof,
    capture: Capture,
) -> None:
    original = capture.descriptor()
    result = proof.verify()
    assert result == {
        "snapshot_id": proof.snapshot.snapshot.snapshot_id,
        "descriptor_sha256": hashlib.sha256(proof.snapshot.descriptor).hexdigest(),
        "index_sha256": hashlib.sha256(
            (capture.state.root / "audit/archive/head.json").read_bytes()
        ).hexdigest(),
        "restored_tree_sha256": hashlib.sha256(
            (proof.store / "backup-restored-authority.json").read_bytes()
        ).hexdigest(),
        "report_sha256": proof.authority.report_sha256,
    }
    assert capture.descriptor() == original
    assert json.loads((proof.store / "backup-verified.json").read_bytes()) == result
    with RestoreStore.locked(proof.store, owner=os.geteuid()) as store:
        assert store.read() is None
    assert not (proof.store / "journal.json").exists()
    before = {
        path: (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
        for path in proof.store.glob("*.json")
    }
    assert proof.verify() == result
    assert before == {
        path: (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes()) for path in before
    }


@pytest.mark.parametrize("field", ["artifact_sha256", "repository_binding", "lineage_sha256"])
def test_unbound_backup_fails_before_any_restore_allocation(proof: Proof, field: str) -> None:
    proof.authority = {
        "artifact_sha256": replace(proof.authority, artifact_sha256="f" * 64),
        "repository_binding": replace(proof.authority, repository_binding="f" * 64),
        "lineage_sha256": replace(proof.authority, lineage_sha256="f" * 64),
    }[field]
    with pytest.raises(HostRestoreError):
        proof.verify()
    assert not proof.calls
    assert not any(path.exists() for path in proof.paths.targets().values())
    assert not (proof.store / "backup-verified.json").exists()


@pytest.mark.parametrize("field", ["original_sha256", "phase_sha256", "report_sha256"])
def test_resume_cannot_rebind_original_rollout_or_report(proof: Proof, field: str) -> None:
    proof.verify()
    before = (proof.store / "backup-inputs.json").read_bytes()
    count = len(proof.calls)
    proof.authority = {
        "original_sha256": replace(proof.authority, original_sha256="f" * 64),
        "phase_sha256": replace(proof.authority, phase_sha256="f" * 64),
        "report_sha256": replace(proof.authority, report_sha256="f" * 64),
    }[field]
    with pytest.raises(HostRestoreError, match="immutable evidence conflicts"):
        proof.verify()
    assert len(proof.calls) == count
    assert (proof.store / "backup-inputs.json").read_bytes() == before


def test_interrupted_restore_retains_exact_snapshot_and_inodes_for_resume(
    proof: Proof,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def interrupted(*args: object, **kwargs: object) -> bytes:
        proof.restore(*args, **kwargs)
        raise RuntimeError("lost restore after writing original tree")

    monkeypatch.setattr(materialize, "_run_restic", interrupted)
    with pytest.raises(RuntimeError, match="lost restore"):
        proof.verify()
    inodes = {path: path.stat().st_ino for path in proof.paths.targets().values()}
    assert not (proof.store / "backup-verified.json").exists()
    monkeypatch.setattr(materialize, "_run_restic", proof.restore)
    result = proof.verify()
    assert result["snapshot_id"] == proof.snapshot.snapshot.snapshot_id
    assert inodes == {path: path.stat().st_ino for path in inodes}


@pytest.mark.parametrize("fault", ["release", "namespace", "index", "descriptor"])
def test_restic_success_does_not_hide_corrupted_restored_bytes(
    proof: Proof,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    def corrupt(arguments: tuple[str, ...], *args: object, **kwargs: object) -> bytes:
        result = proof.restore(arguments, *args, **kwargs)
        target = Path(arguments[4])
        if fault == "release" and target == proof.paths.roots["content"]:
            next((target / "sites").rglob("index.html")).write_bytes(b"changed")
        elif fault in {"namespace", "index"} and target == proof.paths.roots["state"]:
            relative = (
                "platform/namespace.json" if fault == "namespace" else "audit/archive/head.json"
            )
            (target / relative).write_bytes(b"{}\n")
        elif fault == "descriptor" and target == proof.paths.staging:
            (target / "static-recovery.json").write_bytes(b"{}\n")
        return result

    monkeypatch.setattr(materialize, "_run_restic", corrupt)
    with pytest.raises((HostRestoreError, ValueError, RuntimeError)):
        proof.verify()
    assert not (proof.store / "backup-verified.json").exists()


def test_snapshot_switch_and_replaced_private_tree_refuse_reuse(proof: Proof) -> None:
    proof.verify()
    changed = replace(proof.snapshot.snapshot, snapshot_id="e" * 64)
    original = proof.snapshot
    proof.snapshot = replace(original, snapshot=changed)
    with pytest.raises(HostRestoreError, match="immutable evidence conflicts"):
        proof.verify()
    proof.snapshot = original
    target = proof.paths.roots["state"]
    target.rename(target.with_name("retained-original"))
    target.mkdir(mode=0o700)
    with pytest.raises(HostRestoreError, match="identity changed"):
        proof.verify()
    assert (target.with_name("retained-original") / "platform/namespace.json").is_file()


@pytest.mark.parametrize(
    "target",
    [
        *SOURCE_PATHS.values(),
        "/var/lib",
        "/srv/lowerduckpond/private",
        "/var/cache/lowerduckpond-backup/staging",
    ],
)
@pytest.mark.parametrize("purpose", ["evidence", "state", "workspace"])
def test_production_backup_proof_cannot_target_live_sources(
    proof: Proof,
    target: str,
    purpose: str,
) -> None:
    if purpose == "evidence":
        proof.store = Path(target)
    elif purpose == "state":
        proof.paths = replace(proof.paths, roots={**proof.paths.roots, "state": Path(target)})
    else:
        proof.paths = replace(proof.paths, workspace=Path(target))
    with pytest.raises(HostRestoreError, match="private inert destinations"):
        proof.verify()
    assert not proof.calls


def test_private_destination_alias_is_rejected_before_restore(proof: Proof) -> None:
    target = proof.paths.roots["state"]
    target.symlink_to(proof.paths.workspace, target_is_directory=True)
    with pytest.raises(HostRestoreError, match="private inert destinations"):
        proof.verify()
    assert not proof.calls
