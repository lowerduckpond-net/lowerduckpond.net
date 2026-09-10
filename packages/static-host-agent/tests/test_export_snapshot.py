from __future__ import annotations

import os
import stat
from collections.abc import Callable
from copy import deepcopy
from multiprocessing import get_context
from pathlib import Path
from threading import Event, Thread

import pytest
from lowerduckpond_static_contracts import (
    Digest,
    canonical_json_bytes,
    decode_contract,
    deployment_record_digest,
    manifest_digest,
)
from lowerduckpond_static_host_agent.capacity import CapacityReservation, FilesystemCapacity
from lowerduckpond_static_host_agent.export_snapshot import (
    ExportCaptureBoundary,
    ExportSnapshot,
    capture_export_snapshot,
)
from lowerduckpond_static_host_agent.export_spool import (
    ExportSpool,
    ExportSpoolError,
    ExportSpoolLimits,
    ExportSpoolOccupiedError,
)
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName, StateBusyError
from lowerduckpond_static_host_agent.release_tree import (
    measure_release_tree,
    measure_release_tree_snapshot,
)
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository

_OWNER = os.geteuid()
_TENANT = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
_DEPLOYMENT = "0191e2ca-49f2-7608-8cf3-f80ab2cab151"
_JOB = "0198d17f-6f4a-7000-8000-000000000002"
_FIXTURES = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_READ_ONLY_FILE = 0o444
_READ_ONLY_DIRECTORY = 0o555
_KILLED_STATUS = 23


def _mkdir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


@pytest.fixture(autouse=True)
def _filesystem(monkeypatch: pytest.MonkeyPatch) -> None:
    def measure(descriptor: int) -> FilesystemCapacity:
        return FilesystemCapacity(
            os.fstat(descriptor).st_dev, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000
        )

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.export_spool.measure_filesystem_capacity_descriptor",
        measure,
    )


def _fixture(
    tmp_path: Path, state: str = "active"
) -> tuple[Path, Path, dict[str, object], dict[str, object]]:
    root = tmp_path / "state"
    for name in (
        "",
        "exports",
        "locks",
        "tenants",
        f"tenants/{_TENANT}",
        f"tenants/{_TENANT}/deployments",
    ):
        _mkdir(root / name)
    with LockManager.initialize(root / "locks", expected_owner=_OWNER):
        pass
    release_root = tmp_path / "sites"
    release = release_root / _TENANT / "releases" / _DEPLOYMENT
    for path in (
        release_root,
        release_root / _TENANT,
        release.parent,
        release,
        release / "empty",
        release / "assets",
    ):
        _mkdir(path, 0o755)
    (release / "index.html").write_bytes(b"source home\n")
    (release / "assets" / "site.css").write_bytes(b"body {}\n")
    for path in (release / "index.html", release / "assets" / "site.css"):
        path.chmod(0o644)
    manifest = decode_contract((_FIXTURES / "site.json").read_bytes())
    spec = manifest["spec"]
    assert isinstance(spec, dict)
    spec["desiredState"] = state
    deployment = decode_contract((_FIXTURES / "deployment-record.json").read_bytes())
    with (
        LockManager(root / "locks", expected_owner=_OWNER) as locks,
        locks.acquire(LockName.PUBLICATION),
    ):
        deployment["releaseTreeDigest"] = measure_release_tree(
            release, lock_manager=locks, expected_owner=_OWNER
        ).digest.to_dict()
    with StateRepository(root, expected_owner=_OWNER) as repository:
        repository.create_immutable(StateRecordPath.tenant_desired(_TENANT), manifest)
        repository.create_immutable(
            StateRecordPath.tenant_deployment(_TENANT, _DEPLOYMENT), deployment
        )
    return root, release_root, manifest, deployment


def _capture(  # noqa: PLR0913,PLR0917 - explicit capture fixture inputs
    spool: ExportSpool,
    repository: StateRepository,
    release_root: Path,
    manifest: dict[str, object],
    deployment: dict[str, object],
    hook: Callable[[ExportCaptureBoundary], None] | None = None,
) -> ExportSnapshot:
    with repository.transaction(mode=LockMode.SHARED) as transaction:
        return capture_export_snapshot(
            spool,
            transaction,
            release_root=release_root,
            tenant_id=_TENANT,
            expected_manifest_digest=manifest_digest(manifest),
            expected_deployment_digest=deployment_record_digest(deployment),
            expected_owner=_OWNER,
            hook=hook,
        )


@pytest.mark.parametrize("state", ["active", "suspended"])
def test_capture_is_sealed_independent_and_leaves_authority_unchanged(
    tmp_path: Path, state: str
) -> None:
    root, releases, manifest, deployment = _fixture(tmp_path, state)
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        spool.construction(),
    ):
        snapshot = _capture(spool, repository, releases, manifest, deployment)
        original = releases / _TENANT / "releases" / _DEPLOYMENT / "index.html"
        copied = snapshot.content / "index.html"
        assert original.stat().st_ino != copied.stat().st_ino
        assert copied.stat().st_nlink == 1
        assert stat.S_IMODE(copied.stat().st_mode) == _READ_ONLY_FILE
        assert stat.S_IMODE(snapshot.content.stat().st_mode) == _READ_ONLY_DIRECTORY
        assert (snapshot.content / "empty").is_dir()
        assert (spool.workspace / "manifest.json").read_bytes() == canonical_json_bytes(manifest)
        original.unlink()
        assert copied.read_bytes() == b"source home\n"
        assert (
            measure_release_tree_snapshot(
                snapshot.content, lock_manager=spool.locks, expected_owner=_OWNER, read_only=True
            )
            == snapshot.measurement
        )
        assert repository.read(StateRecordPath.tenant_desired(_TENANT)).document == manifest
    assert list((root / "exports").iterdir()) == []


@pytest.mark.parametrize("boundary", list(ExportCaptureBoundary))
def test_every_capture_interruption_cleans_only_private_work(
    tmp_path: Path, boundary: ExportCaptureBoundary
) -> None:
    root, releases, manifest, deployment = _fixture(tmp_path)

    def interrupt(current: ExportCaptureBoundary) -> None:
        if current == boundary:
            raise RuntimeError("simulated crash")

    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        with pytest.raises(RuntimeError, match="simulated crash"), spool.construction():
            _capture(spool, repository, releases, manifest, deployment, interrupt)
        assert list((root / "exports").iterdir()) == []
        assert repository.read(StateRecordPath.tenant_desired(_TENANT)).document == manifest
        with spool.construction():
            _capture(spool, repository, releases, manifest, deployment)


def test_shared_capture_excludes_mutation_and_cleanup_until_verified(tmp_path: Path) -> None:
    root, releases, manifest, deployment = _fixture(tmp_path)
    entered = Event()
    finished = Event()
    outcomes: list[str] = []

    def competitor() -> None:
        assert entered.wait(10)
        with LockManager(root / "locks", expected_owner=_OWNER) as locks:
            with (
                locks.acquire(LockName.PUBLICATION),
                pytest.raises(StateBusyError),
                locks.acquire(LockName.TENANT_STATE),
            ):
                pass
            with locks.acquire(LockName.TENANT_STATE, mode=LockMode.SHARED):
                outcomes.append("backup shared lock succeeds")
        finished.set()

    thread = Thread(target=competitor)
    thread.start()

    def hook(boundary: ExportCaptureBoundary) -> None:
        if boundary == ExportCaptureBoundary.SNAPSHOT_VERIFIED:
            entered.set()
            assert finished.wait(10)

    try:
        with (
            StateRepository(root, expected_owner=_OWNER) as repository,
            ExportSpool(root, expected_owner=_OWNER) as spool,
            spool.construction(),
        ):
            _capture(spool, repository, releases, manifest, deployment, hook)
            with repository.publication_transaction():
                pass
    finally:
        thread.join(10)
    assert outcomes == ["backup shared lock succeeds"]


@pytest.mark.parametrize("boundary", list(ExportCaptureBoundary))
def test_real_capture_death_recovers_private_work_without_changing_source(
    tmp_path: Path, boundary: ExportCaptureBoundary
) -> None:
    root, releases, manifest, deployment = _fixture(tmp_path)

    def killed_capture() -> None:
        def interrupt(current: ExportCaptureBoundary) -> None:
            if current == boundary:
                os._exit(_KILLED_STATUS)

        with (
            StateRepository(root, expected_owner=_OWNER) as repository,
            ExportSpool(root, expected_owner=_OWNER) as spool,
            spool.construction(),
        ):
            _capture(spool, repository, releases, manifest, deployment, interrupt)

    process = get_context("fork").Process(target=killed_capture)
    process.start()
    process.join(20)
    try:
        assert process.exitcode == _KILLED_STATUS
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        process.close()
    assert (root / "exports/.work").is_dir()
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        spool.construction(),
    ):
        assert list(spool.workspace.iterdir()) == []
        snapshot = _capture(spool, repository, releases, manifest, deployment)
        assert snapshot.manifest == manifest
        assert snapshot.deployment == deployment
        assert (snapshot.content / "index.html").read_bytes() == b"source home\n"
    assert list((root / "exports").iterdir()) == []


@pytest.mark.parametrize("drift", ["manifest", "deployment", "content"])
def test_capture_rejects_authority_drift(tmp_path: Path, drift: str) -> None:
    root, releases, manifest, deployment = _fixture(tmp_path)
    if drift == "manifest":
        manifest = deepcopy(manifest)
        metadata = manifest["metadata"]
        assert isinstance(metadata, dict)
        metadata["slug"] = "other-slug"
    elif drift == "deployment":
        deployment["releaseTreeDigest"] = Digest(
            "lowerduckpond-release-tree-v1", "sha256", "0" * 64
        ).to_dict()
    else:
        (releases / _TENANT / "releases" / _DEPLOYMENT / "index.html").write_bytes(b"drift")
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        pytest.raises(ExportSpoolError),
        spool.construction(),
    ):
        _capture(spool, repository, releases, manifest, deployment)
    assert list((root / "exports").iterdir()) == []


def test_spool_counts_actual_blocks_and_retains_completed_result(tmp_path: Path) -> None:
    root, _, _, _ = _fixture(tmp_path)
    completed = root / "exports" / f"{_JOB}.zip"
    completed.write_bytes(b"x" * 8192)
    completed.chmod(0o600)
    with ExportSpool(root, expected_owner=_OWNER) as spool:
        with spool.locks.acquire(LockName.EXPORT):
            usage = spool.measure()
            assert (
                usage.allocated_bytes
                == (completed.stat().st_blocks + completed.parent.stat().st_blocks) * 512
            )
            assert usage.unique_inodes == 2  # noqa: PLR2004
        with pytest.raises(ExportSpoolOccupiedError), spool.construction():
            pass
        assert not spool.reconcile_incomplete()
    assert completed.exists()


@pytest.mark.parametrize(
    "limits", [ExportSpoolLimits(maximum_allocated_bytes=4095), ExportSpoolLimits(maximum_inodes=1)]
)
def test_spool_limits_reject_before_workspace_allocation(
    tmp_path: Path, limits: ExportSpoolLimits
) -> None:
    root, _, _, _ = _fixture(tmp_path)
    with (
        ExportSpool(root, expected_owner=_OWNER, limits=limits) as spool,
        pytest.raises(ExportSpoolError),
        spool.construction(),
    ):
        pass
    assert list((root / "exports").iterdir()) == []


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "fifo", "unknown", "two-results"])
def test_spool_rejects_unsafe_existing_state_without_removing_it(
    tmp_path: Path, unsafe: str
) -> None:
    root, _, _, _ = _fixture(tmp_path)
    target = root / "exports" / f"{_JOB}.zip"
    if unsafe == "symlink":
        target.symlink_to(root / "tenants")
    elif unsafe == "fifo":
        os.mkfifo(target, mode=0o600)
    elif unsafe == "unknown":
        (target.parent / "unknown").touch(mode=0o600)
    else:
        target.touch(mode=0o600)
        if unsafe == "hardlink":
            os.link(target, tmp_path / "outside")
        else:
            (target.parent / f"{_DEPLOYMENT}.zip").touch(mode=0o600)
    with (
        ExportSpool(root, expected_owner=_OWNER) as spool,
        pytest.raises(ExportSpoolError),
        spool.construction(),
    ):
        pass
    assert list(target.parent.iterdir())


def test_startup_removes_partially_sealed_work_and_keeps_completed_result(tmp_path: Path) -> None:
    root, _, _, _ = _fixture(tmp_path)
    work = root / "exports" / ".work"
    _mkdir(work)
    _mkdir(work / "content", 0o555)
    (work / "manifest.json").write_bytes(b"partial")
    (work / "manifest.json").chmod(0o400)
    completed = root / "exports" / f"{_JOB}.zip"
    completed.touch(mode=0o600)
    with ExportSpool(root, expected_owner=_OWNER) as spool:
        assert spool.reconcile_incomplete()
        assert not spool.reconcile_incomplete()
        with spool.locks.acquire(LockName.EXPORT):
            spool.reserve(CapacityReservation(0, 0))
    assert list(completed.parent.iterdir()) == [completed]


def test_host_reserve_failure_leaves_no_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, _, _ = _fixture(tmp_path)

    def exhausted(descriptor: int) -> FilesystemCapacity:
        return FilesystemCapacity(os.fstat(descriptor).st_dev, 4096, 8_000_000, 1, 4_000_000, 1)

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.export_spool.measure_filesystem_capacity_descriptor",
        exhausted,
    )
    from lowerduckpond_static_host_agent.capacity import CapacityRejectedError  # noqa: PLC0415

    with (
        ExportSpool(root, expected_owner=_OWNER) as spool,
        pytest.raises(CapacityRejectedError),
        spool.construction(),
    ):
        pass
    assert list((root / "exports").iterdir()) == []


def test_sealed_snapshot_does_not_weaken_published_release_permissions(tmp_path: Path) -> None:
    from lowerduckpond_static_host_agent.release_tree import ReleaseTreeError  # noqa: PLC0415

    root, releases, manifest, deployment = _fixture(tmp_path)
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        spool.construction(),
    ):
        snapshot = _capture(spool, repository, releases, manifest, deployment)
        with (
            LockManager(root / "locks", expected_owner=_OWNER) as locks,
            locks.acquire(LockName.PUBLICATION),
            pytest.raises(ReleaseTreeError, match="mode"),
        ):
            measure_release_tree(snapshot.content, lock_manager=locks, expected_owner=_OWNER)


def test_copy_accounting_tracks_blocks_and_parent_growth_and_expires_with_lease(
    tmp_path: Path,
) -> None:
    root, _, _, _ = _fixture(tmp_path)
    with ExportSpool(root, expected_owner=_OWNER) as spool, spool.construction():
        with spool.accounting() as account:
            target = spool.workspace / "partial"
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            parent = os.open(spool.workspace, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.write(descriptor, b"x" * 8192)
                os.fsync(descriptor)
                account.record(parent)
                account.record(descriptor)
                usage = spool.measure()
                # The exact remainder is admitted; a detection byte is refused.
                remaining_bytes = 256 * 1024 * 1024 - usage.allocated_bytes
                account.reserve(CapacityReservation(remaining_bytes, 0))
                with pytest.raises(ExportSpoolError):
                    account.reserve(CapacityReservation(remaining_bytes + 1, 0))
                remaining_inodes = 5120 - usage.unique_inodes
                account.reserve(CapacityReservation(0, remaining_inodes))
                with pytest.raises(ExportSpoolError):
                    account.reserve(CapacityReservation(0, remaining_inodes + 1))
            finally:
                os.close(parent)
                os.close(descriptor)
        with pytest.raises(RuntimeError, match="closed"):
            account.reserve(CapacityReservation(0, 0))


@pytest.mark.parametrize("state", ["active", "suspended"])
def test_sealed_captures_build_byte_identical_portable_bundles(tmp_path: Path, state: str) -> None:
    from lowerduckpond_static_host_agent.portable_bundle import (  # noqa: PLC0415
        build_portable_bundle,
        inspect_portable_bundle,
    )

    root, releases, manifest, deployment = _fixture(tmp_path, state)
    payloads: list[bytes] = []
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        for _attempt in range(2):
            with spool.construction():
                snapshot = _capture(spool, repository, releases, manifest, deployment)
                bundle = build_portable_bundle(
                    snapshot.content,
                    snapshot.manifest,
                    output_parent=spool.workspace,
                    output_name="bundle.zip",
                    lock_manager=spool.locks,
                    expected_owner=_OWNER,
                    read_only_snapshot=True,
                )
                output = spool.workspace / bundle.output_name
                inspection = inspect_portable_bundle(output, expected_owner=_OWNER)
                assert inspection.provenance_manifest == manifest
                assert inspection.release_tree_digest == snapshot.measurement.digest
                payloads.append(output.read_bytes())
    assert payloads[0] == payloads[1]


@pytest.mark.parametrize("outside_link", [False, True])
def test_recovery_distinguishes_internal_builder_links_from_external_links(
    tmp_path: Path,
    outside_link: bool,
) -> None:
    root, _, _, _ = _fixture(tmp_path)
    work = root / "exports" / ".work"
    _mkdir(work)
    temporary = work / f".m3-portable-{'a' * 32}.partial"
    temporary.write_bytes(b"interrupted builder output")
    temporary.chmod(0o600)
    os.link(temporary, work / "bundle.zip")
    if outside_link:
        os.link(temporary, tmp_path / "outside")
    with ExportSpool(root, expected_owner=_OWNER) as spool:
        if outside_link:
            with pytest.raises(ExportSpoolError):
                spool.reconcile_incomplete()
            assert (tmp_path / "outside").read_bytes() == b"interrupted builder output"
        else:
            with spool.locks.acquire(LockName.EXPORT):
                usage = spool.measure()
                assert usage.unique_inodes == 3  # noqa: PLR2004 - root, workspace, one output inode
            assert spool.reconcile_incomplete()
            assert not work.exists()
