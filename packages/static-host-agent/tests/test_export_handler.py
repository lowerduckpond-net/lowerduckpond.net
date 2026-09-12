from __future__ import annotations

import io
import os
import shutil
import time
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import partial
from multiprocessing import get_context
from multiprocessing.connection import Connection
from multiprocessing.process import BaseProcess
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import lowerduckpond_static_host_agent.job_runtime as runtime
import pytest
from lowerduckpond_static_contracts import (
    ExportAcknowledgement,
    canonical_json_bytes,
    decode_contract,
    manifest_digest,
)
from lowerduckpond_static_host_agent import entrypoints
from lowerduckpond_static_host_agent.archive_bundle import RemoteArchiveBundleSource
from lowerduckpond_static_host_agent.archive_remote import (
    ArchiveClient,
    ArchiveRemoteError,
    ArchiveRemoteStore,
)
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.execution import (
    AuthorizationExecutor,
    ExecutionError,
    ExecutionOutcome,
)
from lowerduckpond_static_host_agent.export_delivery import (
    ExportDelivery,
    ExportDeliveryBoundary,
    ExportDeliveryError,
)
from lowerduckpond_static_host_agent.export_handler import (
    ExportCommitBoundary,
    ExportLifecycleHandler,
)
from lowerduckpond_static_host_agent.export_spool import (
    DEFAULT_EXPORT_SPOOL_LIMITS,
    ExportSpool,
    ExportSpoolLimits,
)
from lowerduckpond_static_host_agent.intake import ArtifactIntake
from lowerduckpond_static_host_agent.issuance import AuthorizationIssuer, IssuedAuthorization
from lowerduckpond_static_host_agent.job_runtime import (
    DeadlineWriter,
    OperatorSession,
    ResultWaiter,
    RuntimeBoundaryError,
)
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName, StateBusyError
from lowerduckpond_static_host_agent.portable_bundle import (
    build_portable_bundle,
    inspect_portable_bundle,
)
from lowerduckpond_static_host_agent.release_tree import measure_release_tree
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    TenantRouteSnapshot,
    snapshot_tenant_routes,
)
from lowerduckpond_static_host_agent.state_inventory import (
    StateAdmissionRejectedError,
    StateInventoryLimits,
    StateInventoryProjection,
    StateInventoryReservation,
)

_OWNER = os.geteuid()
_KILLED_STATUS = 23
_TENANT = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
_DEPLOYMENT = "0191e2ca-49f2-7608-8cf3-f80ab2cab151"
_CORRELATION = "0198d17f-6f4a-7000-8000-000000000003"
_GENERATION = "0198d17f-6f4a-7000-8000-000000000006"
_NOW = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
_FIXTURES = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"


class _OpenGate:
    def require_enabled(self) -> None:
        pass


def _fixture(name: str) -> dict[str, object]:
    return decode_contract((_FIXTURES / name).read_bytes())


def _mkdir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


def _write(root: Path, path: StateRecordPath, document: dict[str, object]) -> None:
    target = root.joinpath(*path.components)
    target.write_bytes(canonical_json_bytes(document))
    target.chmod(0o600)


@pytest.fixture(autouse=True)
def _filesystem(monkeypatch: pytest.MonkeyPatch) -> None:
    def capacity(descriptor: int) -> FilesystemCapacity:
        return FilesystemCapacity(
            os.fstat(descriptor).st_dev, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000
        )

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.export_spool.measure_filesystem_capacity_descriptor",
        capacity,
    )
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
        lambda _self: FilesystemCapacity(1, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000),
    )
    for module in ("correlations", "execution", "intake"):
        monkeypatch.setattr(
            f"lowerduckpond_static_host_agent.{module}.admit_release_capacity",
            lambda *_args, **_kwargs: None,
        )


def _source(tmp_path: Path, state: str = "active") -> tuple[Path, Path, dict[str, object]]:
    root = tmp_path / "state"
    for name in (
        "",
        "platform",
        "exports",
        "intents",
        "audit",
        "locks",
        "intake",
        "authorization",
        "authorization/jobs",
        "authorization/results",
        "authorization/correlations",
        "tenants",
        f"tenants/{_TENANT}",
        f"tenants/{_TENANT}/deployments",
        f"tenants/{_TENANT}/archives",
    ):
        _mkdir(root / name)
    with LockManager.initialize(root / "locks", expected_owner=_OWNER):
        pass
    releases = tmp_path / "sites"
    release = releases / _TENANT / "releases" / _DEPLOYMENT
    for path in (releases, releases / _TENANT, release.parent, release, release / "empty"):
        _mkdir(path, 0o755)
    (release / "index.html").write_bytes(b"export content\n")
    (release / "index.html").chmod(0o644)
    manifest = _fixture("site.json")
    spec = manifest["spec"]
    assert isinstance(spec, dict)
    spec["desiredState"] = state
    deployment = _fixture("deployment-record.json")
    with (
        LockManager(root / "locks", expected_owner=_OWNER) as locks,
        locks.acquire(LockName.PUBLICATION),
    ):
        deployment["releaseTreeDigest"] = measure_release_tree(
            release, lock_manager=locks, expected_owner=_OWNER
        ).digest.to_dict()
    observed = _fixture("tenant-observed-state.json")
    observed.update(
        desiredManifestDigest=manifest_digest(manifest).to_dict(),
        observedState=state,
        activeDeploymentId=None if state == "archived" else _DEPLOYMENT,
        runtimeGenerationId=_GENERATION if state == "active" else None,
    )
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT), manifest)
    _write(root, StateRecordPath.tenant_observed(_TENANT), observed)
    _write(root, StateRecordPath.tenant_deployment(_TENANT, _DEPLOYMENT), deployment)
    return root, releases, manifest


def _entropy(length: int) -> bytes:
    return os.urandom(length)


def _archived_source(tmp_path: Path) -> tuple[Path, Path, bytes, dict[str, object]]:
    root, releases, manifest = _source(tmp_path, "archived")
    output = tmp_path / "remote-fixture"
    _mkdir(output)
    with ExportSpool(root, expected_owner=_OWNER) as spool, spool.locks.acquire(LockName.EXPORT):
        bundle = build_portable_bundle(
            releases / _TENANT / "releases" / _DEPLOYMENT,
            manifest,
            output_parent=output,
            output_name="remote.zip",
            lock_manager=spool.locks,
            expected_owner=_OWNER,
        )
    record = _fixture("archive-record.json")
    inspection = inspect_portable_bundle(output / "remote.zip", expected_owner=_OWNER)
    record.update(
        manifestDigest=manifest_digest(manifest).to_dict(),
        releaseTreeDigest=inspection.release_tree_digest.to_dict(),
        bundleDigest=bundle.bundle_digest.to_dict(),
        bundleSize=bundle.bundle_size,
    )
    _write(root, StateRecordPath.tenant_archive(_TENANT, _DEPLOYMENT), record)
    return root, releases, (output / "remote.zip").read_bytes(), record


@pytest.mark.parametrize("boundary", [None, *ExportCommitBoundary])
def test_archived_export_delivers_exact_remote_bytes_and_recovers(
    tmp_path: Path, boundary: ExportCommitBoundary | None
) -> None:
    root, releases, body, record = _archived_source(tmp_path)
    calls: list[dict[str, object]] = []
    digest = record["bundleDigest"]
    assert isinstance(digest, dict)

    def get_object(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {
            "Body": io.BytesIO(body),
            "VersionId": record["versionId"],
            "ContentLength": len(body),
            "Metadata": {"sha256": digest["value"]},
        }

    remote = ArchiveRemoteStore(
        cast(ArchiveClient, SimpleNamespace(get_object=get_object)), bucket=str(record["bucket"])
    )
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)

    class Interrupted(BaseException):
        pass

    def interrupt(current: ExportCommitBoundary) -> None:
        if current == boundary:
            raise Interrupted

    if boundary is not None:
        with pytest.raises(Interrupted):
            _execute(root, releases, job_id, hook=interrupt, remote=remote)
    outcome = _execute(root, releases, job_id, remote=remote)
    assert outcome.result["status"] == "succeeded"
    assert (root / "exports" / f"{job_id}.zip").read_bytes() == body
    assert calls
    assert all(
        call == {"Bucket": record["bucket"], "Key": record["key"], "VersionId": record["versionId"]}
        for call in calls
    )
    before_replay = len(calls)
    assert _execute(root, releases, job_id, remote=remote).result == outcome.result
    assert len(calls) == before_replay


def test_archived_export_refuses_wrong_remote_bytes_without_publishing(tmp_path: Path) -> None:
    root, releases, body, record = _archived_source(tmp_path)
    digest = record["bundleDigest"]
    assert isinstance(digest, dict)
    remote = ArchiveRemoteStore(
        cast(
            ArchiveClient,
            SimpleNamespace(
                get_object=lambda **kwargs: {
                    "Body": io.BytesIO(b"x" * len(body)),
                    "VersionId": record["versionId"],
                    "ContentLength": len(body),
                    "Metadata": {"sha256": digest["value"]},
                }
            ),
        ),
        bucket=str(record["bucket"]),
    )
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    with pytest.raises(ArchiveRemoteError):
        _execute(root, releases, job_id, remote=remote)
    assert tuple((root / "exports").iterdir()) == ()
    assert tuple((root / "authorization/results").iterdir()) == ()


def _issue(repository: StateRepository, correlation: str = _CORRELATION) -> str:
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "export",
        "tenantId": _TENANT,
        "correlationId": correlation,
    }
    return (
        AuthorizationIssuer(repository, gate=_OpenGate(), entropy=_entropy)
        .issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        .job_id
    )


def _execute(  # noqa: PLR0913 - explicit export execution dependencies
    root: Path,
    releases: Path,
    job_id: str,
    hook: Callable[[ExportCommitBoundary], None] | None = None,
    *,
    spool_limits: ExportSpoolLimits = DEFAULT_EXPORT_SPOOL_LIMITS,
    runtime_validator: Callable[..., bool] | None = None,
    remote: ArchiveRemoteStore | None = None,
) -> ExecutionOutcome:
    with (
        StateRepository(root, expected_owner=_OWNER, tenant_release_root=releases) as repository,
        ArtifactIntake(root, expected_owner=_OWNER) as intake,
        ExportSpool(root, expected_owner=_OWNER, limits=spool_limits) as spool,
    ):
        handler = ExportLifecycleHandler(
            repository,
            spool,
            _OpenGate(),
            release_root=releases,
            expected_owner=_OWNER,
            now=lambda: _NOW,
            hook=hook,
            archive_source=RemoteArchiveBundleSource(remote) if remote is not None else None,
        )
        return AuthorizationExecutor(
            repository,
            intake,
            handlers={"export": handler},
            tenant_runtime_validator=runtime_validator or (lambda *_args: True),
        ).execute(job_id)


@pytest.mark.parametrize("state", ["active", "suspended"])
def test_executor_exports_without_mutating_source_and_exactly_replays(
    tmp_path: Path, state: str
) -> None:
    root, releases, manifest = _source(tmp_path, state)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
        before = {
            path: canonical_json_bytes(repository.read(path).document)
            for path in (
                StateRecordPath.tenant_desired(_TENANT),
                StateRecordPath.tenant_observed(_TENANT),
                StateRecordPath.tenant_deployment(_TENANT, _DEPLOYMENT),
            )
        }
    outcome = _execute(root, releases, job_id)
    assert outcome.result["status"] == "succeeded"
    bundle = root / "exports" / f"{job_id}.zip"
    original_bytes = bundle.read_bytes()
    inspection = inspect_portable_bundle(bundle, expected_owner=_OWNER)
    assert inspection.provenance_manifest == manifest
    assert inspection.content_paths == ("empty", "index.html")
    retry = _execute(root, releases, job_id)
    assert not retry.created
    assert retry.result == outcome.result
    assert bundle.read_bytes() == original_bytes
    with StateRepository(root, expected_owner=_OWNER) as repository:
        assert {
            path: canonical_json_bytes(repository.read(path).document) for path in before
        } == before
        job = repository.read(StateRecordPath.authorization_job(job_id)).document
        assert job["executionValidated"] is True
        with repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
            assert transaction.measure_intent_records().records == ()
            assert transaction.inspect_audit().entry_count == 1
    assert list(bundle.parent.iterdir()) == [bundle]


@pytest.mark.parametrize("boundary", list(ExportCommitBoundary))
def test_every_export_boundary_recovers_one_result_and_one_audit(
    tmp_path: Path, boundary: ExportCommitBoundary
) -> None:
    root, releases, _manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)

    def interrupt(current: ExportCommitBoundary) -> None:
        if current == boundary:
            raise RuntimeError("simulated interruption")

    with pytest.raises(RuntimeError, match="simulated interruption"):
        _execute(root, releases, job_id, interrupt)
    outcome = _execute(root, releases, job_id)
    assert outcome.result["status"] == "succeeded"
    assert _execute(root, releases, job_id).result == outcome.result
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        repository.transaction(mode=LockMode.EXCLUSIVE) as transaction,
    ):
        assert transaction.inspect_audit().entry_count == 1
        assert transaction.measure_intent_records().records == ()
    assert [path.name for path in (root / "exports").iterdir()] == [f"{job_id}.zip"]


def test_completed_slot_refuses_a_second_export_without_replacing_bytes(tmp_path: Path) -> None:
    root, releases, _manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        first = _issue(repository)
    _execute(root, releases, first)
    bundle = root / "exports" / f"{first}.zip"
    original = bundle.read_bytes()
    with StateRepository(root, expected_owner=_OWNER) as repository:
        second = _issue(repository, "0198d17f-6f4a-7000-8000-000000000004")
    outcome = _execute(root, releases, second)
    assert outcome.result["errorCode"] == "conflict"
    assert bundle.read_bytes() == original


@pytest.mark.parametrize(
    "limits",
    [ExportSpoolLimits(maximum_allocated_bytes=1024 * 1024), ExportSpoolLimits(maximum_inodes=3)],
)
def test_snapshot_capacity_refusal_is_terminal_and_retains_no_export(
    tmp_path: Path, limits: ExportSpoolLimits
) -> None:
    root, releases, manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    outcome = _execute(root, releases, job_id, spool_limits=limits)
    assert outcome.result["status"] == "failed"
    assert outcome.result["errorCode"] == "capacity_exceeded"
    assert list((root / "exports").iterdir()) == []
    with StateRepository(root, expected_owner=_OWNER) as repository:
        assert repository.read(StateRecordPath.tenant_desired(_TENANT)).document == manifest
        with repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
            assert transaction.inspect_audit().entry_count == 1
            assert transaction.measure_intent_records().records == ()


def test_source_change_after_capture_aborts_without_replacing_current_state(tmp_path: Path) -> None:
    root, releases, manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    updated = dict(manifest)
    metadata = updated["metadata"]
    assert isinstance(metadata, dict)
    updated["metadata"] = {**metadata, "slug": "renamed-during-export"}

    def mutate(boundary: ExportCommitBoundary) -> None:
        if boundary == ExportCommitBoundary.BUNDLE_VERIFIED:
            with StateRepository(root, expected_owner=_OWNER) as repository:
                current = repository.read(StateRecordPath.tenant_desired(_TENANT))
                repository.compare_and_swap(
                    StateRecordPath.tenant_desired(_TENANT), current.revision, updated
                )

    outcome = _execute(root, releases, job_id, mutate)
    assert outcome.result["errorCode"] == "state_drift"
    assert list((root / "exports").iterdir()) == []
    with StateRepository(root, expected_owner=_OWNER) as repository:
        assert repository.read(StateRecordPath.tenant_desired(_TENANT)).document == updated


def _killed_export(root: Path, releases: Path, job_id: str, boundary: ExportCommitBoundary) -> None:
    def kill(current: ExportCommitBoundary) -> None:
        if current == boundary:
            os._exit(_KILLED_STATUS)

    _execute(root, releases, job_id, kill)


@pytest.mark.parametrize("boundary", list(ExportCommitBoundary))
def test_process_death_without_finally_recovers_export(
    tmp_path: Path, boundary: ExportCommitBoundary
) -> None:
    root, releases, _manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    process = get_context("fork").Process(
        target=_killed_export, args=(root, releases, job_id, boundary)
    )
    process.start()
    try:
        process.join(20)
        assert not process.is_alive()
        assert process.exitcode == _KILLED_STATUS
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        process.close()
    outcome = _execute(root, releases, job_id)
    assert outcome.result["status"] == "succeeded"
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        repository.transaction(mode=LockMode.EXCLUSIVE) as transaction,
    ):
        assert transaction.inspect_audit().entry_count == 1
        assert transaction.measure_intent_records().records == ()
    assert [path.name for path in (root / "exports").iterdir()] == [f"{job_id}.zip"]


def _assert_terminal_rejection(
    root: Path, releases: Path, job_id: str, manifest: dict[str, object], error_code: str
) -> None:
    outcome = _execute(root, releases, job_id)
    assert outcome.result["status"] == "failed"
    assert outcome.result["errorCode"] == error_code
    retry = _execute(root, releases, job_id)
    assert retry.result == outcome.result
    assert not retry.created
    assert list((root / "exports").iterdir()) == []
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        repository.transaction(mode=LockMode.EXCLUSIVE) as transaction,
    ):
        assert transaction.read(StateRecordPath.tenant_desired(_TENANT)).document == manifest
        job = transaction.read(StateRecordPath.authorization_job(job_id)).document
        assert job["phase"] == "failed"
        assert job["executionValidated"] is True
        assert transaction.inspect_audit().entry_count == 1
        assert transaction.measure_intent_records().records == ()


def test_undeployed_export_is_a_terminal_lifecycle_rejection(tmp_path: Path) -> None:
    root, releases, manifest = _source(tmp_path)
    spec = manifest["spec"]
    assert isinstance(spec, dict)
    spec["desiredState"] = "undeployed"
    del spec["desiredDeployment"]
    observed = _fixture("tenant-observed-state.json")
    observed.update(
        desiredManifestDigest=manifest_digest(manifest).to_dict(),
        observedState="undeployed",
        activeDeploymentId=None,
        runtimeGenerationId=None,
    )
    _write(root, StateRecordPath.tenant_desired(_TENANT), manifest)
    _write(root, StateRecordPath.tenant_observed(_TENANT), observed)
    (root / "tenants" / _TENANT / "deployments" / f"{_DEPLOYMENT}.json").unlink()
    shutil.rmtree(releases / _TENANT / "releases" / _DEPLOYMENT)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    _assert_terminal_rejection(root, releases, job_id, manifest, "invalid_request")


@pytest.mark.parametrize("shape", ["missing", "file", "symlink", "wrong-mode", "fifo"])
def test_unavailable_release_is_terminal_drift_and_does_not_loop(
    tmp_path: Path, shape: str
) -> None:
    root, releases, manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    release = releases / _TENANT / "releases" / _DEPLOYMENT
    if shape in {"missing", "file", "symlink"}:
        shutil.rmtree(release)
        if shape == "file":
            release.write_bytes(b"a directory was required")
        elif shape == "symlink":
            release.symlink_to(tmp_path)
    elif shape == "wrong-mode":
        release.chmod(0o777)
    else:
        os.mkfifo(release / "pipe")
    _assert_terminal_rejection(root, releases, job_id, manifest, "state_drift")


def _receipt(result: dict[str, object]) -> ExportAcknowledgement:
    provenance = result["provenance"]
    bundle = result["exportBundle"]
    assert isinstance(provenance, dict) and isinstance(bundle, dict)
    digest = bundle["digest"]
    assert isinstance(digest, dict) and isinstance(bundle["size"], int)
    return ExportAcknowledgement(str(provenance["jobId"]), str(digest["value"]), bundle["size"])


@pytest.mark.parametrize("state", ["active", "suspended"])
def test_acknowledgement_retires_only_download_and_preserves_exact_retry(
    tmp_path: Path, state: str
) -> None:
    root, releases, _manifest = _source(tmp_path, state)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    result = _execute(root, releases, job_id).result
    before = (root / "authorization/results" / f"{job_id}.json").read_bytes()
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        delivery = ExportDelivery(repository, spool, now=lambda: _NOW)
        with delivery.download(job_id, result) as remaining:
            assert remaining == 24 * 60 * 60
        for _attempt in range(2):
            assert (
                delivery.acknowledge(_receipt(result), operator_principal="operator@example.test")
                == result
            )
        with delivery.download(job_id, result) as remaining:
            assert remaining is None
    assert list((root / "exports").iterdir()) == []
    assert (root / "authorization/results" / f"{job_id}.json").read_bytes() == before
    assert _execute(root, releases, job_id).result == result
    with StateRepository(root, expected_owner=_OWNER) as repository:
        second = _issue(repository, "0198d17f-6f4a-7000-8000-000000000004")
    assert _execute(root, releases, second).result["status"] == "succeeded"


@pytest.mark.parametrize("mismatch", ["operator", "digest", "size", "job"])
def test_acknowledgement_rejects_mismatched_authority(tmp_path: Path, mismatch: str) -> None:
    root, releases, _manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    result = _execute(root, releases, job_id).result
    original = _receipt(result)
    receipt = ExportAcknowledgement(
        _CORRELATION if mismatch == "job" else original.job_id,
        "0" * 64 if mismatch == "digest" else original.sha256,
        original.size + 1 if mismatch == "size" else original.size,
    )
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        delivery = ExportDelivery(repository, spool, now=lambda: _NOW)
        with pytest.raises((ExportDeliveryError, FileNotFoundError)):
            delivery.acknowledge(
                receipt,
                operator_principal="intruder@example.test"
                if mismatch == "operator"
                else "operator@example.test",
            )
        assert (
            repository.read(StateRecordPath.authorization_job(job_id)).document["exportDelivery"]
            == "unacknowledged"
        )
    assert (root / "exports" / f"{job_id}.zip").exists()


@pytest.mark.parametrize("boundary", list(ExportDeliveryBoundary))
@pytest.mark.parametrize("reason", ["acknowledged", "expired"])
def test_process_death_during_retirement_recovers_without_changing_result(
    tmp_path: Path, boundary: ExportDeliveryBoundary, reason: str
) -> None:
    root, releases, _manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    result = _execute(root, releases, job_id).result
    now = _NOW + timedelta(hours=24) if reason == "expired" else _NOW

    def killed() -> None:
        def interrupt(selected: ExportDeliveryBoundary) -> None:
            if selected is boundary:
                os._exit(_KILLED_STATUS)

        with (
            StateRepository(root, expected_owner=_OWNER) as repository,
            ExportSpool(root, expected_owner=_OWNER) as spool,
        ):
            delivery = ExportDelivery(repository, spool, now=lambda: now, hook=interrupt)
            if reason == "expired":
                delivery.reconcile()
            else:
                delivery.acknowledge(_receipt(result), operator_principal="operator@example.test")

    child = get_context("fork").Process(target=killed)
    child.start()
    child.join(10)
    assert child.exitcode == _KILLED_STATUS
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        delivery = ExportDelivery(repository, spool, now=lambda: now)
        delivery.reconcile()
        delivery.reconcile()
        assert (
            repository.read(StateRecordPath.authorization_job(job_id)).document["exportDelivery"]
            == reason
        )
    assert list((root / "exports").iterdir()) == []
    assert _execute(root, releases, job_id).result == result


def test_expiry_is_fixed_and_download_excludes_removal(tmp_path: Path) -> None:
    root, releases, _manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    result = _execute(root, releases, job_id).result
    now = _NOW + timedelta(hours=24, seconds=-1)
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        delivery = ExportDelivery(repository, spool, now=lambda: now)
        delivery.reconcile()
        with delivery.download(job_id, result) as remaining:
            assert remaining == 1
            now += timedelta(seconds=1)
            assert (root / "exports" / f"{job_id}.zip").exists()
        assert not (root / "exports" / f"{job_id}.zip").exists()
        assert (
            delivery.acknowledge(_receipt(result), operator_principal="operator@example.test")
            == result
        )
    assert _execute(root, releases, job_id).result == result


def _compete_for_export(root: Path) -> None:
    with ExportSpool(root, expected_owner=_OWNER) as spool:
        try:
            with spool.locks.acquire(LockName.EXPORT, blocking=False):
                pass
        except StateBusyError:
            os._exit(_KILLED_STATUS)


def test_download_holds_global_exclusion_until_reader_closes(tmp_path: Path) -> None:
    root, releases, _manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    result = _execute(root, releases, job_id).result
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        delivery = ExportDelivery(repository, spool, now=lambda: _NOW)
        with delivery.download(job_id, result):
            blocked = get_context("spawn").Process(target=_compete_for_export, args=(root,))
            blocked.start()
            blocked.join(10)
            assert blocked.exitcode == _KILLED_STATUS
        released = get_context("spawn").Process(target=_compete_for_export, args=(root,))
        released.start()
        released.join(10)
        assert released.exitcode == 0


def test_retirement_supports_export_jobs_accepted_before_delivery_marker(tmp_path: Path) -> None:
    root, releases, _manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    result = _execute(root, releases, job_id).result
    with StateRepository(root, expected_owner=_OWNER) as repository:
        path = StateRecordPath.authorization_job(job_id)
        old_job = repository.read(path).document
    del old_job["exportDelivery"]
    _write(root, path, old_job)
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        ExportDelivery(repository, spool, now=lambda: _NOW).acknowledge(
            _receipt(result), operator_principal="operator@example.test"
        )
    assert _execute(root, releases, job_id).result == result


def _deliver_with_competing_tenant_state(
    root: Path, job_id: str, result: dict[str, object], boundary: str, channel: Connection
) -> None:
    with (
        pytest.MonkeyPatch.context() as patch,
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        # A spawned process does not inherit the parent capacity fixture.
        patch.setattr(
            "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
            lambda _self: FilesystemCapacity(1, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000),
        )
        delivery = ExportDelivery(repository, spool, now=lambda: _NOW)

        def ready() -> None:
            channel.send("ready")
            assert channel.recv() == "continue"

        if boundary == "download-close":
            with delivery.download(job_id, result):
                ready()
        else:
            ready()
            if boundary == "download-open":
                with delivery.download(job_id, result):
                    pass
            elif boundary == "acknowledgement":
                assert (
                    delivery.acknowledge(
                        _receipt(result), operator_principal="operator@example.test"
                    )
                    == result
                )
            else:
                delivery.reconcile()
        channel.send("completed")


def _await_queued_tenant_write(root: Path, process: BaseProcess) -> None:
    inode = (root / "locks/tenant-state.lock").stat().st_ino
    deadline = time.monotonic() + 10
    while process.is_alive() and time.monotonic() < deadline:
        for line in Path("/proc/locks").read_text().splitlines():
            fields = line.split()
            if (
                "->" in fields
                and f"WRITE {process.pid}" in line
                and any(field.endswith(f":{inode}") for field in fields)
            ):
                return
        time.sleep(0.01)
    raise AssertionError("delivery did not wait for the competing tenant-state holder")


@pytest.mark.parametrize("mode", [LockMode.SHARED, LockMode.EXCLUSIVE])
@pytest.mark.parametrize(
    "boundary", ["download-open", "download-close", "acknowledgement", "reconciliation"]
)
def test_delivery_waits_for_competing_tenant_state(
    tmp_path: Path, boundary: str, mode: LockMode
) -> None:
    root, releases, _manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    result = _execute(root, releases, job_id).result
    result_path = root / "authorization/results" / f"{job_id}.json"
    before = result_path.read_bytes()
    context = get_context("spawn")
    parent, child = context.Pipe()
    process = context.Process(
        target=_deliver_with_competing_tenant_state,
        args=(root, job_id, result, boundary, child),
    )
    process.start()
    child.close()
    try:
        assert parent.poll(10)
        assert parent.recv() == "ready"
        with (
            LockManager(root / "locks", expected_owner=_OWNER) as locks,
            locks.acquire(LockName.TENANT_STATE, mode=mode),
        ):
            parent.send("continue")
            _await_queued_tenant_write(root, process)
            assert not parent.poll()
        assert parent.poll(10)
        assert parent.recv() == "completed"
        process.join(10)
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        process.close()
        parent.close()
    assert result_path.read_bytes() == before
    assert (root / "exports" / f"{job_id}.zip").exists() == (boundary != "acknowledgement")


@pytest.mark.parametrize("complete_runtime", [True, False])
def test_export_validates_the_current_complete_runtime_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, complete_runtime: bool
) -> None:
    root, releases, manifest = _source(tmp_path)
    selected_generation = "0198d17f-6f4a-7000-8000-000000000009"
    with StateRepository(root, expected_owner=_OWNER) as repository:
        before = repository.read(StateRecordPath.tenant_observed(_TENANT)).document
        assert before["runtimeGenerationId"] != selected_generation
        with repository.publication_transaction() as transaction:
            snapshot = snapshot_tenant_routes(transaction)
        if not complete_runtime:
            snapshot = replace(snapshot, tenants=())

        class Runtime:
            def __enter__(self) -> Runtime:
                return self

            def __exit__(self, *_exception: object) -> None:
                pass

            def using_held_publication_lock(self, _repository: object) -> nullcontext[None]:
                return nullcontext()

            def read_active(self) -> str:
                return selected_generation

            def read_generation_route_snapshot(self, requested: str) -> TenantRouteSnapshot:
                assert requested == selected_generation
                return snapshot

        monkeypatch.setattr(entrypoints, "_open_caddy_control_runtime", Runtime)
        validator = partial(entrypoints._selected_tenant_runtime_matches, repository)
        job_id = _issue(repository)
        if complete_runtime:
            result = _execute(root, releases, job_id, runtime_validator=validator).result
            assert result["status"] == "succeeded"
            assert _execute(root, releases, job_id, runtime_validator=validator).result == result
        else:
            with pytest.raises(ExecutionError, match="authorized routes"):
                _execute(root, releases, job_id, runtime_validator=validator)
        job = repository.read(StateRecordPath.authorization_job(job_id)).document
        assert job["executionValidated"] is complete_runtime
        assert repository.read(StateRecordPath.tenant_desired(_TENANT)).document == manifest
        assert repository.read(StateRecordPath.tenant_observed(_TENANT)).document == before


@pytest.mark.parametrize("resource", ["records", "bytes"])
def test_result_capacity_exhaustion_precedes_intent_or_bundle_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, resource: str
) -> None:
    root, releases, manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)

    def stop_after_claim(boundary: ExportCommitBoundary) -> None:
        if boundary == ExportCommitBoundary.SNAPSHOT_CAPTURED:
            raise RuntimeError("leave the executor-claimed job for retry")

    with pytest.raises(RuntimeError, match="executor-claimed"):
        _execute(root, releases, job_id, stop_after_claim)
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        repository.transaction(mode=LockMode.EXCLUSIVE) as transaction,
    ):
        inventory = transaction.measure_inventory()
    limits = (
        StateInventoryLimits(maximum_authorization_records=inventory.authorization_record_count)
        if resource == "records"
        else StateInventoryLimits(
            maximum_authorization_allocated_bytes=inventory.authorization_allocated_bytes
        )
    )
    original_admit = _StateTransaction.admit_inventory

    def admit_full(
        transaction: _StateTransaction, reservation: StateInventoryReservation
    ) -> StateInventoryProjection:
        return original_admit(transaction, reservation, limits=limits)

    with monkeypatch.context() as patch:
        patch.setattr(_StateTransaction, "admit_inventory", admit_full)
        with (
            StateRepository(root, expected_owner=_OWNER) as repository,
            ExportSpool(root, expected_owner=_OWNER) as spool,
        ):
            handler = ExportLifecycleHandler(
                repository,
                spool,
                _OpenGate(),
                release_root=releases,
                expected_owner=_OWNER,
                now=lambda: _NOW,
            )
            with pytest.raises(StateAdmissionRejectedError):
                handler.execute(job_id, claim=None, blocking=False)
    assert list((root / "exports").iterdir()) == []
    assert list((root / "intents").iterdir()) == []
    assert list((root / "authorization/results").iterdir()) == []
    with StateRepository(root, expected_owner=_OWNER) as repository:
        assert repository.read(StateRecordPath.tenant_desired(_TENANT)).document == manifest
    assert _execute(root, releases, job_id).result["status"] == "succeeded"


@pytest.mark.parametrize("disconnected_write", [1, 2, 3], ids=["header", "result", "payload"])
def test_disconnect_closes_source_before_releasing_slot_and_preserves_exact_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, disconnected_write: int
) -> None:
    root, releases, _manifest = _source(tmp_path)
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
    result = _execute(root, releases, job_id).result
    original_bundle = (root / "exports" / f"{job_id}.zip").read_bytes()
    reader, writer = os.pipe()
    original_write = DeadlineWriter.write
    original_close = runtime._ExportSource.close
    writes = 0
    closed: list[int] = []

    def disconnect(channel: DeadlineWriter, data: bytes | memoryview) -> None:
        nonlocal writes, reader
        writes += 1
        if writes == disconnected_write:
            os.close(reader)
            reader = -1
        original_write(channel, data)

    def close(source: runtime._ExportSource) -> None:
        spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
        closed.append(source.file_descriptor)
        original_close(source)

    try:
        with (
            StateRepository(root, expected_owner=_OWNER) as repository,
            ExportSpool(root, expected_owner=_OWNER) as spool,
        ):
            job = repository.read(StateRecordPath.authorization_job(job_id)).document
            issued = IssuedAuthorization(job_id, False, 0, job)
            delivery = ExportDelivery(repository, spool, now=lambda: _NOW)
            with monkeypatch.context() as patch:
                patch.setattr(DeadlineWriter, "write", disconnect)
                patch.setattr(runtime._ExportSource, "close", close)
                session = OperatorSession(
                    SimpleNamespace(receive=lambda **_kwargs: issued),
                    ResultWaiter(
                        repository,
                        SimpleNamespace(await_completion=lambda *_args, **_kwargs: None),
                    ),
                    state_root=root,
                    expected_owner=_OWNER,
                    writer=DeadlineWriter(writer),
                    export_delivery=delivery,
                )
                with pytest.raises(RuntimeBoundaryError, match="disconnected"):
                    session.run(operator_principal="operator@example.test")
            assert len(closed) == 1
            with pytest.raises(OSError):
                os.fstat(closed[0])
            with (
                LockManager(root / "locks", expected_owner=_OWNER) as competitor,
                competitor.acquire(LockName.EXPORT),
            ):
                assert (root / "exports" / f"{job_id}.zip").read_bytes() == original_bundle
            with delivery.download(job_id, result) as remaining:
                assert remaining is not None and remaining > 0
            assert (
                delivery.acknowledge(_receipt(result), operator_principal="operator@example.test")
                == result
            )
    finally:
        if reader >= 0:
            os.close(reader)
        os.close(writer)
    assert list((root / "exports").iterdir()) == []
    assert _execute(root, releases, job_id).result == result
