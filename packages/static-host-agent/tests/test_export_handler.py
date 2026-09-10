from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from multiprocessing import get_context
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes, decode_contract, manifest_digest
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.execution import AuthorizationExecutor, ExecutionOutcome
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
from lowerduckpond_static_host_agent.issuance import AuthorizationIssuer
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName
from lowerduckpond_static_host_agent.portable_bundle import inspect_portable_bundle
from lowerduckpond_static_host_agent.release_tree import measure_release_tree
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository

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
        activeDeploymentId=_DEPLOYMENT,
        runtimeGenerationId=_GENERATION if state == "active" else None,
    )
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT), manifest)
    _write(root, StateRecordPath.tenant_observed(_TENANT), observed)
    _write(root, StateRecordPath.tenant_deployment(_TENANT, _DEPLOYMENT), deployment)
    return root, releases, manifest


def _entropy(length: int) -> bytes:
    return os.urandom(length)


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


def _execute(
    root: Path,
    releases: Path,
    job_id: str,
    hook: Callable[[ExportCommitBoundary], None] | None = None,
    *,
    spool_limits: ExportSpoolLimits = DEFAULT_EXPORT_SPOOL_LIMITS,
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
        )
        return AuthorizationExecutor(
            repository,
            intake,
            handlers={"export": handler},
            tenant_runtime_validator=lambda *_args: True,
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
