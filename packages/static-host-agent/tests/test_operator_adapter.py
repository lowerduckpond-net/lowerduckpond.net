from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import (
    ContractError,
    FrameHeader,
    FrameKind,
    canonical_json_bytes,
    encode_header,
    manifest_digest,
)
from lowerduckpond_static_host_agent import (
    ArtifactIntake,
    AuthorizationExecutor,
    AuthorizationIssuer,
    CapacityProjection,
    ClosedPublicationGate,
    DeadlineReader,
    FilesystemCapacity,
    LocalRequestDecoder,
    LockManager,
    OperatorAdapter,
    OperatorAdapterError,
    PublicationDisabledError,
    StateRecordPath,
    StateRepository,
    StreamError,
    VerifiedArtifact,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
_TENANT_ID = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
_DEPLOYMENT_ID = "0191e2ca-49f2-7608-8cf3-f80ab2cab151"


class _OpenGate:
    def require_enabled(self) -> None:
        return


class _Entropy:
    def __call__(self, length: int) -> bytes:
        return b"\x01" * length


@pytest.fixture(autouse=True)
def _capacity_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.intake.admit_release_capacity",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
        lambda _transaction: FilesystemCapacity(
            device=1,
            fragment_size=4096,
            total_blocks=100_000_000,
            available_blocks=80_000_000,
            total_inodes=1_000_000,
            available_inodes=900_000,
        ),
    )
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.correlations.admit_release_capacity",
        lambda *_args, **_kwargs: CapacityProjection(
            projected_allocated_bytes=0,
            projected_unique_inodes=0,
            remaining_available_bytes=1,
            remaining_available_inodes=1,
            required_available_bytes=0,
            required_available_inodes=0,
        ),
    )


def _fixture(name: str) -> dict[str, object]:
    value = json.loads((_FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _mkdir(path: Path) -> None:
    path.mkdir()
    path.chmod(0o700)


def _state_root(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    _mkdir(root)
    for components in (
        ("platform",),
        ("tenants",),
        ("authorization",),
        ("authorization", "correlations"),
        ("authorization", "jobs"),
        ("authorization", "results"),
        ("intents",),
        ("intake",),
        ("locks",),
    ):
        _mkdir(root.joinpath(*components))
    manager = LockManager.initialize(root / "locks", expected_owner=os.geteuid())
    manager.close()
    return root


def _write(root: Path, path: StateRecordPath, document: dict[str, object]) -> None:
    target = root.joinpath(*path.components)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.parent.chmod(0o700)
    target.write_bytes(canonical_json_bytes(document))
    target.chmod(0o600)


def _frame(request: dict[str, object], artifact: bytes | None = None) -> bytes:
    raw = canonical_json_bytes(request)
    return (
        encode_header(
            FrameHeader(
                FrameKind.REQUEST,
                len(raw),
                len(artifact) if artifact is not None else None,
            )
        )
        + raw
        + (artifact or b"")
    )


def _pipe(payload: bytes) -> tuple[int, int]:
    read_fd, write_fd = os.pipe()
    os.write(write_fd, payload)
    os.close(write_fd)
    return read_fd, -1


def _adapter(
    root: Path,
    read_fd: int,
    *,
    gate: _OpenGate | ClosedPublicationGate,
    wall_clock: Callable[[], datetime] | None = None,
) -> tuple[OperatorAdapter, ArtifactIntake, StateRepository]:
    repository = StateRepository(root, expected_owner=os.geteuid())
    intake = ArtifactIntake(root, expected_owner=os.geteuid())
    issuer = AuthorizationIssuer(repository, gate=gate, entropy=_Entropy())
    return (
        OperatorAdapter(
            reader=DeadlineReader(read_fd),
            intake=intake,
            issuer=issuer,
            decoder=LocalRequestDecoder(),
            clock=time.monotonic,
            wall_clock=wall_clock or (lambda: _NOW),
        ),
        intake,
        repository,
    )


def _deploy_intent(correlation_id: str, artifact_sha256: str) -> dict[str, object]:
    source = _fixture("site.json")
    source_digest = manifest_digest(source).to_dict()
    candidate = json.loads(json.dumps(source))
    candidate_spec = candidate["spec"]
    assert type(candidate_spec) is dict
    candidate_deployment = candidate_spec["desiredDeployment"]
    assert type(candidate_deployment) is dict
    candidate_deployment["id"] = "0198d17f-6f4a-7000-8000-000000000005"
    candidate_deployment["archiveSha256"] = artifact_sha256
    candidate_digest = manifest_digest(candidate).to_dict()
    source_observed = _fixture("tenant-observed-state.json")
    source_observed["desiredManifestDigest"] = source_digest
    candidate_observed = json.loads(json.dumps(source_observed))
    candidate_observed["desiredManifestDigest"] = candidate_digest
    candidate_observed["activeDeploymentId"] = candidate_deployment["id"]
    candidate_observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000006"
    intent = _fixture("transaction-intent.json")
    intent.update(
        {
            "correlationId": correlation_id,
            "operation": "deploy",
            "sourceManifest": source,
            "sourceManifestDigest": source_digest,
            "candidateManifest": candidate,
            "candidateManifestDigest": candidate_digest,
            "lifecycleRecovery": {
                "sourceObservedState": source_observed,
                "sourceRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000004",
                "sourceRouteSet": "both",
                "candidateObservedState": candidate_observed,
                "candidateRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000006",
                "candidateRouteSet": "both",
            },
        }
    )
    return intent


def test_disabled_adapter_stops_before_artifact_or_state_allocation(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    artifact = b"payload"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
        "tenantId": _TENANT_ID,
        "artifact": {"size": len(artifact), "sha256": hashlib.sha256(artifact).hexdigest()},
    }
    read_fd, _ = _pipe(_frame(request, artifact))
    adapter, intake, repository = _adapter(root, read_fd, gate=ClosedPublicationGate())
    try:
        with pytest.raises(PublicationDisabledError, match="publication_disabled"):
            adapter.receive(operator_principal="operator@example.test")
        assert repository.measure_authorization_records().record_count == 0
        assert list((root / "intake").iterdir()) == []
    finally:
        intake.close()
        repository.close()
        os.close(read_fd)


def test_adapter_issues_nonartifact_job_after_exact_eof(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    read_fd, _ = _pipe(_frame(_fixture("operation-request.json")))
    adapter, intake, repository = _adapter(root, read_fd, gate=_OpenGate())
    try:
        issued = adapter.receive(operator_principal="operator@example.test")
    finally:
        intake.close()
        repository.close()
        os.close(read_fd)

    assert issued.created is True
    assert issued.document["artifact"] is None


def test_adapter_syncs_artifact_before_immutable_job(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    desired = _fixture("site.json")
    deployment = _fixture("deployment-record.json")
    _write(root, StateRecordPath.platform_namespace(), namespace)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), desired)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        deployment,
    )
    artifact = b"payload"
    correlation = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation,
        "tenantId": _TENANT_ID,
        "artifact": {"size": len(artifact), "sha256": hashlib.sha256(artifact).hexdigest()},
    }
    read_fd, _ = _pipe(_frame(request, artifact))
    timestamp_calls = 0

    def accepted_at() -> datetime:
        nonlocal timestamp_calls
        timestamp_calls += 1
        assert os.read(read_fd, 1) == b""
        return _NOW

    adapter, intake, repository = _adapter(
        root,
        read_fd,
        gate=_OpenGate(),
        wall_clock=accepted_at,
    )
    try:
        issued = adapter.receive(operator_principal="operator@example.test")
    finally:
        intake.close()
        repository.close()
        os.close(read_fd)

    assert issued.created is True
    assert timestamp_calls == 1
    assert (root / "intake" / f"{correlation}.artifact").read_bytes() == artifact


def test_adapter_accepts_an_exact_artifact_retry_without_a_second_slot(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    artifact = b"payload"
    correlation = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation,
        "tenantId": _TENANT_ID,
        "artifact": {"size": len(artifact), "sha256": hashlib.sha256(artifact).hexdigest()},
    }

    issued = []
    for _attempt in range(2):
        read_fd, _ = _pipe(_frame(request, artifact))
        adapter, intake, repository = _adapter(root, read_fd, gate=_OpenGate())
        try:
            issued.append(adapter.receive(operator_principal="operator@example.test"))
        finally:
            intake.close()
            repository.close()
            os.close(read_fd)

    assert [result.created for result in issued] == [True, False]
    assert issued[0].job_id == issued[1].job_id
    assert [entry.name for entry in (root / "intake").iterdir()] == [f"{correlation}.artifact"]


def test_exact_artifact_retry_preserves_bytes_for_result_bearing_recovery(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    artifact = b"recoverable payload"
    correlation = "0198d17f-6f4a-7000-8000-000000000003"
    artifact_sha256 = hashlib.sha256(artifact).hexdigest()
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation,
        "tenantId": _TENANT_ID,
        "artifact": {"size": len(artifact), "sha256": artifact_sha256},
    }

    first_fd, _ = _pipe(_frame(request, artifact))
    adapter, intake, repository = _adapter(root, first_fd, gate=_OpenGate())
    try:
        issued = adapter.receive(operator_principal="operator@example.test")
    finally:
        intake.close()
        repository.close()
        os.close(first_fd)

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        intent = _deploy_intent(correlation, artifact_sha256)
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": correlation,
            "operation": "deploy",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": _TENANT_ID,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

    retry_fd, _ = _pipe(_frame(request, artifact))
    adapter, intake, repository = _adapter(root, retry_fd, gate=_OpenGate())
    try:
        retry = adapter.receive(operator_principal="operator@example.test")
    finally:
        intake.close()
        repository.close()
        os.close(retry_fd)

    assert retry.created is False
    assert retry.job_id == issued.job_id
    assert (root / "intake" / f"{correlation}.artifact").read_bytes() == artifact


def test_exact_artifact_retry_repairs_a_job_committed_before_lease_commit(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    artifact = b"payload"
    correlation = "0198d17f-6f4a-7000-8000-000000000003"
    verified = VerifiedArtifact(
        size=len(artifact),
        sha256=hashlib.sha256(artifact).hexdigest(),
    )
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation,
        "tenantId": _TENANT_ID,
        "artifact": {"size": verified.size, "sha256": verified.sha256},
    }
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        first = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=verified,
        )
    assert list((root / "intake").iterdir()) == []

    read_fd, _ = _pipe(_frame(request, artifact))
    adapter, intake, repository = _adapter(root, read_fd, gate=_OpenGate())
    try:
        retry = adapter.receive(operator_principal="operator@example.test")
    finally:
        intake.close()
        repository.close()
        os.close(read_fd)

    assert retry.created is False
    assert retry.job_id == first.job_id
    assert (root / "intake" / f"{correlation}.artifact").read_bytes() == artifact


def test_exact_terminal_retry_does_not_recreate_consumed_artifact(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    artifact = b"payload"
    correlation = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation,
        "tenantId": _TENANT_ID,
        "artifact": {"size": len(artifact), "sha256": hashlib.sha256(artifact).hexdigest()},
    }

    first_fd, _ = _pipe(_frame(request, artifact))
    adapter, intake, repository = _adapter(root, first_fd, gate=_OpenGate())
    try:
        issued = adapter.receive(operator_principal="operator@example.test")
    finally:
        intake.close()
        repository.close()
        os.close(first_fd)
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        AuthorizationExecutor(repository, intake).execute(issued.job_id)
    assert list((root / "intake").iterdir()) == []

    retry_fd, _ = _pipe(_frame(request, artifact))
    adapter, intake, repository = _adapter(root, retry_fd, gate=_OpenGate())
    try:
        retry = adapter.receive(operator_principal="operator@example.test")
    finally:
        intake.close()
        repository.close()
        os.close(retry_fd)

    assert retry.created is False
    assert list((root / "intake").iterdir()) == []


def test_adapter_rejects_trailing_byte_and_cleans_artifact(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    desired = _fixture("site.json")
    deployment = _fixture("deployment-record.json")
    _write(root, StateRecordPath.platform_namespace(), namespace)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), desired)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        deployment,
    )
    artifact = b"payload"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000003",
        "tenantId": _TENANT_ID,
        "artifact": {"size": len(artifact), "sha256": hashlib.sha256(artifact).hexdigest()},
    }
    read_fd, _ = _pipe(_frame(request, artifact) + b"x")
    adapter, intake, repository = _adapter(root, read_fd, gate=_OpenGate())
    try:
        with pytest.raises(StreamError, match="trailing_bytes"):
            adapter.receive(operator_principal="operator@example.test")
        assert list((root / "intake").iterdir()) == []
        assert repository.measure_authorization_records().record_count == 0
    finally:
        intake.close()
        repository.close()
        os.close(read_fd)


def test_adapter_rejects_header_request_artifact_mismatch_before_gate(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "create",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
        "slug": "duck-repair",
        "quotas": {"storageMiB": 100, "entries": 5000},
    }
    read_fd, _ = _pipe(_frame(request, b"x"))
    adapter, intake, repository = _adapter(root, read_fd, gate=ClosedPublicationGate())
    try:
        with pytest.raises(OperatorAdapterError, match="does not accept"):
            adapter.receive(operator_principal="operator@example.test")
    finally:
        intake.close()
        repository.close()
        os.close(read_fd)


def test_adapter_rejects_standalone_manifest_before_gate(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    read_fd, _ = _pipe(_frame(_fixture("site.json")))
    adapter, intake, repository = _adapter(root, read_fd, gate=ClosedPublicationGate())
    try:
        with pytest.raises(ContractError):
            adapter.receive(operator_principal="operator@example.test")
    finally:
        intake.close()
        repository.close()
        os.close(read_fd)
