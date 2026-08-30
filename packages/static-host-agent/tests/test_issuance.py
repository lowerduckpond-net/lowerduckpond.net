from __future__ import annotations

import json
import os
import subprocess
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import (
    ContractError,
    canonical_json_bytes,
    deployment_record_digest,
    manifest_digest,
    platform_state_digest,
)
from lowerduckpond_static_host_agent import (
    AuthorizationIssuer,
    CapacityProjection,
    ClosedPublicationGate,
    CommandPublicationGate,
    CorrelationConflictError,
    FilesystemCapacity,
    IssuanceError,
    LockManager,
    PublicationDisabledError,
    StateRecordPath,
    StateRepository,
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
    def __init__(self) -> None:
        self._counter = 0

    def __call__(self, length: int) -> bytes:
        self._counter += 1
        return self._counter.to_bytes(length, "big")


@pytest.fixture(autouse=True)
def _state_filesystem_with_inode_accounting(monkeypatch: pytest.MonkeyPatch) -> None:
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


def _repository(root: Path) -> StateRepository:
    return StateRepository(root, expected_owner=os.geteuid())


def _create_request(correlation: str = "0198d17f-6f4a-7000-8000-000000000001") -> bytes:
    request = _fixture("operation-request.json")
    request["correlationId"] = correlation
    return canonical_json_bytes(request)


def _deploy_request() -> tuple[bytes, VerifiedArtifact]:
    artifact = VerifiedArtifact(size=7, sha256="a" * 64)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000003",
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }
    return canonical_json_bytes(request), artifact


def test_closed_gate_rejects_before_state_access_or_allocation(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    with _repository(root) as repository:
        issuer = AuthorizationIssuer(
            repository,
            gate=ClosedPublicationGate(),
            entropy=_Entropy(),
        )
        with pytest.raises(PublicationDisabledError, match="publication_disabled"):
            issuer.issue(
                _create_request(),
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=None,
            )
        inventory = repository.measure_authorization_records()

    assert inventory.record_count == 0


def test_command_gate_accepts_only_the_fixed_success_or_disabled_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "static-publication-gate"
    outcomes = iter(
        (
            subprocess.CompletedProcess([executable, "job-issuance"], 0, stderr=b""),
            subprocess.CompletedProcess(
                [executable, "job-issuance"],
                78,
                stderr=b"publication_disabled\n",
            ),
            subprocess.CompletedProcess(
                [executable, "job-issuance"],
                78,
                stderr=b"changed_contract\n",
            ),
        )
    )

    def run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return next(outcomes)

    monkeypatch.setattr("lowerduckpond_static_host_agent.issuance.subprocess.run", run)
    gate = CommandPublicationGate(executable)
    gate.require_enabled()
    with pytest.raises(PublicationDisabledError, match="publication_disabled"):
        gate.require_enabled()
    with pytest.raises(IssuanceError, match="failed closed"):
        gate.require_enabled()


def test_create_issues_immutable_platform_bound_job_and_exact_retry(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    _write(root, StateRecordPath.platform_namespace(), namespace)

    with _repository(root) as repository:
        issuer = AuthorizationIssuer(repository, gate=_OpenGate(), entropy=_Entropy())
        first = issuer.issue(
            _create_request(),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        retry = issuer.issue(
            _create_request(),
            operator_principal="operator@example.test",
            now=_NOW + timedelta(minutes=1),
            artifact=None,
        )

    assert first.created is True
    assert retry.created is False
    assert retry.job_id == first.job_id
    assert retry.document == first.document
    expected = first.document["expectedSource"]
    assert type(expected) is dict
    assert expected == {
        "expectsTenantAbsent": True,
        "lifecycle": None,
        "manifestDigest": None,
        "deploymentDigest": None,
        "archiveRecordDigest": None,
        "platformStateDigest": platform_state_digest(namespace).to_dict(),
    }


def test_exact_retry_recognition_requires_the_original_full_binding(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    raw_request = _create_request()

    with _repository(root) as repository:
        issuer = AuthorizationIssuer(repository, gate=_OpenGate(), entropy=_Entropy())
        assert (
            issuer.recognize_exact_retry(
                raw_request,
                operator_principal="operator@example.test",
                artifact=None,
            )
            is False
        )
        issuer.issue(
            raw_request,
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        assert (
            issuer.recognize_exact_retry(
                raw_request,
                operator_principal="operator@example.test",
                artifact=None,
            )
            is True
        )
        with pytest.raises(CorrelationConflictError, match="another"):
            issuer.recognize_exact_retry(
                raw_request,
                operator_principal="another@example.test",
                artifact=None,
            )


def test_exact_retry_recognition_checks_the_gate_before_state(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    with _repository(root) as repository:
        issuer = AuthorizationIssuer(
            repository,
            gate=ClosedPublicationGate(),
            entropy=_Entropy(),
        )
        with pytest.raises(PublicationDisabledError, match="publication_disabled"):
            issuer.recognize_exact_retry(
                _create_request(),
                operator_principal="operator@example.test",
                artifact=None,
            )


def test_noncreate_job_binds_manifest_and_current_deployment(tmp_path: Path) -> None:
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
    raw_request, artifact = _deploy_request()

    with _repository(root) as repository:
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            raw_request,
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=artifact,
        )

    expected = issued.document["expectedSource"]
    assert type(expected) is dict
    assert expected["lifecycle"] == "active"
    assert expected["manifestDigest"] == manifest_digest(desired).to_dict()
    assert expected["deploymentDigest"] == deployment_record_digest(deployment).to_dict()
    assert expected["archiveRecordDigest"] is None


def test_changed_source_or_artifact_binding_cannot_reuse_correlation(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    _write(root, StateRecordPath.platform_namespace(), namespace)

    with _repository(root) as repository:
        issuer = AuthorizationIssuer(repository, gate=_OpenGate(), entropy=_Entropy())
        issuer.issue(
            _create_request(),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        changed = deepcopy(namespace)
        changed["initializedAt"] = "2026-08-30T12:01:00Z"
        current = repository.read(StateRecordPath.platform_namespace())
        repository.compare_and_swap(StateRecordPath.platform_namespace(), current.revision, changed)
        with pytest.raises(CorrelationConflictError, match="another"):
            issuer.issue(
                _create_request(),
                operator_principal="operator@example.test",
                now=_NOW + timedelta(minutes=1),
                artifact=None,
            )


@pytest.mark.parametrize("principal", ["", " spaced", "operator/value", "a" * 129])
def test_issuer_rejects_invalid_principal_before_gate(principal: str, tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    with _repository(root) as repository:
        issuer = AuthorizationIssuer(
            repository,
            gate=ClosedPublicationGate(),
            entropy=_Entropy(),
        )
        with pytest.raises(IssuanceError, match="principal"):
            issuer.issue(
                _create_request(),
                operator_principal=principal,
                now=_NOW,
                artifact=None,
            )


def test_issuer_requires_exact_artifact_presence_and_binding(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    raw_request, artifact = _deploy_request()
    with _repository(root) as repository:
        issuer = AuthorizationIssuer(
            repository,
            gate=ClosedPublicationGate(),
            entropy=_Entropy(),
        )
        with pytest.raises(IssuanceError, match="required"):
            issuer.issue(
                raw_request,
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=None,
            )
        with pytest.raises(IssuanceError, match="binding"):
            issuer.issue(
                raw_request,
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=VerifiedArtifact(artifact.size + 1, artifact.sha256),
            )


def test_standalone_manifest_never_reaches_the_publication_gate(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    with _repository(root) as repository:
        issuer = AuthorizationIssuer(
            repository,
            gate=ClosedPublicationGate(),
            entropy=_Entropy(),
        )
        with pytest.raises(ContractError):
            issuer.issue(
                canonical_json_bytes(_fixture("site.json")),
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=None,
            )
