from __future__ import annotations

import hashlib
import json
import os
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import (
    canonical_json_bytes,
    deployment_record_digest,
    manifest_digest,
    request_digest,
)
from lowerduckpond_static_host_agent import (
    ArtifactClaim,
    ArtifactIntake,
    AuthorizationExecutor,
    AuthorizationIssuer,
    CapacityProjection,
    ExecutionOutcome,
    FilesystemCapacity,
    IntakeArtifactUnavailableError,
    IntentRemovalToken,
    IssuedAuthorization,
    LockManager,
    StateRecordPath,
    StateRepository,
    VerifiedArtifact,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
_TENANT_ID = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
_DEPLOYMENT_ID = "0191e2ca-49f2-7608-8cf3-f80ab2cab151"
_TENANT_ROOTED_RECORD_COMPONENTS = 3


class _OpenGate:
    def require_enabled(self) -> None:
        return


class _Entropy:
    def __call__(self, length: int) -> bytes:
        return b"\x08" * length


class _CompletingCreateHandler:
    def __init__(
        self,
        repository: StateRepository,
        *,
        persist_result: bool = True,
        commit_job: bool = True,
    ) -> None:
        self._repository = repository
        self._persist_result = persist_result
        self._commit_job = commit_job
        self.phases: list[object] = []
        self.claims: list[ArtifactClaim | None] = []

    def execute(
        self,
        job_id: str,
        *,
        claim: ArtifactClaim | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        job = self._repository.read(
            StateRecordPath.authorization_job(job_id),
            blocking=blocking,
        )
        self.phases.append(job.document["phase"])
        self.claims.append(claim)
        created = False
        try:
            result = self._repository.read(
                StateRecordPath.authorization_result(job_id),
                blocking=blocking,
            ).document
        except FileNotFoundError:
            request = job.document["request"]
            assert type(request) is dict
            result = _fixture("operation-result.json")
            provenance = result["provenance"]
            assert type(provenance) is dict
            provenance["jobId"] = job_id
            result["correlationId"] = request["correlationId"]
            if self._persist_result:
                self._repository.create_immutable(
                    StateRecordPath.authorization_result(job_id),
                    result,
                    blocking=blocking,
                )
                created = True
        if self._commit_job:
            current = self._repository.read(
                StateRecordPath.authorization_job(job_id),
                blocking=blocking,
            )
            completed = current.document
            completed["phase"] = "completed" if result["status"] == "succeeded" else "failed"
            self._repository.compare_and_swap(
                StateRecordPath.authorization_job(job_id),
                current.revision,
                completed,
                blocking=blocking,
            )
        return ExecutionOutcome(result, created)


class _CompletingFailureHandler:
    def __init__(self, repository: StateRepository) -> None:
        self._repository = repository
        self.claims: list[ArtifactClaim | None] = []

    def execute(
        self,
        job_id: str,
        *,
        claim: ArtifactClaim | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        self.claims.append(claim)
        job = self._repository.read(
            StateRecordPath.authorization_job(job_id),
            blocking=blocking,
        )
        request = job.document["request"]
        assert type(request) is dict
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": job_id},
            "correlationId": request["correlationId"],
            "operation": request["operation"],
            "status": "failed",
            "errorCode": "not_implemented",
            "tenantId": request["tenantId"],
        }
        self._repository.create_immutable(
            StateRecordPath.authorization_result(job_id),
            result,
            blocking=blocking,
        )
        failed = job.document
        failed["phase"] = "failed"
        self._repository.compare_and_swap(
            StateRecordPath.authorization_job(job_id),
            job.revision,
            failed,
            blocking=blocking,
        )
        return ExecutionOutcome(result, True)


class _UnavailableArtifactHandler:
    def execute(
        self,
        job_id: str,
        *,
        claim: ArtifactClaim | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        assert job_id
        assert claim is not None
        assert blocking is False
        raise IntakeArtifactUnavailableError("handler recovery requires its artifact")


class _CompletingUnavailableClaim(AbstractContextManager[ArtifactClaim]):
    def __init__(
        self,
        repository: StateRepository,
        *,
        job_id: str,
        intent_id: str,
    ) -> None:
        self._repository = repository
        self._job_id = job_id
        self._intent_id = intent_id

    def __enter__(self) -> ArtifactClaim:
        path = StateRecordPath.transaction_intent(self._intent_id)
        intent = self._repository.read(path)
        inventory = self._repository.measure_intent_records()
        generation = next(
            record.metadata_generation
            for record in inventory.records
            if record.intent_id == self._intent_id
        )
        self._repository.remove_reconciled_intent(
            path,
            IntentRemovalToken(intent.revision, generation),
        )
        job = self._repository.read(StateRecordPath.authorization_job(self._job_id))
        failed = job.document
        failed["phase"] = "failed"
        self._repository.compare_and_swap(
            StateRecordPath.authorization_job(self._job_id),
            job.revision,
            failed,
        )
        raise IntakeArtifactUnavailableError("concurrent replay consumed the artifact")

    def __exit__(self, *_exception: object) -> None:
        return


class _CompletingUnavailableIntake:
    def __init__(
        self,
        repository: StateRepository,
        *,
        job_id: str,
        intent_id: str,
    ) -> None:
        self._repository = repository
        self._job_id = job_id
        self._intent_id = intent_id

    def claim(
        self,
        *,
        correlation_id: object,
        declared: VerifiedArtifact,
        blocking: bool = False,
    ) -> AbstractContextManager[ArtifactClaim]:
        assert correlation_id
        assert declared.size > 0
        assert blocking is True
        return _CompletingUnavailableClaim(
            self._repository,
            job_id=self._job_id,
            intent_id=self._intent_id,
        )


@pytest.fixture(autouse=True)
def _capacity_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
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
    for module in ("correlations", "execution", "intake"):
        monkeypatch.setattr(
            f"lowerduckpond_static_host_agent.{module}.admit_release_capacity",
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
        ("audit",),
        ("intents",),
        ("intake",),
        ("locks",),
    ):
        _mkdir(root.joinpath(*components))
    LockManager.initialize(root / "locks", expected_owner=os.geteuid()).close()
    return root


def _write(root: Path, path: StateRecordPath, document: dict[str, object]) -> None:
    target = root.joinpath(*path.components)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.parent.chmod(0o700)
    if (
        path.components[:1] == ("tenants",)
        and len(path.components) == _TENANT_ROOTED_RECORD_COMPONENTS
    ):
        for name in ("archives", "deployments"):
            child = target.parent / name
            child.mkdir(exist_ok=True)
            child.chmod(0o700)
    target.write_bytes(canonical_json_bytes(document))
    target.chmod(0o600)


def _create_request() -> bytes:
    return canonical_json_bytes(_fixture("operation-request.json"))


def _issue_create(repository: StateRepository) -> IssuedAuthorization:
    return AuthorizationIssuer(
        repository,
        gate=_OpenGate(),
        entropy=_Entropy(),
    ).issue(
        _create_request(),
        operator_principal="operator@example.test",
        now=_NOW,
        artifact=None,
    )


def _create_intent(correlation_id: object) -> dict[str, object]:
    intent = _fixture("transaction-intent.json")
    intent["correlationId"] = correlation_id
    intent["operation"] = "create"
    intent["sourceManifestDigest"] = None
    candidate = _fixture("tenant-observed-state.json")
    candidate.update(
        {
            "desiredManifestDigest": intent["candidateManifestDigest"],
            "observedState": "undeployed",
            "activeDeploymentId": None,
            "runtimeGenerationId": None,
        }
    )
    intent["lifecycleRecovery"] = {
        "sourceObservedState": None,
        "sourceRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000004",
        "sourceRouteSet": "absent",
        "candidateObservedState": candidate,
        "candidateRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000006",
        "candidateRouteSet": "absent",
    }
    return intent


def test_executor_publishes_one_immutable_mutation_free_terminal_result(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    before_tenants = list((root / "tenants").iterdir())

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        first = AuthorizationExecutor(repository, intake).execute(issued.job_id)
        second = AuthorizationExecutor(repository, intake).execute(issued.job_id)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        stored = repository.read(StateRecordPath.authorization_result(issued.job_id)).document

    assert first.created is True
    assert first.result["status"] == "failed"
    assert first.result["errorCode"] == "not_implemented"
    assert second.created is False
    assert second.result == first.result == stored
    assert job["phase"] == "failed"
    assert list((root / "tenants").iterdir()) == before_tenants


def test_executor_preserves_a_claimed_job_when_its_handler_is_unavailable(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        request = claimed["request"]
        assert type(request) is dict
        intent = _create_intent(request["correlationId"])
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )

        with pytest.raises(RuntimeError, match="handler is unavailable"):
            AuthorizationExecutor(repository, intake).execute(issued.job_id)

        preserved = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        preserved_intent = repository.read(
            StateRecordPath.transaction_intent(intent["intentId"])
        ).document
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.authorization_result(issued.job_id))

    assert preserved["phase"] == "claimed"
    assert preserved_intent == intent


def test_executor_preserves_result_bearing_recovery_without_its_handler(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        request = claimed["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        manifest = result["manifest"]
        assert type(provenance) is dict
        assert type(manifest) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        intent = _create_intent(request["correlationId"])
        candidate_digest = manifest_digest(manifest).to_dict()
        intent["candidateManifestDigest"] = candidate_digest
        recovery = intent["lifecycleRecovery"]
        assert type(recovery) is dict
        candidate_observed = recovery["candidateObservedState"]
        assert type(candidate_observed) is dict
        candidate_observed["desiredManifestDigest"] = candidate_digest
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

        with pytest.raises(RuntimeError, match=r"result-bearing.*handler is unavailable"):
            AuthorizationExecutor(repository, intake).execute(issued.job_id)

        preserved = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        preserved_result = repository.read(
            StateRecordPath.authorization_result(issued.job_id)
        ).document
        preserved_intent = repository.read(
            StateRecordPath.transaction_intent(intent["intentId"])
        ).document

    assert preserved["phase"] == "claimed"
    assert preserved_result == result
    assert preserved_intent == intent


def test_executor_dispatches_claimed_create_and_replays_its_handler(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        handler = _CompletingCreateHandler(repository)
        executor = AuthorizationExecutor(repository, intake, handlers={"create": handler})

        first = executor.execute(issued.job_id)
        second = executor.execute(issued.job_id)

        stored = repository.read(StateRecordPath.authorization_result(issued.job_id)).document
        phase = repository.read(StateRecordPath.authorization_job(issued.job_id)).document["phase"]

    assert first.created is True
    assert second.created is False
    assert first.result == second.result == stored
    assert first.result["status"] == "succeeded"
    assert phase == "completed"
    assert handler.phases == ["claimed"]
    assert handler.claims == [None]


def test_executor_repairs_a_lagging_job_phase_without_handler_replay(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        assert type(provenance) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"create": handler},
        ).execute(issued.job_id)

    assert outcome.created is False
    assert outcome.result == result
    assert handler.phases == []


def test_executor_rejects_a_misbound_result_before_handler_dispatch(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        assert type(provenance) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = "0198d17f-6f4a-7000-8000-000000000099"
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        request = issued.document["request"]
        assert type(request) is dict
        intent = _create_intent(request["correlationId"])
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(RuntimeError, match="does not match its authorization job"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"create": handler},
            ).execute(issued.job_id)

    assert handler.phases == []


@pytest.mark.parametrize("drift", ["tenant", "candidate"])
def test_executor_binds_a_successful_create_result_to_its_active_intent(
    tmp_path: Path,
    drift: str,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        manifest = result["manifest"]
        assert type(provenance) is dict
        assert type(manifest) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        intent = _create_intent(request["correlationId"])
        metadata = manifest["metadata"]
        assert type(metadata) is dict
        if drift == "tenant":
            other_tenant = "0198d17f-6f4a-7000-8000-000000000099"
            other_origin = f"t-{other_tenant.replace('-', '')}.lowerduckpond.com"
            result["tenantId"] = other_tenant
            result["canonicalOrigin"] = other_origin
            metadata["id"] = other_tenant
            metadata["canonicalOrigin"] = other_origin
        candidate_digest = manifest_digest(manifest).to_dict()
        intent["candidateManifestDigest"] = candidate_digest
        recovery = intent["lifecycleRecovery"]
        assert type(recovery) is dict
        candidate_observed = recovery["candidateObservedState"]
        assert type(candidate_observed) is dict
        candidate_observed["desiredManifestDigest"] = candidate_digest
        if drift == "candidate":
            metadata["slug"] = "different-duck"
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(RuntimeError, match="result disagrees with its lifecycle intent"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"create": handler},
            ).execute(issued.job_id)

    assert handler.phases == []


def test_executor_binds_a_successful_rename_result_to_its_active_intent(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    source_manifest = _fixture("site.json")
    source_digest = manifest_digest(source_manifest).to_dict()
    candidate_manifest = json.loads(json.dumps(source_manifest))
    candidate_metadata = candidate_manifest["metadata"]
    assert type(candidate_metadata) is dict
    candidate_metadata["slug"] = "renamed-duck"
    candidate_digest = manifest_digest(candidate_manifest).to_dict()

    job = _fixture("authorization-job.json")
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "rename",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
        "tenantId": _TENANT_ID,
        "slug": "renamed-duck",
    }
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "claimed"
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": "active",
            "manifestDigest": source_digest,
            "deploymentDigest": deployment_record_digest(
                _fixture("deployment-record.json")
            ).to_dict(),
            "archiveRecordDigest": None,
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"

    intent = _fixture("transaction-intent.json")
    source_observed = _fixture("tenant-observed-state.json")
    source_observed["desiredManifestDigest"] = source_digest
    candidate_observed = json.loads(json.dumps(source_observed))
    candidate_observed["desiredManifestDigest"] = candidate_digest
    candidate_observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000006"
    intent.update(
        {
            "tenantId": _TENANT_ID,
            "correlationId": request["correlationId"],
            "operation": "rename",
            "sourceManifestDigest": source_digest,
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
    result = _fixture("operation-result.json")
    provenance = result["provenance"]
    assert type(provenance) is dict
    provenance["jobId"] = job["jobId"]
    result.update(
        {
            "correlationId": request["correlationId"],
            "operation": "rename",
            "tenantId": _TENANT_ID,
            "manifest": candidate_manifest,
        }
    )
    result_manifest = result["manifest"]
    assert type(result_manifest) is dict
    result_metadata = result_manifest["metadata"]
    assert type(result_metadata) is dict
    result_metadata["slug"] = "different-duck"

    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(root, StateRecordPath.transaction_intent(intent["intentId"]), intent)
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(RuntimeError, match="result disagrees with its lifecycle intent"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"rename": handler},
            ).execute(job["jobId"])

    assert handler.phases == []


@pytest.mark.parametrize(
    ("persist_result", "commit_job", "message"),
    [
        (False, True, "result is not durably exact"),
        (True, False, "before terminal job commit"),
    ],
)
def test_executor_rejects_an_incomplete_handler_commit(
    tmp_path: Path,
    persist_result: bool,
    commit_job: bool,
    message: str,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        handler = _CompletingCreateHandler(
            repository,
            persist_result=persist_result,
            commit_job=commit_job,
        )
        with pytest.raises(RuntimeError, match=message):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"create": handler},
            ).execute(issued.job_id)


def test_executor_revalidates_expected_source_before_claiming(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    _write(root, StateRecordPath.platform_namespace(), namespace)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        current = repository.read(StateRecordPath.platform_namespace())
        namespace["initializedAt"] = "2026-08-30T12:01:00Z"
        repository.compare_and_swap(
            StateRecordPath.platform_namespace(),
            current.revision,
            namespace,
        )
        handler = _CompletingCreateHandler(repository)
        executor = AuthorizationExecutor(
            repository,
            intake,
            handlers={"create": handler},
        )
        outcome = executor.execute(issued.job_id)
        replay = executor.execute(issued.job_id)

    assert outcome.result["errorCode"] == "state_drift"
    assert replay.result == outcome.result
    assert replay.created is False
    assert handler.phases == []


def test_executor_terminalizes_delete_that_becomes_ineligible(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    desired = _fixture("site.json")
    spec = desired["spec"]
    assert type(spec) is dict
    spec["desiredState"] = "undeployed"
    del spec["desiredDeployment"]
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), desired)
    request = _fixture("operation-request.json")
    request.update({"operation": "delete", "tenantId": _TENANT_ID})
    request.pop("slug", None)
    request.pop("quotas", None)
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        _write(
            root,
            StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
            _fixture("deployment-record.json"),
        )
        outcome = AuthorizationExecutor(repository, intake).execute(issued.job_id)
        stored = repository.read(StateRecordPath.authorization_result(issued.job_id)).document

    assert outcome.created is True
    assert outcome.result == stored
    assert outcome.result["status"] == "failed"
    assert outcome.result["errorCode"] == "state_drift"


def test_executor_archive_failure_includes_explicit_absent_record(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    request = _fixture("operation-request.json")
    request.update({"operation": "archive", "tenantId": _TENANT_ID})
    request.pop("slug", None)
    request.pop("quotas", None)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        outcome = AuthorizationExecutor(repository, intake).execute(issued.job_id)

    assert outcome.result["status"] == "failed"
    assert outcome.result["errorCode"] == "not_implemented"
    assert outcome.result["archiveRecord"] is None


def test_executor_uses_bound_intent_not_error_code_to_select_handler_replay(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        request = issued.document["request"]
        assert type(request) is dict
        intent = _create_intent(request["correlationId"])
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": request["correlationId"],
            "operation": "create",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": None,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"create": handler},
        ).execute(issued.job_id)

    assert outcome.result == result
    assert outcome.created is False
    assert handler.phases == ["claimed"]


def test_executor_rejects_an_intent_for_another_operation_before_handler_replay(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        intent = _fixture("transaction-intent.json")
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        request = issued.document["request"]
        assert type(request) is dict
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": request["correlationId"],
            "operation": "create",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": None,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(RuntimeError, match="intent authority does not match"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"create": handler},
            ).execute(issued.job_id)

    assert handler.phases == []


@pytest.mark.parametrize(
    ("intent_fixture", "operation", "lifecycle"),
    [
        ("archive-construction-intent.json", "archive", "active"),
        ("archive-retirement-intent.json", "delete", "archived"),
    ],
)
def test_executor_recognizes_archive_intent_paths_for_handler_replay(
    tmp_path: Path,
    intent_fixture: str,
    operation: str,
    lifecycle: str,
) -> None:
    root = _state_root(tmp_path)
    job = _fixture("authorization-job.json")
    intent = _fixture(intent_fixture)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": operation,
        "correlationId": intent["correlationId"],
        "tenantId": intent["tenantId"],
    }
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "failed"
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": lifecycle,
            "manifestDigest": intent["sourceManifestDigest"],
            "deploymentDigest": intent.get(
                "deploymentRecordDigest",
                {
                    "format": "lowerduckpond-deployment-record-v1",
                    "algorithm": "sha256",
                    "value": "c" * 64,
                },
            ),
            "archiveRecordDigest": intent.get("archiveRecordDigest"),
        }
    )
    correlation = dict(job)
    correlation["phase"] = "pending"
    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": operation,
        "status": "failed",
        "errorCode": "state_drift",
        "tenantId": request["tenantId"],
    }
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)
    intent_path = (
        StateRecordPath.archive_construction_intent(intent["intentId"])
        if intent_fixture == "archive-construction-intent.json"
        else StateRecordPath.archive_retirement_intent(intent["intentId"])
    )
    _write(root, intent_path, intent)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={operation: handler},
        ).execute(job["jobId"])

    assert outcome.result == result
    assert outcome.created is False
    assert handler.phases == ["failed"]


def test_executor_binds_a_successful_archive_result_to_its_construction_intent(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    job = _fixture("authorization-job.json")
    intent = _fixture("archive-construction-intent.json")
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "archive",
        "correlationId": intent["correlationId"],
        "tenantId": intent["tenantId"],
    }
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "claimed"
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": "active",
            "manifestDigest": intent["sourceManifestDigest"],
            "deploymentDigest": intent["deploymentRecordDigest"],
            "archiveRecordDigest": None,
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"
    manifest = _fixture("site.json")
    spec = manifest["spec"]
    metadata = manifest["metadata"]
    assert type(spec) is dict
    assert type(metadata) is dict
    spec["desiredState"] = "archived"
    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": "archive",
        "status": "succeeded",
        "tenantId": request["tenantId"],
        "canonicalOrigin": metadata["canonicalOrigin"],
        "manifest": manifest,
    }
    assert manifest_digest(manifest).to_dict() != intent["candidateManifestDigest"]
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(
        root,
        StateRecordPath.archive_construction_intent(intent["intentId"]),
        intent,
    )
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(RuntimeError, match="construction intent"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"archive": handler},
            ).execute(job["jobId"])

    assert handler.phases == []


def test_executor_dispatches_a_claimed_job_without_rechecking_its_source(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    _write(root, StateRecordPath.platform_namespace(), namespace)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        current = repository.read(StateRecordPath.platform_namespace())
        namespace["initializedAt"] = "2026-08-30T12:01:00Z"
        repository.compare_and_swap(
            StateRecordPath.platform_namespace(),
            current.revision,
            namespace,
        )
        handler = _CompletingCreateHandler(repository)

        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"create": handler},
        ).execute(issued.job_id)

    assert outcome.result["status"] == "succeeded"
    assert handler.phases == ["claimed"]


def test_executor_consumes_only_the_artifact_bound_to_the_job(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    payload = b"bounded deployment"
    artifact = VerifiedArtifact(len(payload), hashlib.sha256(payload).hexdigest())
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation_id,
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=correlation_id,
            declared=artifact,
            read=BytesIO(payload).read,
        ) as lease:
            issued = AuthorizationIssuer(
                repository,
                gate=_OpenGate(),
                entropy=_Entropy(),
            ).issue(
                canonical_json_bytes(request),
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=artifact,
            )
            lease.commit()
        handler = _CompletingFailureHandler(repository)
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"deploy": handler},
        ).execute(issued.job_id)

    assert outcome.result["errorCode"] == "not_implemented"
    assert len(handler.claims) == 1
    assert handler.claims[0] is not None
    assert handler.claims[0].artifact == lease.artifact
    assert list((root / "intake").iterdir()) == []


def test_executor_reacquires_the_bound_artifact_for_lifecycle_replay(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    manifest = _fixture("site.json")
    manifest_digest_value = manifest_digest(manifest).to_dict()
    candidate_manifest = json.loads(json.dumps(manifest))
    candidate_spec = candidate_manifest["spec"]
    assert type(candidate_spec) is dict
    candidate_deployment = candidate_spec["desiredDeployment"]
    assert type(candidate_deployment) is dict
    candidate_deployment["id"] = "0198d17f-6f4a-7000-8000-000000000005"
    candidate_deployment["archiveSha256"] = "d" * 64
    candidate_manifest_digest = manifest_digest(candidate_manifest).to_dict()
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    payload = b"recoverable replay deployment"
    artifact = VerifiedArtifact(len(payload), hashlib.sha256(payload).hexdigest())
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation_id,
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=correlation_id,
            declared=artifact,
            read=BytesIO(payload).read,
        ) as lease:
            issued = AuthorizationIssuer(
                repository,
                gate=_OpenGate(),
                entropy=_Entropy(),
            ).issue(
                canonical_json_bytes(request),
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=artifact,
            )
            lease.commit()

        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        source_observed = _fixture("tenant-observed-state.json")
        source_observed["desiredManifestDigest"] = manifest_digest_value
        candidate_observed = json.loads(json.dumps(source_observed))
        candidate_observed["desiredManifestDigest"] = candidate_manifest_digest
        candidate_observed["activeDeploymentId"] = "0198d17f-6f4a-7000-8000-000000000005"
        candidate_observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000006"
        intent = _fixture("transaction-intent.json")
        intent.update(
            {
                "tenantId": _TENANT_ID,
                "correlationId": correlation_id,
                "operation": "deploy",
                "sourceManifestDigest": manifest_digest_value,
                "candidateManifestDigest": candidate_manifest_digest,
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
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": correlation_id,
            "operation": "deploy",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": _TENANT_ID,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

        handler = _CompletingCreateHandler(repository)
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"deploy": handler},
        ).execute(issued.job_id)

    assert outcome.result == result
    assert outcome.created is False
    assert len(handler.claims) == 1
    assert handler.claims[0] is not None
    assert handler.claims[0].artifact.verified == artifact
    assert list((root / "intake").iterdir()) == []


def test_executor_returns_a_completed_replay_after_losing_the_artifact_race(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    manifest = _fixture("site.json")
    source_digest = manifest_digest(manifest).to_dict()
    candidate_manifest = json.loads(json.dumps(manifest))
    candidate_spec = candidate_manifest["spec"]
    assert type(candidate_spec) is dict
    candidate_deployment = candidate_spec["desiredDeployment"]
    assert type(candidate_deployment) is dict
    candidate_deployment["id"] = "0198d17f-6f4a-7000-8000-000000000005"
    candidate_deployment["archiveSha256"] = "d" * 64
    candidate_digest = manifest_digest(candidate_manifest).to_dict()
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    artifact = VerifiedArtifact(32, "d" * 64)
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation_id,
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=artifact,
        )
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        source_observed = _fixture("tenant-observed-state.json")
        source_observed["desiredManifestDigest"] = source_digest
        candidate_observed = json.loads(json.dumps(source_observed))
        candidate_observed["desiredManifestDigest"] = candidate_digest
        candidate_observed["activeDeploymentId"] = candidate_deployment["id"]
        candidate_observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000006"
        intent = _fixture("transaction-intent.json")
        intent.update(
            {
                "tenantId": _TENANT_ID,
                "correlationId": correlation_id,
                "operation": "deploy",
                "sourceManifestDigest": source_digest,
                "candidateManifestDigest": candidate_digest,
                "lifecycleRecovery": {
                    "sourceObservedState": source_observed,
                    "sourceRuntimeGenerationId": ("0198d17f-6f4a-7000-8000-000000000004"),
                    "sourceRouteSet": "both",
                    "candidateObservedState": candidate_observed,
                    "candidateRuntimeGenerationId": ("0198d17f-6f4a-7000-8000-000000000006"),
                    "candidateRouteSet": "both",
                },
            }
        )
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": correlation_id,
            "operation": "deploy",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": _TENANT_ID,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        handler = _CompletingFailureHandler(repository)
        intent_id = intent["intentId"]
        assert type(intent_id) is str
        intake = _CompletingUnavailableIntake(
            repository,
            job_id=issued.job_id,
            intent_id=intent_id,
        )

        # The intake double preserves the production claim protocol without
        # constructing a privileged filesystem-backed ArtifactIntake.
        outcome = AuthorizationExecutor(
            repository,
            intake,  # type: ignore[arg-type]
            handlers={"deploy": handler},
        ).execute(issued.job_id, blocking=True)

        terminal = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.transaction_intent(intent["intentId"]))

    assert outcome.result == result
    assert outcome.created is False
    assert terminal["phase"] == "failed"
    assert handler.claims == []


def test_executor_does_not_terminalize_handler_artifact_errors(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    payload = b"recoverable deployment"
    artifact = VerifiedArtifact(len(payload), hashlib.sha256(payload).hexdigest())
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation_id,
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=correlation_id,
            declared=artifact,
            read=BytesIO(payload).read,
        ) as lease:
            issued = AuthorizationIssuer(
                repository,
                gate=_OpenGate(),
                entropy=_Entropy(),
            ).issue(
                canonical_json_bytes(request),
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=artifact,
            )
            lease.commit()

        with pytest.raises(
            IntakeArtifactUnavailableError,
            match="handler recovery requires",
        ):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"deploy": _UnavailableArtifactHandler()},
            ).execute(issued.job_id)

        job = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.authorization_result(issued.job_id))

    assert job["phase"] == "claimed"
    assert [path.name for path in (root / "intake").iterdir()] == [f"{correlation_id}.artifact"]


def test_executor_fails_terminally_when_bound_artifact_is_absent(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    artifact = VerifiedArtifact(7, "a" * 64)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000004",
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=artifact,
        )
        outcome = AuthorizationExecutor(repository, intake).execute(issued.job_id)

    assert outcome.result["errorCode"] == "invalid_artifact"


def test_executor_recovers_a_claimed_lifecycle_job_without_its_artifact(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    manifest = _fixture("site.json")
    source_digest = manifest_digest(manifest).to_dict()
    candidate_manifest = json.loads(json.dumps(manifest))
    candidate_spec = candidate_manifest["spec"]
    assert type(candidate_spec) is dict
    candidate_deployment = candidate_spec["desiredDeployment"]
    assert type(candidate_deployment) is dict
    candidate_deployment["id"] = "0198d17f-6f4a-7000-8000-000000000005"
    candidate_deployment["archiveSha256"] = "d" * 64
    candidate_digest = manifest_digest(candidate_manifest).to_dict()
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    artifact = VerifiedArtifact(32, "d" * 64)
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation_id,
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=artifact,
        )
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        source_observed = _fixture("tenant-observed-state.json")
        source_observed["desiredManifestDigest"] = source_digest
        candidate_observed = json.loads(json.dumps(source_observed))
        candidate_observed["desiredManifestDigest"] = candidate_digest
        candidate_observed["activeDeploymentId"] = candidate_deployment["id"]
        candidate_observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000006"
        intent = _fixture("transaction-intent.json")
        intent.update(
            {
                "tenantId": _TENANT_ID,
                "correlationId": correlation_id,
                "operation": "deploy",
                "sourceManifestDigest": source_digest,
                "candidateManifestDigest": candidate_digest,
                "lifecycleRecovery": {
                    "sourceObservedState": source_observed,
                    "sourceRuntimeGenerationId": ("0198d17f-6f4a-7000-8000-000000000004"),
                    "sourceRouteSet": "both",
                    "candidateObservedState": candidate_observed,
                    "candidateRuntimeGenerationId": ("0198d17f-6f4a-7000-8000-000000000006"),
                    "candidateRouteSet": "both",
                },
            }
        )
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        handler = _CompletingFailureHandler(repository)

        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"deploy": handler},
        ).execute(issued.job_id)
        terminal = repository.read(StateRecordPath.authorization_job(issued.job_id)).document

    assert outcome.result["errorCode"] == "not_implemented"
    assert terminal["phase"] == "failed"
    assert handler.claims == [None]


def test_executor_repairs_a_terminal_result_published_before_job_phase(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": request["correlationId"],
            "operation": "create",
            "status": "failed",
            "errorCode": "not_implemented",
            "tenantId": None,
        }
        repository.create_immutable(StateRecordPath.authorization_result(issued.job_id), result)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        outcome = AuthorizationExecutor(repository, intake).execute(issued.job_id)
        phase = repository.read(StateRecordPath.authorization_job(issued.job_id)).document["phase"]

    assert outcome.created is False
    assert phase == "failed"


def test_executor_repairs_a_successful_create_with_its_generated_tenant(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        assert type(provenance) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        repository.create_immutable(StateRecordPath.authorization_result(issued.job_id), result)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        outcome = AuthorizationExecutor(repository, intake).execute(issued.job_id)
        phase = repository.read(StateRecordPath.authorization_job(issued.job_id)).document["phase"]

    assert outcome.created is False
    assert outcome.result["status"] == "succeeded"
    assert phase == "completed"
