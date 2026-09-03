"""Expected-state-bound immutable authorization-job issuance."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Protocol, cast

from lowerduckpond_static_contracts import (
    archive_record_digest,
    decode_request,
    deployment_record_digest,
    manifest_digest,
    platform_state_digest,
    request_digest,
    validate_uuid7,
)
from lowerduckpond_static_domain import EntropySource, generate_uuid7

from lowerduckpond_static_host_agent.correlations import (
    CorrelationAdmission,
    CorrelationResolution,
)
from lowerduckpond_static_host_agent.locks import LockMode
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)

_PRINCIPAL: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,127}", flags=re.ASCII)
_DISABLED_STATUS: Final = 78


class IssuanceError(RuntimeError):
    """A request cannot become an expected-state-bound authorization job."""


class PublicationDisabledError(IssuanceError):
    """Production publication is closed before intake or durable allocation."""


class PublicationGate(Protocol):
    """Root-owned publication policy checked before state access or allocation."""

    def require_enabled(self) -> None: ...


class StateReader(Protocol):
    """Read validated state through either a repository or held transaction."""

    def read(self, path: StateRecordPath) -> StoredContract: ...

    def tenant_has_deployment_history(self, tenant_id: object) -> bool: ...


class ClosedPublicationGate:
    """The production-inert M3 gate used until publication is separately enabled."""

    def require_enabled(self) -> None:
        raise PublicationDisabledError("publication_disabled")


class CommandPublicationGate:
    """Delegate enablement to one fixed root-owned installed gate executable."""

    def __init__(self, executable: Path) -> None:
        if not executable.is_absolute():
            raise ValueError("publication gate executable must be absolute")
        self._executable = executable

    def require_enabled(self) -> None:
        try:
            completed = subprocess.run(  # noqa: S603
                [self._executable, "job-issuance"],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                close_fds=True,
                cwd="/",
                env={"LANG": "C.UTF-8"},
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise IssuanceError("publication gate failed closed") from error
        if completed.returncode == 0:
            return
        if (
            completed.returncode == _DISABLED_STATUS
            and completed.stderr == b"publication_disabled\n"
        ):
            raise PublicationDisabledError("publication_disabled")
        raise IssuanceError("publication gate failed closed")


@dataclass(frozen=True, slots=True)
class VerifiedArtifact:
    """Artifact metadata independently established by root-owned intake."""

    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class IssuedAuthorization:
    """The immutable job selected for a new request or exact retry."""

    job_id: str
    created: bool
    repaired_records: int
    document: dict[str, object]


class AuthorizationIssuer:
    """Bind validated operator input to current authoritative source state."""

    def __init__(
        self,
        repository: StateRepository,
        *,
        gate: PublicationGate,
        entropy: EntropySource,
    ) -> None:
        self._repository = repository
        self._gate = gate
        self._entropy = entropy
        self._admission = CorrelationAdmission(repository)

    def issue(
        self,
        raw_request: bytes,
        *,
        operator_principal: str,
        now: datetime,
        artifact: VerifiedArtifact | None,
        blocking: bool = False,
    ) -> IssuedAuthorization:
        """Validate the byte gate, then durably resolve one exact authorization."""

        request = decode_request(raw_request)
        principal = _validate_principal(operator_principal)
        _validate_artifact_binding(request, artifact)
        self._gate.require_enabled()
        accepted_at = _canonical_time(now)
        job_id = generate_uuid7(
            clock=lambda: _unix_milliseconds(accepted_at),
            entropy=self._entropy,
        )
        expected_source, source_authority = _build_source_bindings(
            self._repository,
            request,
        )
        candidate: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "AuthorizationJob",
            "compatibilityVersion": "static-job-v2",
            "jobId": job_id,
            "operatorPrincipal": principal,
            "request": request,
            "requestDigest": request_digest(request).to_dict(),
            "artifact": request.get("artifact"),
            "expectedSource": expected_source,
            "sourceAuthority": source_authority,
            "dispatchArchiveDeploymentIds": None,
            "dispatchDeploymentIds": None,
            "executionValidated": False,
            "acceptedAt": accepted_at.isoformat().replace("+00:00", "Z"),
            "phase": "pending",
        }
        resolution = self._admission.resolve(candidate, now=accepted_at, blocking=blocking)
        return _issued(resolution)

    def require_enabled(self) -> None:
        """Check the same gate before artifact intake begins."""

        self._gate.require_enabled()

    def recognize_exact_retry(
        self,
        raw_request: bytes,
        *,
        operator_principal: str,
        artifact: VerifiedArtifact | None,
        blocking: bool = False,
    ) -> IssuedAuthorization | None:
        """Resolve only durable authority with the same original caller binding."""

        request = decode_request(raw_request)
        principal = _validate_principal(operator_principal)
        _validate_artifact_binding(request, artifact)
        self._gate.require_enabled()
        resolution = self._admission.find_retry(
            request["correlationId"],
            binding={
                "operatorPrincipal": principal,
                "request": request,
                "requestDigest": request_digest(request).to_dict(),
                "artifact": request.get("artifact"),
            },
            blocking=blocking,
        )
        return None if resolution is None else _issued(resolution)

    def retry_requires_artifact(self, issued: IssuedAuthorization) -> bool:
        """Return whether an exact retry still needs its bound intake bytes."""

        if issued.created:
            raise IssuanceError("new authorization is not an exact retry")
        job_id = validate_uuid7(issued.job_id)
        with self._repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
            job = transaction.read(StateRecordPath.authorization_job(job_id)).document
            try:
                transaction.read(StateRecordPath.authorization_result(job_id))
            except FileNotFoundError:
                if job["phase"] in {"pending", "claimed"}:
                    return True
                raise IssuanceError("terminal authorization job has no immutable result") from None
            request = job["request"]
            if type(request) is not dict:  # pragma: no cover - validated reads prove this
                raise IssuanceError("authorization request is malformed")
            correlation_id = request["correlationId"]
            for identity in transaction.measure_intent_records().records:
                _path, intent = transaction.read_intent(identity.intent_id)
                if (
                    intent.document["kind"] == "TransactionIntent"
                    and intent.document["correlationId"] == correlation_id
                ):
                    return True
        return False


def _validate_principal(value: object) -> str:
    if type(value) is not str or _PRINCIPAL.fullmatch(value) is None:
        raise IssuanceError("operator principal is invalid")
    return value


def _validate_artifact_binding(
    request: dict[str, object],
    artifact: VerifiedArtifact | None,
) -> None:
    operation = request["operation"]
    declared = request.get("artifact")
    if operation in {"deploy", "import"}:
        if type(declared) is not dict or artifact is None:
            raise IssuanceError("artifact bytes are required for this operation")
        if declared != {"size": artifact.size, "sha256": artifact.sha256}:
            raise IssuanceError("artifact bytes do not match the request binding")
        return
    if declared is not None or artifact is not None:
        raise IssuanceError("this operation does not accept artifact bytes")


def _canonical_time(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise IssuanceError("issuance clock must be timezone-aware")
    return value.astimezone(UTC)


def _unix_milliseconds(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def _issued(resolution: CorrelationResolution) -> IssuedAuthorization:
    document = resolution.job.document
    return IssuedAuthorization(
        job_id=validate_uuid7(document["jobId"]),
        created=resolution.created,
        repaired_records=resolution.repaired_records,
        document=document,
    )


def build_expected_source(
    reader: StateReader,
    request: dict[str, object],
) -> dict[str, object]:
    """Derive the complete expected-source binding from one trusted reader."""

    expected, _authority = _build_source_bindings(reader, request)
    return expected


def _build_source_bindings(
    reader: StateReader,
    request: dict[str, object],
) -> tuple[dict[str, object], dict[str, object] | None]:
    """Derive digest and exact replay authority from the same source snapshot."""

    namespace = reader.read(StateRecordPath.platform_namespace()).document
    platform_digest = platform_state_digest(namespace).to_dict()
    if request["operation"] == "create":
        return (
            {
                "expectsTenantAbsent": True,
                "lifecycle": None,
                "manifestDigest": None,
                "deploymentDigest": None,
                "archiveRecordDigest": None,
                "platformStateDigest": platform_digest,
            },
            None,
        )

    tenant_id = validate_uuid7(request["tenantId"])
    desired = reader.read(StateRecordPath.tenant_desired(tenant_id)).document
    spec = cast(dict[str, object], desired["spec"])
    lifecycle = cast(str, spec["desiredState"])
    deployment_digest: dict[str, str] | None = None
    archive_digest: dict[str, str] | None = None
    archive: dict[str, object] | None = None
    if lifecycle != "undeployed":
        reference = cast(dict[str, object], spec["desiredDeployment"])
        deployment_id = validate_uuid7(reference["id"])
        deployment = reader.read(
            StateRecordPath.tenant_deployment(tenant_id, deployment_id)
        ).document
        deployment_digest = deployment_record_digest(deployment).to_dict()
        if lifecycle == "archived":
            archive = reader.read(StateRecordPath.tenant_archive(tenant_id, deployment_id)).document
            archive_digest = archive_record_digest(archive).to_dict()
    expected: dict[str, object] = {
        "expectsTenantAbsent": False,
        "lifecycle": lifecycle,
        "manifestDigest": manifest_digest(desired).to_dict(),
        "deploymentDigest": deployment_digest,
        "archiveRecordDigest": archive_digest,
        "platformStateDigest": platform_digest,
    }
    if request["operation"] == "delete":
        metadata = cast(dict[str, object], desired["metadata"])
        deletion_evidence: dict[str, object] | None = None
        if lifecycle == "undeployed":
            if reader.tenant_has_deployment_history(tenant_id):
                raise IssuanceError("undeployed tenant retains deployment history")
            deletion_evidence = {
                "mode": "never-deployed",
                "releasedSlugs": [metadata["slug"]],
                "archiveRecordDigest": None,
                "bucket": None,
                "key": None,
                "versionId": None,
                "emergencyReason": None,
            }
        elif lifecycle == "archived" and archive is not None:
            deletion_evidence = {
                "mode": "archived",
                "releasedSlugs": [metadata["slug"]],
                "archiveRecordDigest": archive_digest,
                "bucket": archive["bucket"],
                "key": archive["key"],
                "versionId": archive["versionId"],
                "emergencyReason": None,
            }
        else:
            raise IssuanceError("tenant lifecycle is not eligible for ordinary deletion")
        expected["deletionEvidence"] = deletion_evidence
    return expected, {"manifest": desired, "archiveRecord": archive}
