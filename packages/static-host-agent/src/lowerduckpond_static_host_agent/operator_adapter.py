"""Root-side orchestration of one strict operator request frame."""

from __future__ import annotations

from datetime import datetime
from typing import Final

from lowerduckpond_static_contracts import (
    HEADER_SIZE,
    MAX_DEPLOY_ARTIFACT_BYTES,
    FrameKind,
    decode_header,
)

from lowerduckpond_static_host_agent.intake import ArtifactIntake
from lowerduckpond_static_host_agent.issuance import (
    AuthorizationIssuer,
    IssuedAuthorization,
    VerifiedArtifact,
)
from lowerduckpond_static_host_agent.operator_stream import (
    DeadlineReader,
    MonotonicClock,
    ReadDeadline,
)
from lowerduckpond_static_host_agent.request_decoder import RequestDecoder

_DOCUMENT_TOTAL_SECONDS: Final = 15.0
_DOCUMENT_IDLE_SECONDS: Final = 15.0
_ARTIFACT_TOTAL_SECONDS: Final = 15.0 * 60.0
_ARTIFACT_IDLE_SECONDS: Final = 30.0


class OperatorAdapterError(RuntimeError):
    """The authenticated peer supplied an inconsistent operator frame."""


class OperatorAdapter:
    """Keep framing, intake, and issuance ordered across one SSH stream."""

    def __init__(
        self,
        *,
        reader: DeadlineReader,
        intake: ArtifactIntake,
        issuer: AuthorizationIssuer,
        decoder: RequestDecoder,
        clock: MonotonicClock,
    ) -> None:
        self._reader = reader
        self._intake = intake
        self._issuer = issuer
        self._decoder = decoder
        self._clock = clock

    def receive(
        self,
        *,
        operator_principal: str,
        now: datetime,
    ) -> IssuedAuthorization:
        """Receive exactly one frame and commit no artifact before the gate."""

        document_deadline = ReadDeadline.start(
            total_seconds=_DOCUMENT_TOTAL_SECONDS,
            idle_seconds=_DOCUMENT_IDLE_SECONDS,
            clock=self._clock,
        )
        header = decode_header(
            self._reader.read_exact(HEADER_SIZE, deadline=document_deadline),
            expected_kind=FrameKind.REQUEST,
        )
        raw_request = self._reader.read_exact(
            header.document_length,
            deadline=document_deadline,
        )
        canonical_request, request = self._decoder.decode(raw_request)
        artifact = _declared_artifact(request, header.payload_length)
        self._issuer.require_enabled()
        if artifact is None:
            self._reader.require_eof(deadline=document_deadline)
            return self._issuer.issue(
                canonical_request,
                operator_principal=operator_principal,
                now=now,
                artifact=None,
            )

        artifact_deadline = ReadDeadline.start(
            total_seconds=_ARTIFACT_TOTAL_SECONDS,
            idle_seconds=_ARTIFACT_IDLE_SECONDS,
            clock=self._clock,
        )
        allow_existing = self._issuer.recognize_exact_retry(
            canonical_request,
            operator_principal=operator_principal,
            artifact=artifact,
        )
        with self._intake.admit(
            operation=str(request["operation"]),
            correlation_id=request["correlationId"],
            declared=artifact,
            read=lambda count: self._reader.read_exact(count, deadline=artifact_deadline),
            allow_existing=allow_existing,
        ) as lease:
            self._reader.require_eof(deadline=artifact_deadline)
            issued = self._issuer.issue(
                canonical_request,
                operator_principal=operator_principal,
                now=now,
                artifact=lease.artifact.verified,
            )
            lease.commit()
            return issued


def _declared_artifact(
    request: dict[str, object],
    payload_length: int | None,
) -> VerifiedArtifact | None:
    operation = request["operation"]
    declared = request.get("artifact")
    if operation not in {"deploy", "import"}:
        if payload_length is not None:
            raise OperatorAdapterError("operation does not accept an artifact frame")
        return None
    if type(declared) is not dict or payload_length is None:
        raise OperatorAdapterError("operation requires one artifact frame")
    size = declared["size"]
    sha256 = declared["sha256"]
    if type(size) is not int or type(sha256) is not str or size != payload_length:
        raise OperatorAdapterError("artifact frame length does not match its request")
    if operation == "deploy" and size > MAX_DEPLOY_ARTIFACT_BYTES:
        raise OperatorAdapterError("deploy artifact exceeds its operation ceiling")
    return VerifiedArtifact(size=size, sha256=sha256)
