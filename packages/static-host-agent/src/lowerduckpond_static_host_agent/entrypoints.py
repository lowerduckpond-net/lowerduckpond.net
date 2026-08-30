"""Fixed installed entry points for SSH issuance, execution, and recovery."""

from __future__ import annotations

import os
import secrets
import sys
import time
from pathlib import Path
from typing import Final

from lowerduckpond_static_contracts import ContractError, ProtocolError, validate_uuid7

from lowerduckpond_static_host_agent.capacity import CapacityError
from lowerduckpond_static_host_agent.correlations import CorrelationError
from lowerduckpond_static_host_agent.execution import AuthorizationExecutor, ExecutionError
from lowerduckpond_static_host_agent.intake import ArtifactIntake, IntakeError
from lowerduckpond_static_host_agent.issuance import (
    AuthorizationIssuer,
    CommandPublicationGate,
    IssuanceError,
    PublicationDisabledError,
)
from lowerduckpond_static_host_agent.job_runtime import (
    DeadlineWriter,
    OperatorSession,
    ResultWaiter,
    RuntimeBoundaryError,
    StartupReconciler,
    SystemdJobHandoff,
)
from lowerduckpond_static_host_agent.locks import StateBusyError
from lowerduckpond_static_host_agent.operator_adapter import OperatorAdapter, OperatorAdapterError
from lowerduckpond_static_host_agent.operator_stream import DeadlineReader, StreamError
from lowerduckpond_static_host_agent.repository import StateRecordError, StateRepository
from lowerduckpond_static_host_agent.request_decoder import (
    RequestDecodeError,
    SubprocessRequestDecoder,
)
from lowerduckpond_static_host_agent.state_inventory import StateInventoryError

_STATE_ROOT: Final = Path("/var/lib/lowerduckpond/static")
_DECODER: Final = Path("/usr/local/libexec/lowerduckpond/static-request-decoder")
_PUBLICATION_GATE: Final = Path("/usr/local/libexec/lowerduckpond/static-publication-gate")
_EXPECTED_OWNER: Final = 0
_PRINCIPAL_ARGUMENTS: Final = 2

_SAFE_ERRORS: Final = (
    ContractError,
    CapacityError,
    ProtocolError,
    CorrelationError,
    ExecutionError,
    IntakeError,
    IssuanceError,
    OperatorAdapterError,
    RequestDecodeError,
    RuntimeBoundaryError,
    StateRecordError,
    StateBusyError,
    StateInventoryError,
    StreamError,
)


def _entropy(length: int) -> bytes:
    return secrets.token_bytes(length)


def operator_main(arguments: list[str] | None = None) -> int:
    """Run one authenticated forced-command session from fixed host paths."""

    values = sys.argv[1:] if arguments is None else arguments
    if len(values) != _PRINCIPAL_ARGUMENTS or values[0] != "--principal":
        return _fail("invalid_operator_adapter_invocation", 64)
    principal = values[1]
    try:
        gate = CommandPublicationGate(_PUBLICATION_GATE)
        # Preserve the disabled boundary even if durable state is absent,
        # partially restored, or unsafe: no state descriptor is opened first.
        gate.require_enabled()
        with (
            StateRepository(_STATE_ROOT, expected_owner=_EXPECTED_OWNER) as repository,
            ArtifactIntake(_STATE_ROOT, expected_owner=_EXPECTED_OWNER) as intake,
        ):
            issuer = AuthorizationIssuer(
                repository,
                gate=gate,
                entropy=_entropy,
            )
            adapter = OperatorAdapter(
                reader=DeadlineReader(sys.stdin.fileno()),
                intake=intake,
                issuer=issuer,
                decoder=SubprocessRequestDecoder(_DECODER),
                clock=time.monotonic,
            )
            handoff = SystemdJobHandoff()
            OperatorSession(
                adapter,
                ResultWaiter(repository, handoff),
                state_root=_STATE_ROOT,
                expected_owner=_EXPECTED_OWNER,
                writer=DeadlineWriter(sys.stdout.fileno()),
            ).run(operator_principal=principal)
    except PublicationDisabledError:
        return _fail("publication_disabled", 78)
    except _SAFE_ERRORS as error:
        return _fail(str(error), 1)
    except (OSError, ValueError) as error:
        return _fail(f"static_operator_failed:{type(error).__name__}", 1)
    return 0


def executor_main(arguments: list[str] | None = None) -> int:
    """Execute exactly one root-generated UUIDv7 authorization job."""

    values = sys.argv[1:] if arguments is None else arguments
    if len(values) != 1:
        return _fail("invalid_authorized_job_invocation", 64)
    try:
        job_id = validate_uuid7(values[0])
        with (
            StateRepository(_STATE_ROOT, expected_owner=_EXPECTED_OWNER) as repository,
            ArtifactIntake(_STATE_ROOT, expected_owner=_EXPECTED_OWNER) as intake,
        ):
            AuthorizationExecutor(repository, intake).execute(job_id, blocking=True)
    except (
        CapacityError,
        ContractError,
        ExecutionError,
        IntakeError,
        StateBusyError,
        StateInventoryError,
        StateRecordError,
    ):
        return _fail("authorized_job_failed", 1)
    except (OSError, ValueError) as error:
        return _fail(f"authorized_job_failed:{type(error).__name__}", 1)
    return 0


def reconcile_main(arguments: list[str] | None = None) -> int:
    """Repair and requeue only committed bounded authorization state."""

    values = sys.argv[1:] if arguments is None else arguments
    if values:
        return _fail("invalid_authorization_reconcile_invocation", 64)
    try:
        with (
            StateRepository(_STATE_ROOT, expected_owner=_EXPECTED_OWNER) as repository,
            ArtifactIntake(_STATE_ROOT, expected_owner=_EXPECTED_OWNER) as intake,
        ):
            StartupReconciler(repository, intake, SystemdJobHandoff()).reconcile()
    except (
        CapacityError,
        CorrelationError,
        ExecutionError,
        IntakeError,
        RuntimeBoundaryError,
        StateBusyError,
        StateInventoryError,
        StateRecordError,
    ):
        return _fail("authorization_reconcile_failed", 1)
    except (OSError, ValueError) as error:
        return _fail(f"authorization_reconcile_failed:{type(error).__name__}", 1)
    return 0


def _fail(message: str, status: int) -> int:
    os.write(sys.stderr.fileno(), message.encode("ascii", errors="replace")[:256] + b"\n")
    return status
