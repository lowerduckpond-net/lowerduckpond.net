"""Fixed installed entry points for SSH issuance, execution, and recovery."""

from __future__ import annotations

import grp
import hashlib
import os
import pwd
import re
import secrets
import ssl
import subprocess
import sys
import time
from functools import partial
from pathlib import Path
from typing import Final, Protocol

from lowerduckpond_static_contracts import (
    ContractError,
    ProtocolError,
    validate_uuid7,
)
from lowerduckpond_static_domain import generate_uuid7

from lowerduckpond_static_host_agent.caddy_admin import verify_running_caddy
from lowerduckpond_static_host_agent.caddy_bootstrap import (
    ensure_platform_generation,
    platform_generation_state,
    require_exact_file,
)
from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_GENERATION_ROOT_MODE,
    MAX_CADDY_ENVIRONMENT_BYTES,
    CaddyBinarySource,
    CaddyGenerationStore,
)
from lowerduckpond_static_host_agent.caddy_routes import TENANT_RELEASE_ROOT
from lowerduckpond_static_host_agent.caddy_runtime import (
    CADDY_PUBLICATION_LOCK_MODE,
    CADDY_RUNTIME_ROOT_MODE,
    CaddyRuntime,
    CaddyRuntimeError,
    prepare_active_caddy_execution,
)
from lowerduckpond_static_host_agent.caddy_startup import (
    CaddyStartPhase,
    CaddyStartupError,
    CaddyStartupStore,
    start_target,
)
from lowerduckpond_static_host_agent.capacity import CapacityError
from lowerduckpond_static_host_agent.correlations import CorrelationError
from lowerduckpond_static_host_agent.execution import (
    AuthorizationExecutor,
    ExecutionError,
)
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
from lowerduckpond_static_host_agent.operator_adapter import (
    OperatorAdapter,
    OperatorAdapterError,
)
from lowerduckpond_static_host_agent.operator_stream import DeadlineReader, StreamError
from lowerduckpond_static_host_agent.release_tree import (
    ReleaseTreeError,
    measure_release_tree,
)
from lowerduckpond_static_host_agent.repository import StateRecordError, StateRepository
from lowerduckpond_static_host_agent.request_decoder import (
    RequestDecodeError,
    SubprocessRequestDecoder,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteSnapshotError,
    snapshot_tenant_routes,
)
from lowerduckpond_static_host_agent.state_inventory import StateInventoryError

_STATE_ROOT: Final = Path("/var/lib/lowerduckpond/static")
_DECODER: Final = Path("/usr/local/libexec/lowerduckpond/static-request-decoder")
_PUBLICATION_GATE: Final = Path("/usr/local/libexec/lowerduckpond/static-publication-gate")
_EXPECTED_OWNER: Final = 0
_PRINCIPAL_ARGUMENTS: Final = 2
_CADDY_RUNTIME_ROOT: Final = Path("/etc/caddy")
_CADDY_GENERATION_ROOT: Final = _CADDY_RUNTIME_ROOT / "generations"
_CADDY_INTENT_ROOT: Final = _CADDY_RUNTIME_ROOT / "intents"
_PUBLICATION_LOCK: Final = _STATE_ROOT / "locks/publication.lock"
_SYSTEMD_DESCRIPTOR_START: Final = 3
_CADDY_ACCOUNT: Final = "caddy"
_MAXIMUM_CA_PEM_BYTES: Final = 64 * 1024
_MAXIMUM_TENANT_RELEASES: Final = 3
_CADDY_BOOTSTRAP_MINIMUM_ARGUMENTS: Final = 5
_CADDY_ORIGIN_PULL_MODES: Final = {
    "--origin-pull-staged": False,
    "--origin-pull-required": True,
}


class _ReleaseStateTransaction(Protocol):
    def tenant_deployment_ids(self, tenant_id: object) -> tuple[str, ...]: ...


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
            AuthorizationExecutor(
                repository,
                intake,
                deleted_tenant_route_validator=partial(
                    _selected_tenant_routes_absent,
                    repository,
                ),
                tenant_runtime_validator=partial(
                    _selected_tenant_runtime_matches,
                    repository,
                ),
                tenant_release_validator=partial(
                    _selected_tenant_release_matches,
                    repository,
                ),
            ).execute(job_id, blocking=True)
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


def caddy_launcher_main(arguments: list[str] | None = None) -> int:
    """Exec the manifest-verified active generation from systemd's lock descriptor."""

    values = sys.argv[1:] if arguments is None else arguments
    if values:
        return _fail("invalid_caddy_launcher_invocation", 64)
    try:
        lock_descriptor = _systemd_publication_lock_descriptor()
        caddy_user = pwd.getpwnam(_CADDY_ACCOUNT)
        caddy_group = grp.getgrnam(_CADDY_ACCOUNT)
        with CaddyRuntime.from_lock_descriptor(
            _CADDY_RUNTIME_ROOT,
            lock_descriptor,
            expected_owner=0,
            expected_group=caddy_group.gr_gid,
            validation_uid=caddy_user.pw_uid,
            validation_gid=caddy_group.gr_gid,
            expected_binary_sha256=None,
            expected_lock_owner=0,
            expected_lock_group=0,
            root_mode=CADDY_RUNTIME_ROOT_MODE,
            lock_mode=CADDY_PUBLICATION_LOCK_MODE,
        ) as runtime:
            execution = prepare_active_caddy_execution(runtime)
        with execution:
            execution.execute(inherited_environment=os.environ)
    except KeyError, OSError, RuntimeError, ValueError:
        return _fail("caddy_generation_launch_failed", 1)
    return _fail("caddy_generation_launch_returned", 1)


def caddy_start_gate_main(arguments: list[str] | None = None) -> int:
    """Fence one bounded systemd start attempt to the exact active generation."""

    values = sys.argv[1:] if arguments is None else arguments
    try:
        _require_no_arguments(values)
        invocation_id = _systemd_invocation_id()
        with (
            _open_caddy_control_runtime() as runtime,
            CaddyStartupStore.open(_CADDY_INTENT_ROOT, expected_owner=0) as startup,
            runtime.locked(),
        ):
            startup.reconcile_temporaries()
            selected = runtime.open_active_verified()
            with selected.generation as generation:
                startup.prepare_start(
                    active=start_target(selected.generation_id, generation.manifest.to_bytes()),
                    invocation_id=invocation_id,
                )
    except KeyError, OSError, RuntimeError, ValueError:
        return _fail("caddy_start_gate_failed", 1)
    return 0


def caddy_start_verifier_main(arguments: list[str] | None = None) -> int:
    """Commit only the matching healthy systemd invocation after Caddy starts."""

    values = sys.argv[1:] if arguments is None else arguments
    try:
        _require_no_arguments(values)
        invocation_id = _systemd_invocation_id()
        with (
            _open_caddy_control_runtime() as runtime,
            CaddyStartupStore.open(_CADDY_INTENT_ROOT, expected_owner=0) as startup,
            runtime.locked(),
        ):
            startup.reconcile_temporaries()
            selected = runtime.open_active_verified()
            with selected.generation as generation:
                intent = startup.require_matching_success(
                    active=start_target(selected.generation_id, generation.manifest.to_bytes()),
                    invocation_id=invocation_id,
                )
                verify_running_caddy(generation)
                startup.commit_success(intent)
    except (
        ContractError,
        KeyError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        ValueError,
    ):
        return _fail("caddy_start_verification_failed", 1)
    return 0


def caddy_start_recovery_main(arguments: list[str] | None = None) -> int:
    """Select one durable predecessor after candidate attempts are exhausted."""

    values = sys.argv[1:] if arguments is None else arguments
    restart_required = False
    try:
        _require_no_arguments(values)
        with (
            _open_systemd_caddy_runtime() as runtime,
            CaddyStartupStore.open(_CADDY_INTENT_ROOT, expected_owner=0) as startup,
            runtime.locked(),
        ):
            startup.reconcile_temporaries()
            intent = startup.require_rollback_target()
            if intent is not None:
                if intent.previous is None:  # pragma: no cover - intent validation proves this
                    raise CaddyStartupError("rollback has no previous generation")
                runtime.select_active(intent.previous.generation_id)
                intent = startup.mark_rollback_restart_required(intent)
                restart_required = intent.phase is CaddyStartPhase.ROLLBACK_RESTART_REQUIRED
            else:
                startup.clear_exhausted_ordinary_start()
        if restart_required:
            subprocess.run(
                ["/usr/bin/systemctl", "reset-failed", "caddy.service"],
                check=True,
                timeout=10,
            )
            subprocess.run(
                ["/usr/bin/systemctl", "--no-block", "start", "caddy.service"],
                check=True,
                timeout=10,
            )
    except (
        KeyError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        ValueError,
    ):
        return _fail("caddy_start_recovery_failed", 1)
    return 0


def caddy_bootstrap_main(arguments: list[str] | None = None) -> int:
    """Create or verify the first production-dark complete generation."""

    values = sys.argv[1:] if arguments is None else arguments
    check_only = bool(values and values[0] == "--check")
    if check_only:
        values = values[1:]
    if (
        len(values) < _CADDY_BOOTSTRAP_MINIMUM_ARGUMENTS
        or values[0] not in _CADDY_ORIGIN_PULL_MODES
        or re.fullmatch(r"[0-9a-f]{64}", values[2]) is None
    ):
        return _fail("invalid_caddy_bootstrap_invocation", 64)
    origin_pull_required = _CADDY_ORIGIN_PULL_MODES[values[0]]
    binary_path = Path(values[1])
    expected_digest = values[2]
    environment_path = Path(values[3])
    ca_paths = tuple(Path(value) for value in values[4:])
    if not all(path.is_absolute() for path in (binary_path, environment_path, *ca_paths)):
        return _fail("invalid_caddy_bootstrap_invocation", 64)
    try:
        caddy_user = pwd.getpwnam(_CADDY_ACCOUNT)
        caddy_group = grp.getgrnam(_CADDY_ACCOUNT)
        binary = CaddyBinarySource(binary_path, owner=0, group=0, mode=0o755)
        if (
            _digest_bytes(
                require_exact_file(
                    binary_path,
                    owner=0,
                    group=0,
                    modes=(0o755,),
                    maximum_bytes=128 * 1024 * 1024,
                )
            )
            != expected_digest
        ):
            raise CaddyRuntimeError("trusted Caddy binary digest disagrees")
        environment = require_exact_file(
            environment_path,
            owner=0,
            group=caddy_group.gr_gid,
            modes=(0o640,),
            maximum_bytes=MAX_CADDY_ENVIRONMENT_BYTES,
        )
        origin_pull_ca_der = tuple(
            _pem_certificate_der(
                require_exact_file(
                    path,
                    owner=0,
                    group=caddy_group.gr_gid,
                    modes=(0o440,),
                    maximum_bytes=_MAXIMUM_CA_PEM_BYTES,
                )
            )
            for path in ca_paths
        )
        with (
            CaddyRuntime.open(
                _CADDY_RUNTIME_ROOT,
                _PUBLICATION_LOCK,
                expected_owner=0,
                expected_group=caddy_group.gr_gid,
                validation_uid=caddy_user.pw_uid,
                validation_gid=caddy_group.gr_gid,
                expected_binary_sha256=expected_digest,
                expected_lock_owner=0,
                expected_lock_group=0,
            ) as runtime,
            CaddyGenerationStore.open(
                _CADDY_GENERATION_ROOT,
                expected_owner=0,
                expected_group=caddy_group.gr_gid,
                expected_mode=CADDY_GENERATION_ROOT_MODE,
            ) as store,
            CaddyStartupStore.open(_CADDY_INTENT_ROOT, expected_owner=0) as startup,
        ):
            if check_only:
                state = platform_generation_state(
                    runtime,
                    store,
                    binary=binary,
                    environment=environment,
                    origin_pull_ca_der=origin_pull_ca_der,
                    origin_pull_required=origin_pull_required,
                    startup=startup,
                )
            else:
                changed = ensure_platform_generation(
                    runtime,
                    store,
                    generation_id=generate_uuid7(
                        clock=lambda: time.time_ns() // 1_000_000,
                        entropy=_entropy,
                    ),
                    binary=binary,
                    environment=environment,
                    origin_pull_ca_der=origin_pull_ca_der,
                    origin_pull_required=origin_pull_required,
                    startup=startup,
                )
    except (
        CaddyRuntimeError,
        ContractError,
        KeyError,
        OSError,
        RuntimeError,
        ValueError,
    ):
        return _fail("caddy_generation_bootstrap_failed", 1)
    if check_only:
        os.write(sys.stdout.fileno(), f"{state.value}\n".encode("ascii"))
    else:
        os.write(sys.stdout.fileno(), b"changed\n" if changed else b"unchanged\n")
    return 0


def _require_no_arguments(values: list[str]) -> None:
    if values:
        raise ValueError("invalid Caddy startup helper invocation")


def _systemd_invocation_id() -> str:
    value = os.environ.get("INVOCATION_ID", "")
    if re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise CaddyRuntimeError("systemd invocation ID is absent or invalid")
    return value


def _open_systemd_caddy_runtime() -> CaddyRuntime:
    lock_descriptor = _systemd_publication_lock_descriptor()
    caddy_user = pwd.getpwnam(_CADDY_ACCOUNT)
    caddy_group = grp.getgrnam(_CADDY_ACCOUNT)
    return CaddyRuntime.from_lock_descriptor(
        _CADDY_RUNTIME_ROOT,
        lock_descriptor,
        expected_owner=0,
        expected_group=caddy_group.gr_gid,
        validation_uid=caddy_user.pw_uid,
        validation_gid=caddy_group.gr_gid,
        expected_binary_sha256=None,
        expected_lock_owner=0,
        expected_lock_group=0,
        root_mode=CADDY_RUNTIME_ROOT_MODE,
        lock_mode=CADDY_PUBLICATION_LOCK_MODE,
    )


def _open_caddy_control_runtime() -> CaddyRuntime:
    """Open the validated lock path for systemd pre-start and post-start hooks.

    systemd supplies ``OpenFile=`` descriptors to the main ``ExecStart=`` process,
    but not to the privileged ``ExecStartPre=`` and ``ExecStartPost=`` control
    processes. The main launcher remains descriptor-pinned; these bounded hooks
    open the root-owned lock with the same no-follow metadata contract.
    """

    caddy_user = pwd.getpwnam(_CADDY_ACCOUNT)
    caddy_group = grp.getgrnam(_CADDY_ACCOUNT)
    return CaddyRuntime.open(
        _CADDY_RUNTIME_ROOT,
        _PUBLICATION_LOCK,
        expected_owner=0,
        expected_group=caddy_group.gr_gid,
        validation_uid=caddy_user.pw_uid,
        validation_gid=caddy_group.gr_gid,
        expected_binary_sha256=None,
        expected_lock_owner=0,
        expected_lock_group=0,
        root_mode=CADDY_RUNTIME_ROOT_MODE,
        lock_mode=CADDY_PUBLICATION_LOCK_MODE,
    )


def _selected_tenant_routes_absent(
    repository: StateRepository,
    tenant_id: str,
) -> bool:
    """Require the selected generation to equal complete post-delete state."""

    try:
        with (
            _open_caddy_control_runtime() as runtime,
            repository.publication_transaction(blocking=True) as transaction,
            runtime.using_held_publication_lock(repository),
        ):
            generation_id = runtime.read_active()
            snapshot = runtime.read_generation_route_snapshot(generation_id)
            expected = snapshot_tenant_routes(transaction)
    except (
        CaddyRuntimeError,
        KeyError,
        OSError,
        RouteSnapshotError,
        StateInventoryError,
        StateRecordError,
        TypeError,
        ValueError,
    ):
        return False
    if snapshot != expected:
        return False
    for tenant in expected.tenants:
        metadata = tenant.manifest.get("metadata")
        if type(metadata) is dict and metadata.get("id") == tenant_id:
            return False
    return True


def _selected_tenant_runtime_matches(  # noqa: PLR0911,PLR0913,PLR0917
    repository: StateRepository,
    tenant_id: str,
    route_set: str,
    generation_id: str | None,
    manifest: dict[str, object],
    observed_state: dict[str, object] | None,
) -> bool:
    """Bind one lifecycle candidate to the selected verified route snapshot."""

    if route_set not in {"absent", "both"}:
        return False
    try:
        with (
            _open_caddy_control_runtime() as runtime,
            repository.publication_transaction(blocking=True) as transaction,
            runtime.using_held_publication_lock(repository),
        ):
            active_generation_id = runtime.read_active()
            if generation_id is not None and active_generation_id != generation_id:
                return False
            snapshot = runtime.read_generation_route_snapshot(active_generation_id)
            expected = snapshot_tenant_routes(transaction)
            if snapshot != expected:
                return False
            matching = []
            for tenant in snapshot.tenants:
                metadata = tenant.manifest.get("metadata")
                if type(metadata) is dict and metadata.get("id") == tenant_id:
                    matching.append(tenant)
            if len(matching) != 1:
                return False
            tenant = matching[0]
            if tenant.manifest != manifest or (
                observed_state is not None and tenant.observed_state != observed_state
            ):
                return False
            spec = tenant.manifest.get("spec")
            observed = tenant.observed_state
            if type(spec) is not dict:
                return False
            if route_set == "both":
                return (
                    spec.get("desiredState") == "active"
                    and observed.get("observedState") == "active"
                    and observed.get("runtimeGenerationId") == generation_id
                )
            return (
                spec.get("desiredState") != "active"
                and observed.get("observedState") == spec.get("desiredState")
                and observed.get("runtimeGenerationId") is None
            )
    except (
        CaddyRuntimeError,
        KeyError,
        OSError,
        ReleaseTreeError,
        RouteSnapshotError,
        StateInventoryError,
        StateRecordError,
        TypeError,
        ValueError,
    ):
        return False


def _selected_tenant_release_matches(
    repository: StateRepository,
    tenant_id: str,
    manifest: dict[str, object],
) -> bool:
    """Bind selected release bytes and the release inventory to durable state."""

    try:
        with repository.publication_transaction(blocking=True) as transaction:
            expected = snapshot_tenant_routes(transaction)
            matching = []
            for tenant in expected.tenants:
                metadata = tenant.manifest.get("metadata")
                if type(metadata) is dict and metadata.get("id") == tenant_id:
                    matching.append(tenant)
            return (
                len(matching) == 1
                and matching[0].manifest == manifest
                and _tenant_release_state_matches(repository, transaction, matching[0])
            )
    except (
        KeyError,
        OSError,
        ReleaseTreeError,
        RouteSnapshotError,
        StateInventoryError,
        StateRecordError,
        TypeError,
        ValueError,
    ):
        return False


def _tenant_release_state_matches(  # noqa: PLR0911 - explicit fail-closed matrix
    repository: StateRepository,
    transaction: _ReleaseStateTransaction,
    tenant: object,
) -> bool:
    """Bind every local release to state and remeasure the selected release."""

    manifest = getattr(tenant, "manifest", None)
    deployment = getattr(tenant, "deployment", None)
    if type(manifest) is not dict:
        return False
    metadata = manifest.get("metadata")
    spec = manifest.get("spec")
    if type(metadata) is not dict or type(spec) is not dict:
        return False
    tenant_id = validate_uuid7(metadata.get("id"))
    deployment_ids = transaction.tenant_deployment_ids(tenant_id)
    release_ids = _tenant_release_ids(tenant_id)
    if not set(release_ids).issubset(deployment_ids):
        return False
    if spec.get("desiredState") not in {"active", "suspended"}:
        return True
    selected = spec.get("desiredDeployment")
    if type(selected) is not dict or type(deployment) is not dict:
        return False
    deployment_id = validate_uuid7(selected.get("id"))
    if deployment_id not in deployment_ids or deployment.get("id") != deployment_id:
        return False
    measurement = measure_release_tree(
        Path(TENANT_RELEASE_ROOT) / tenant_id / "releases" / deployment_id,
        lock_manager=repository,
        expected_owner=_EXPECTED_OWNER,
    )
    return measurement.digest.to_dict() == deployment.get("releaseTreeDigest")


def _tenant_release_ids(tenant_id: str) -> tuple[str, ...]:
    """Enumerate one bounded root-owned release namespace without following entries."""

    release_root = Path(TENANT_RELEASE_ROOT) / tenant_id / "releases"
    try:
        with os.scandir(release_root) as entries:
            found = tuple(sorted(entries, key=lambda entry: entry.name))
    except FileNotFoundError:
        return ()
    if len(found) > _MAXIMUM_TENANT_RELEASES:
        raise ReleaseTreeError("tenant release history exceeds its retention bound")
    identities: list[str] = []
    for entry in found:
        if not entry.is_dir(follow_symlinks=False):
            raise ReleaseTreeError("tenant release history contains a non-directory entry")
        try:
            identities.append(validate_uuid7(entry.name))
        except (TypeError, ValueError) as error:
            raise ReleaseTreeError("tenant release history has an invalid identity") from error
    return tuple(identities)


def _systemd_publication_lock_descriptor() -> int:
    if (
        os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "1"
        or os.environ.get("LISTEN_FDNAMES") != "publication-lock"
    ):
        raise CaddyRuntimeError("systemd did not pass the exact publication lock")
    return _SYSTEMD_DESCRIPTOR_START


def _pem_certificate_der(data: bytes) -> bytes:
    try:
        return ssl.PEM_cert_to_DER_cert(data.decode("ascii"))
    except (UnicodeError, ValueError) as error:
        raise CaddyRuntimeError("origin-pull CA is not one PEM certificate") from error


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fail(message: str, status: int) -> int:
    os.write(sys.stderr.fileno(), message.encode("ascii", errors="replace")[:256] + b"\n")
    return status
