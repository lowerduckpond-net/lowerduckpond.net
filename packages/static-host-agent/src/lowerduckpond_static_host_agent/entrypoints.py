"""Fixed installed entry points for SSH issuance, execution, and recovery."""

from __future__ import annotations

import grp
import hashlib
import os
import pwd
import re
import secrets
import ssl
import stat
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

from lowerduckpond_static_host_agent.caddy_admin import (
    CaddyAdminError,
    verify_starting_caddy,
)
from lowerduckpond_static_host_agent.caddy_bootstrap import (
    ensure_platform_generation,
    platform_generation_state,
    require_exact_file,
)
from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_GENERATION_ROOT_MODE,
    MAX_CADDY_ENVIRONMENT_BYTES,
    CaddyBinarySource,
    CaddyGenerationError,
    CaddyGenerationStore,
)
from lowerduckpond_static_host_agent.caddy_routes import TENANT_RELEASE_ROOT, TenantRouteInput
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
from lowerduckpond_static_host_agent.create_activate import CreateActivationError
from lowerduckpond_static_host_agent.create_commit import CreateCommitError
from lowerduckpond_static_host_agent.create_handler import (
    CreateLifecycleError,
    CreateLifecycleHandler,
)
from lowerduckpond_static_host_agent.create_prepare import CreatePreparationError
from lowerduckpond_static_host_agent.create_recover import CreateRecoveryError
from lowerduckpond_static_host_agent.deployment_activate import DeploymentActivationError
from lowerduckpond_static_host_agent.deployment_commit import DeploymentCommitError
from lowerduckpond_static_host_agent.deployment_handler import (
    DeploymentLifecycleError,
    DeploymentLifecycleHandler,
)
from lowerduckpond_static_host_agent.deployment_prepare import DeploymentPreparationError
from lowerduckpond_static_host_agent.deployment_recover import DeploymentRecoveryError
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
from lowerduckpond_static_host_agent.release_store import (
    DeploymentReleaseStore,
    ReleaseStoreError,
)
from lowerduckpond_static_host_agent.release_tree import (
    ReleaseTreeError,
    measure_release_tree,
)
from lowerduckpond_static_host_agent.repository import (
    StateRecordError,
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.request_decoder import (
    RequestDecodeError,
    SubprocessRequestDecoder,
)
from lowerduckpond_static_host_agent.route_activate import RouteActivationError
from lowerduckpond_static_host_agent.route_commit import RouteCommitError
from lowerduckpond_static_host_agent.route_handler import (
    RouteLifecycleError,
    RouteLifecycleHandler,
)
from lowerduckpond_static_host_agent.route_prepare import RoutePreparationError
from lowerduckpond_static_host_agent.route_recover import RouteRecoveryError
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteSnapshotError,
    RouteSnapshotTransaction,
    TenantRouteSnapshot,
    snapshot_tenant_authority,
    snapshot_tenant_routes,
)
from lowerduckpond_static_host_agent.state_inventory import (
    DEFAULT_STATE_INVENTORY_LIMITS,
    StateInventoryError,
)

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
_RELEASE_STAGING_NAME: Final = ".staging"
_RELEASE_STAGING_OWNER: Final = 0
_RELEASE_STAGING_GROUP: Final = 0
_RELEASE_STAGING_MODE: Final = 0o700
_CADDY_BOOTSTRAP_MINIMUM_ARGUMENTS: Final = 5
_CADDY_ORIGIN_PULL_MODES: Final = {
    "--origin-pull-staged": False,
    "--origin-pull-required": True,
}


class _ReleaseStateTransaction(Protocol):
    def read(self, path: StateRecordPath) -> StoredContract: ...

    def tenant_deployment_ids(self, tenant_id: object) -> tuple[str, ...]: ...


_SAFE_ERRORS: Final = (
    ContractError,
    CapacityError,
    CaddyAdminError,
    CaddyGenerationError,
    CaddyRuntimeError,
    CreateActivationError,
    CreateCommitError,
    CreateLifecycleError,
    CreatePreparationError,
    CreateRecoveryError,
    DeploymentActivationError,
    DeploymentCommitError,
    DeploymentLifecycleError,
    DeploymentPreparationError,
    DeploymentRecoveryError,
    RouteActivationError,
    RouteCommitError,
    RouteLifecycleError,
    RoutePreparationError,
    RouteRecoveryError,
    ProtocolError,
    CorrelationError,
    ExecutionError,
    IntakeError,
    IssuanceError,
    OperatorAdapterError,
    RequestDecodeError,
    ReleaseStoreError,
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
            _open_deployment_release_store() as release_store,
            _open_caddy_control_runtime() as runtime,
        ):
            publication_gate = CommandPublicationGate(_PUBLICATION_GATE)
            route_handler = RouteLifecycleHandler(repository, runtime, publication_gate)
            deployment_handler = DeploymentLifecycleHandler(
                repository,
                runtime,
                intake,
                release_store,
                publication_gate,
            )
            AuthorizationExecutor(
                repository,
                intake,
                handlers={
                    "create": CreateLifecycleHandler(
                        repository,
                        runtime,
                        publication_gate,
                    ),
                    "deploy": deployment_handler,
                    "rollback": deployment_handler,
                    "suspend": route_handler,
                    "resume": route_handler,
                    "rename": route_handler,
                    "reconcile": route_handler,
                },
                deleted_tenant_release_validator=partial(
                    _deleted_tenant_publication_absent,
                    repository,
                ),
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
                tenant_release_inventory_validator=partial(
                    _all_tenant_release_state_matches,
                    repository,
                ),
                tenant_runtime_inventory_validator=partial(
                    _all_tenant_runtime_state_matches,
                    repository,
                ),
            ).execute(job_id, blocking=True)
    except _SAFE_ERRORS:
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
                verify_starting_caddy(generation)
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


def _open_deployment_release_store() -> DeploymentReleaseStore:
    """Open the fixed production release and private staging roots."""

    caddy_group = grp.getgrnam(_CADDY_ACCOUNT)
    release_root = Path(TENANT_RELEASE_ROOT)
    return DeploymentReleaseStore(
        release_root,
        release_root / _RELEASE_STAGING_NAME,
        expected_owner=_RELEASE_STAGING_OWNER,
        expected_release_group=caddy_group.gr_gid,
        expected_staging_group=_RELEASE_STAGING_GROUP,
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


def _deleted_tenant_publication_absent(
    repository: StateRepository,
    tenant_id: str,
) -> bool:
    """Require the complete tenant publication namespace to be absent."""

    try:
        canonical_id = validate_uuid7(tenant_id)
        with repository.publication_transaction(blocking=True):
            try:
                (Path(TENANT_RELEASE_ROOT) / canonical_id).lstat()
            except FileNotFoundError:
                return True
            return False
    except OSError, StateRecordError, TypeError, ValueError:
        return False


def _selected_tenant_runtime_matches(  # noqa: PLR0911,PLR0913,PLR0917
    repository: StateRepository,
    tenant_id: str,
    route_set: str,
    generation_id: str | None,
    manifest: dict[str, object],
    observed_state: dict[str, object] | None,
    allow_reconcile_source_drift: bool = False,
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
            expected = (
                snapshot_tenant_routes(
                    transaction,
                    observed_drift_tenant_id=tenant_id,
                )
                if allow_reconcile_source_drift
                else snapshot_tenant_routes(transaction)
            )
            if snapshot != expected:
                return (
                    allow_reconcile_source_drift
                    and generation_id is not None
                    and observed_state is not None
                    and _reconcile_source_runtime_matches(
                        transaction,
                        snapshot,
                        expected,
                        tenant_id=tenant_id,
                        route_set=route_set,
                        manifest=manifest,
                        observed_state=observed_state,
                    )
                )
            matching = []
            for tenant in snapshot.tenants:
                metadata = tenant.manifest.get("metadata")
                if type(metadata) is dict and metadata.get("id") == tenant_id:
                    matching.append(tenant)
            manifest_spec = manifest.get("spec")
            if (
                not matching
                and route_set == "absent"
                and type(manifest_spec) is dict
                and manifest_spec.get("desiredState") == "archived"
                and observed_state is not None
            ):
                durable_manifest = transaction.read(
                    StateRecordPath.tenant_desired(tenant_id)
                ).document
                durable_observed = transaction.read(
                    StateRecordPath.tenant_observed(tenant_id)
                ).document
                return (
                    durable_manifest == manifest
                    and durable_observed == observed_state
                    and observed_state.get("observedState") == "archived"
                    and observed_state.get("runtimeGenerationId") is None
                )
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
                    and observed.get("runtimeGenerationId") is not None
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


def _reconcile_source_runtime_matches(  # noqa: PLR0911,PLR0913
    transaction: RouteSnapshotTransaction,
    selected: TenantRouteSnapshot,
    expected: TenantRouteSnapshot,
    *,
    tenant_id: str,
    route_set: str,
    manifest: dict[str, object],
    observed_state: dict[str, object],
) -> bool:
    """Validate a reconcile rollback against its bound immutable generation."""

    if selected.platform_namespace != expected.platform_namespace:
        return False
    durable_manifest = transaction.read(StateRecordPath.tenant_desired(tenant_id)).document
    durable_observed = transaction.read(StateRecordPath.tenant_observed(tenant_id)).document
    if durable_manifest != manifest or durable_observed != observed_state:
        return False
    selected_target, selected_others = _partition_runtime_snapshot(selected, tenant_id)
    _expected_target, expected_others = _partition_runtime_snapshot(expected, tenant_id)
    if selected_others != expected_others or len(selected_target) > 1:
        return False
    if not selected_target:
        return route_set == "absent"
    tenant = selected_target[0]
    spec = tenant.manifest.get("spec")
    observed = tenant.observed_state
    if type(spec) is not dict:
        return False
    if route_set == "both":
        return (
            spec.get("desiredState") == "active"
            and observed.get("observedState") == "active"
            and observed.get("runtimeGenerationId") is not None
        )
    return (
        route_set == "absent"
        and spec.get("desiredState") != "active"
        and observed.get("observedState") == spec.get("desiredState")
        and observed.get("runtimeGenerationId") is None
    )


def _partition_runtime_snapshot(
    snapshot: TenantRouteSnapshot,
    tenant_id: str,
) -> tuple[tuple[TenantRouteInput, ...], tuple[TenantRouteInput, ...]]:
    """Separate one tenant from an otherwise exact complete route snapshot."""

    target: list[TenantRouteInput] = []
    others: list[TenantRouteInput] = []
    for tenant in snapshot.tenants:
        metadata = tenant.manifest.get("metadata")
        if type(metadata) is not dict:
            raise RouteSnapshotError("runtime route metadata is malformed")
        (target if metadata.get("id") == tenant_id else others).append(tenant)
    return tuple(target), tuple(others)


def _selected_tenant_release_matches(
    repository: StateRepository,
    tenant_id: str,
    manifest: dict[str, object],
    allow_reconcile_source_drift: bool = False,
) -> bool:
    """Bind selected release bytes and the release inventory to durable state."""

    try:
        with repository.publication_transaction(blocking=True) as transaction:
            expected = (
                snapshot_tenant_authority(
                    transaction,
                    observed_drift_tenant_id=tenant_id,
                )
                if allow_reconcile_source_drift
                else snapshot_tenant_authority(transaction)
            )
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


def _all_tenant_release_state_matches(
    repository: StateRepository,
    observed_drift_tenant_id: str | None = None,
) -> bool:
    """Remeasure every tenant release while holding the publication lock."""

    try:
        with repository.publication_transaction(blocking=True) as transaction:
            expected = (
                snapshot_tenant_authority(
                    transaction,
                    observed_drift_tenant_id=observed_drift_tenant_id,
                )
                if observed_drift_tenant_id is not None
                else snapshot_tenant_authority(transaction)
            )
            authoritative_tenant_ids = {_snapshot_tenant_id(tenant) for tenant in expected.tenants}
            if not set(_tenant_release_namespace_ids()).issubset(authoritative_tenant_ids):
                return False
            return all(
                _tenant_release_state_matches(repository, transaction, tenant)
                for tenant in expected.tenants
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


def _all_tenant_runtime_state_matches(
    repository: StateRepository,
    observed_drift_tenant_id: str | None = None,
) -> bool:
    """Bind the selected runtime generation to all authoritative tenants."""

    try:
        with (
            _open_caddy_control_runtime() as runtime,
            repository.publication_transaction(blocking=True) as transaction,
            runtime.using_held_publication_lock(repository),
        ):
            active_generation_id = runtime.read_active()
            snapshot = (
                snapshot_tenant_routes(
                    transaction,
                    observed_drift_tenant_id=observed_drift_tenant_id,
                )
                if observed_drift_tenant_id is not None
                else snapshot_tenant_routes(transaction)
            )
            selected = runtime.read_generation_route_snapshot(active_generation_id)
            if observed_drift_tenant_id is None:
                return selected == snapshot
            if selected.platform_namespace != snapshot.platform_namespace:
                return False
            selected_target, selected_others = _partition_runtime_snapshot(
                selected,
                observed_drift_tenant_id,
            )
            expected_target, expected_others = _partition_runtime_snapshot(
                snapshot,
                observed_drift_tenant_id,
            )
            return (
                selected_others == expected_others
                and len(selected_target) <= 1
                and len(expected_target) <= 1
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
    if release_ids != deployment_ids:
        return False
    retained: dict[str, dict[str, object]] = {}
    for deployment_id in deployment_ids:
        record = transaction.read(
            StateRecordPath.tenant_deployment(tenant_id, deployment_id)
        ).document
        measurement = measure_release_tree(
            Path(TENANT_RELEASE_ROOT) / tenant_id / "releases" / deployment_id,
            lock_manager=repository,
            expected_owner=_EXPECTED_OWNER,
        )
        if measurement.digest.to_dict() != record.get("releaseTreeDigest"):
            return False
        retained[deployment_id] = record
    if spec.get("desiredState") not in {"active", "suspended"}:
        return True
    selected = spec.get("desiredDeployment")
    if type(selected) is not dict or type(deployment) is not dict:
        return False
    deployment_id = validate_uuid7(selected.get("id"))
    return deployment_id in retained and deployment == retained[deployment_id]


def _snapshot_tenant_id(tenant: object) -> str:
    manifest = getattr(tenant, "manifest", None)
    metadata = manifest.get("metadata") if type(manifest) is dict else None
    if type(metadata) is not dict:
        raise ReleaseTreeError("authoritative tenant snapshot has no identity")
    return validate_uuid7(metadata.get("id"))


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


def _tenant_release_namespace_ids() -> tuple[str, ...]:
    """Enumerate the complete bounded publication-root tenant namespace."""

    try:
        with os.scandir(TENANT_RELEASE_ROOT) as entries:
            found = tuple(sorted(entries, key=lambda entry: entry.name))
    except FileNotFoundError as error:
        raise ReleaseTreeError("tenant release root is absent") from error
    staging = tuple(entry for entry in found if entry.name == _RELEASE_STAGING_NAME)
    tenant_entries = tuple(entry for entry in found if entry.name != _RELEASE_STAGING_NAME)
    if len(staging) != 1:
        raise ReleaseTreeError("release staging root is absent")
    _validate_release_staging_root(staging[0])
    if len(tenant_entries) > DEFAULT_STATE_INVENTORY_LIMITS.maximum_tenants:
        raise ReleaseTreeError("tenant release namespace exceeds its tenant bound")
    identities: list[str] = []
    for entry in tenant_entries:
        if not entry.is_dir(follow_symlinks=False):
            raise ReleaseTreeError("tenant release namespace contains a non-directory entry")
        try:
            identities.append(validate_uuid7(entry.name))
        except (TypeError, ValueError) as error:
            raise ReleaseTreeError("tenant release namespace has an invalid identity") from error
        try:
            with os.scandir(entry.path) as children:
                tenant_entries = tuple(children)
        except OSError as error:
            raise ReleaseTreeError("tenant release namespace could not be inspected") from error
        if (
            len(tenant_entries) != 1
            or tenant_entries[0].name != "releases"
            or not tenant_entries[0].is_dir(follow_symlinks=False)
        ):
            raise ReleaseTreeError("tenant release namespace has an unexpected shape")
    return tuple(identities)


def _validate_release_staging_root(entry: os.DirEntry[str]) -> None:
    """Require the one reserved staging namespace to be private and quiescent."""

    if not entry.is_dir(follow_symlinks=False):
        raise ReleaseTreeError("release staging root has an unexpected type")
    try:
        metadata = entry.stat(follow_symlinks=False)
        with os.scandir(entry.path) as children:
            populated = next(children, None) is not None
    except OSError as error:
        raise ReleaseTreeError("release staging root could not be inspected") from error
    if (
        metadata.st_uid != _RELEASE_STAGING_OWNER
        or metadata.st_gid != _RELEASE_STAGING_GROUP
        or stat.S_IMODE(metadata.st_mode) != _RELEASE_STAGING_MODE
    ):
        raise ReleaseTreeError("release staging root metadata drifted")
    if populated:
        raise ReleaseTreeError("release staging root is not quiescent")


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
