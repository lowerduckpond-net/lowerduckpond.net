"""Fixed installed entry points for SSH issuance, execution, and recovery."""

from __future__ import annotations

import grp
import hashlib
import os
import pwd
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Final

from lowerduckpond_static_contracts import (
    ContractError,
    ProtocolError,
    canonical_json_bytes,
    decode_json_object,
    validate_uuid7,
)
from lowerduckpond_static_domain import generate_uuid7

from lowerduckpond_static_host_agent.caddy_bootstrap import (
    ensure_platform_generation,
    platform_generation_state,
    require_exact_file,
)
from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_BINARY_NAME,
    CADDY_CONFIGURATION_NAME,
    CADDY_GENERATION_ROOT_MODE,
    MAX_CADDY_CONFIGURATION_BYTES,
    MAX_CADDY_ENVIRONMENT_BYTES,
    CaddyBinarySource,
    CaddyGenerationStore,
    PinnedCaddyGeneration,
)
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
_CADDY_RUNTIME_ROOT: Final = Path("/etc/caddy")
_CADDY_GENERATION_ROOT: Final = _CADDY_RUNTIME_ROOT / "generations"
_CADDY_INTENT_ROOT: Final = _CADDY_RUNTIME_ROOT / "intents"
_PUBLICATION_LOCK: Final = _STATE_ROOT / "locks/publication.lock"
_SYSTEMD_DESCRIPTOR_START: Final = 3
_CADDY_ACCOUNT: Final = "caddy"
_MAXIMUM_CA_PEM_BYTES: Final = 64 * 1024
_CADDY_BOOTSTRAP_MINIMUM_ARGUMENTS: Final = 4
_CADDY_ADMIN_SOCKET: Final = Path("/run/caddy/admin.sock")
_CADDY_ADMIN_RESPONSE_BYTES: Final = MAX_CADDY_CONFIGURATION_BYTES + 64 * 1024

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
            _open_systemd_caddy_runtime() as runtime,
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
            _open_systemd_caddy_runtime() as runtime,
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
                _verify_running_caddy(generation)
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
        or re.fullmatch(r"[0-9a-f]{64}", values[1]) is None
    ):
        return _fail("invalid_caddy_bootstrap_invocation", 64)
    binary_path = Path(values[0])
    expected_digest = values[1]
    environment_path = Path(values[2])
    ca_paths = tuple(Path(value) for value in values[3:])
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
                    startup=startup,
                )
    except CaddyRuntimeError, ContractError, KeyError, OSError, RuntimeError, ValueError:
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


def _verify_running_caddy(generation: PinnedCaddyGeneration) -> None:
    manifest = generation.manifest
    expected = {item.name: item.sha256 for item in manifest.files}
    main_pid = subprocess.run(
        ["/usr/bin/systemctl", "show", "--property=MainPID", "--value", "caddy.service"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    ).stdout.strip()
    if not main_pid.isascii() or not main_pid.isdecimal() or int(main_pid) <= 1:
        raise CaddyRuntimeError("Caddy main PID is invalid")
    if _digest_running_executable(Path(f"/proc/{main_pid}/exe")) != expected[CADDY_BINARY_NAME]:
        raise CaddyRuntimeError("running Caddy binary disagrees with its generation")
    response = _read_caddy_admin_configuration()
    configuration = decode_json_object(response, maximum_bytes=MAX_CADDY_CONFIGURATION_BYTES)
    if _digest_bytes(canonical_json_bytes(configuration)) != expected[CADDY_CONFIGURATION_NAME]:
        raise CaddyRuntimeError("running Caddy configuration disagrees with its generation")


def _read_caddy_admin_configuration() -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(_CADDY_ADMIN_SOCKET))
        client.sendall(b"GET /config/ HTTP/1.0\r\nHost: localhost\r\n\r\n")
        chunks: list[bytes] = []
        total = 0
        while chunk := client.recv(64 * 1024):
            total += len(chunk)
            if total > _CADDY_ADMIN_RESPONSE_BYTES:
                raise CaddyRuntimeError("Caddy admin response exceeds its bound")
            chunks.append(chunk)
    head, separator, body = b"".join(chunks).partition(b"\r\n\r\n")
    if not separator or re.match(rb"HTTP/1\.[01] 200 ", head) is None:
        raise CaddyRuntimeError("Caddy admin health response is invalid")
    return body


def _digest_running_executable(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    digest = hashlib.sha256()
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or not 0 < metadata.st_size <= 128 * 1024 * 1024
        ):
            raise CaddyRuntimeError("running Caddy executable metadata is unsafe")
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise CaddyRuntimeError("running Caddy executable changed while reading")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CaddyRuntimeError("running Caddy executable exceeds its bound")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


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
