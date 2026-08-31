from __future__ import annotations

import fcntl
import os
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

import lowerduckpond_static_host_agent.caddy_runtime as caddy_runtime_module
import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import (
    CADDY_ACTIVE_REFERENCE_MODE,
    CADDY_ACTIVE_REFERENCE_NAME,
    CADDY_GENERATION_ROOT_MODE,
    CADDY_PUBLICATION_LOCK_MODE,
    CADDY_RUNTIME_ROOT_MODE,
    CaddyBinarySource,
    CaddyGenerationPayload,
    CaddyGenerationStore,
    CaddyRuntime,
    CaddyRuntimeError,
    CaddySelectionBoundary,
    LockManager,
    LockMode,
    LockName,
    LockOrderError,
    build_platform_only_caddy_routes,
    prepare_active_caddy_execution,
)

GENERATION_A = "0198d17f-6f4a-7000-8000-000000000001"
GENERATION_B = "0198d17f-6f4a-7000-8000-000000000002"


def _accept_candidate(_generation: object, _environment: object) -> None:
    pass


def _configuration() -> dict[str, object]:
    return build_platform_only_caddy_routes().configuration


@dataclass(frozen=True)
class RuntimeFixture:
    root: Path
    lock: Path
    binary: Path
    owner: int
    group: int

    def open(self) -> CaddyRuntime:
        return CaddyRuntime.open(
            self.root,
            self.lock,
            expected_owner=self.owner,
            expected_group=self.group,
            validation_uid=self.owner,
            validation_gid=self.group,
            candidate_validator=_accept_candidate,
        )

    def open_validating(self) -> CaddyRuntime:
        return CaddyRuntime.open(
            self.root,
            self.lock,
            expected_owner=self.owner,
            expected_group=self.group,
            validation_uid=self.owner,
            validation_gid=self.group,
        )


class CapturedExecution(TypedDict, total=False):
    binary: bytes
    arguments: list[str]
    configuration: bytes
    configuration_fd: int
    configuration_inheritable: bool
    environment: dict[str, str]


@pytest.fixture
def runtime_fixture(tmp_path: Path) -> RuntimeFixture:
    owner = os.geteuid()
    group = os.getegid()
    root = tmp_path / "runtime"
    generations = root / "generations"
    root.mkdir(mode=CADDY_RUNTIME_ROOT_MODE)
    generations.mkdir(mode=CADDY_GENERATION_ROOT_MODE)
    lock = tmp_path / "publication.lock"
    lock.write_bytes(b"")
    lock.chmod(CADDY_PUBLICATION_LOCK_MODE)
    binary = tmp_path / "caddy"
    binary.write_bytes(Path("/usr/bin/true").read_bytes())
    binary.chmod(0o755)

    routes = build_platform_only_caddy_routes()
    with CaddyGenerationStore.open(
        generations,
        expected_owner=owner,
        expected_group=group,
    ) as store:
        for generation_id, marker in ((GENERATION_A, "a"), (GENERATION_B, "b")):
            store.publish(
                generation_id,
                CaddyGenerationPayload(
                    binary=CaddyBinarySource(binary, owner=owner, group=group),
                    environment=(
                        f"CLOUDFLARE_API_TOKEN=token-{marker}\n"
                        "XDG_CONFIG_HOME=/etc/caddy\n"
                        "XDG_DATA_HOME=/var/lib/caddy\n"
                    ).encode(),
                    configuration=_configuration(),
                    route_metadata=routes.route_metadata,
                ),
            )
    return RuntimeFixture(root, lock, binary, owner, group)


def test_selection_requires_the_publication_lock(
    runtime_fixture: RuntimeFixture,
) -> None:
    with runtime_fixture.open() as runtime:
        with pytest.raises(CaddyRuntimeError, match="publication lock is required"):
            runtime.select_active(GENERATION_A)
        with pytest.raises(CaddyRuntimeError, match="publication lock is required"):
            runtime.read_active()


def test_publication_lock_authority_is_bound_to_the_owning_thread(
    runtime_fixture: RuntimeFixture,
) -> None:
    failures: list[BaseException] = []

    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)

        def select_from_non_owner() -> None:
            try:
                runtime.select_active(GENERATION_B)
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=select_from_non_owner)
        thread.start()
        thread.join(2)

        assert not thread.is_alive()
        assert len(failures) == 1
        assert isinstance(failures[0], CaddyRuntimeError)
        assert str(failures[0]) == "publication lock is required"
        assert runtime.read_active() == GENERATION_A


def test_runtime_holds_the_exact_publication_lock_inode(
    runtime_fixture: RuntimeFixture,
) -> None:
    competing_fd = os.open(runtime_fixture.lock, os.O_RDWR | os.O_CLOEXEC)
    try:
        with (
            runtime_fixture.open() as runtime,
            runtime.locked(),
            pytest.raises(BlockingIOError),
        ):
            fcntl.flock(competing_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(competing_fd)


def test_same_runtime_serializes_concurrent_in_process_callers(
    runtime_fixture: RuntimeFixture,
) -> None:
    first_entered = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    second_entered = threading.Event()
    failures: list[BaseException] = []

    with runtime_fixture.open() as runtime:

        def first() -> None:
            try:
                with runtime.locked():
                    first_entered.set()
                    if not release_first.wait(2):
                        raise RuntimeError("test did not release first caller")
            except BaseException as error:
                failures.append(error)

        def second() -> None:
            try:
                if not first_entered.wait(2):
                    raise RuntimeError("first caller did not enter")
                second_started.set()
                with runtime.locked():
                    second_entered.set()
            except BaseException as error:
                failures.append(error)

        first_thread = threading.Thread(target=first)
        second_thread = threading.Thread(target=second)
        first_thread.start()
        second_thread.start()
        assert first_entered.wait(2)
        assert second_started.wait(2)
        assert not second_entered.wait(0.1)
        release_first.set()
        first_thread.join(2)
        second_thread.join(2)

    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert not failures
    assert second_entered.is_set()


def test_runtime_composes_with_the_same_lock_already_held_by_lock_manager(
    runtime_fixture: RuntimeFixture,
) -> None:
    with (
        LockManager(runtime_fixture.lock.parent, expected_owner=runtime_fixture.owner) as locks,
        runtime_fixture.open() as runtime,
        locks.acquire(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE, blocking=True),
        runtime.using_held_publication_lock(locks),
    ):
        runtime.select_active(GENERATION_A)
        assert runtime.read_active() == GENERATION_A


def test_held_lock_context_fails_busy_instead_of_inverting_the_process_mutex(
    runtime_fixture: RuntimeFixture,
) -> None:
    contender_started = threading.Event()
    contender_entered = threading.Event()
    failures: list[BaseException] = []
    with (
        LockManager(runtime_fixture.lock.parent, expected_owner=runtime_fixture.owner) as locks,
        runtime_fixture.open() as runtime,
        locks.acquire(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE, blocking=True),
    ):

        def contender() -> None:
            try:
                contender_started.set()
                with runtime.locked():
                    contender_entered.set()
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=contender)
        thread.start()
        assert contender_started.wait(2)
        assert not contender_entered.wait(0.1)
        with (
            pytest.raises(CaddyRuntimeError, match="busy in this process"),
            runtime.using_held_publication_lock(locks),
        ):
            pass

    thread.join(2)
    assert not thread.is_alive()
    assert not failures
    assert contender_entered.is_set()


def test_runtime_refuses_a_different_managers_held_publication_inode(
    runtime_fixture: RuntimeFixture,
    tmp_path: Path,
) -> None:
    other = tmp_path / "other-locks"
    other.mkdir(mode=0o700)
    for name in LockName:
        path = other / name.filename
        path.write_bytes(b"")
        path.chmod(0o600)
    with (
        LockManager(other, expected_owner=runtime_fixture.owner) as locks,
        runtime_fixture.open() as runtime,
        locks.acquire(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE, blocking=True),
        pytest.raises(LockOrderError, match="held inode does not match"),
        runtime.using_held_publication_lock(locks),
    ):
        pass


def test_runtime_accepts_a_preopened_root_owned_publication_lock_descriptor(
    runtime_fixture: RuntimeFixture,
) -> None:
    descriptor = os.open(runtime_fixture.lock, os.O_RDWR | os.O_CLOEXEC)
    os.set_inheritable(descriptor, True)
    try:
        with (
            CaddyRuntime.from_lock_descriptor(
                runtime_fixture.root,
                descriptor,
                expected_owner=runtime_fixture.owner,
                expected_group=runtime_fixture.group,
                validation_uid=runtime_fixture.owner,
                validation_gid=runtime_fixture.group,
                expected_lock_owner=runtime_fixture.owner,
                expected_lock_group=runtime_fixture.group,
                candidate_validator=_accept_candidate,
            ) as runtime,
            runtime.locked(),
        ):
            runtime.select_active(GENERATION_A)
            assert runtime.read_active() == GENERATION_A
            assert not os.get_inheritable(descriptor)
    finally:
        os.close(descriptor)


def test_selection_verifies_and_durably_replaces_one_regular_reference(
    runtime_fixture: RuntimeFixture,
) -> None:
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        assert runtime.read_active() == GENERATION_A
        runtime.select_active(GENERATION_B)
        assert runtime.read_active() == GENERATION_B

    reference = runtime_fixture.root / CADDY_ACTIVE_REFERENCE_NAME
    metadata = reference.stat(follow_symlinks=False)
    assert reference.read_bytes() == f"{GENERATION_B}\n".encode()
    assert metadata.st_uid == runtime_fixture.owner
    assert metadata.st_gid == runtime_fixture.group
    assert metadata.st_mode & 0o777 == CADDY_ACTIVE_REFERENCE_MODE
    assert metadata.st_nlink == 1
    assert not list(runtime_fixture.root.glob(".ldp-active-*"))


def test_selection_refuses_an_unverified_or_non_uuid_generation(
    runtime_fixture: RuntimeFixture,
) -> None:
    with runtime_fixture.open() as runtime, runtime.locked():
        with pytest.raises(FileNotFoundError):
            runtime.select_active("0198d17f-6f4a-7000-8000-000000000003")
        with pytest.raises(CaddyRuntimeError, match="UUIDv7"):
            runtime.select_active("not-a-generation")


@pytest.mark.parametrize("boundary", list(CaddySelectionBoundary))
def test_selection_failure_injection_never_leaves_a_temporary_reference(
    runtime_fixture: RuntimeFixture,
    boundary: CaddySelectionBoundary,
) -> None:
    def fail(current: CaddySelectionBoundary) -> None:
        if current == boundary:
            raise RuntimeError(current)

    with runtime_fixture.open() as runtime:
        with runtime.locked(), pytest.raises(RuntimeError, match=boundary.value):
            runtime.select_active(GENERATION_A, failure_hook=fail)
        with runtime.locked():
            if boundary == CaddySelectionBoundary.REFERENCE_SYNC:
                with pytest.raises(FileNotFoundError):
                    runtime.read_active()
            else:
                assert runtime.read_active() == GENERATION_A

    assert not list(runtime_fixture.root.glob(".ldp-active-*"))


def test_failed_pre_rename_reselection_preserves_the_preceding_reference(
    runtime_fixture: RuntimeFixture,
) -> None:
    def fail(boundary: CaddySelectionBoundary) -> None:
        if boundary == CaddySelectionBoundary.REFERENCE_SYNC:
            raise RuntimeError(boundary)

    with runtime_fixture.open() as runtime:
        with runtime.locked():
            runtime.select_active(GENERATION_A)
        with runtime.locked(), pytest.raises(RuntimeError):
            runtime.select_active(GENERATION_B, failure_hook=fail)
        with runtime.locked():
            assert runtime.read_active() == GENERATION_A


def test_selection_reconciles_and_syncs_safe_crash_left_reference_staging(
    runtime_fixture: RuntimeFixture,
) -> None:
    abandoned = runtime_fixture.root / (".ldp-active-" + "a" * 32)
    abandoned.write_bytes(f"{GENERATION_B}\n".encode())
    abandoned.chmod(CADDY_ACTIVE_REFERENCE_MODE)

    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        assert runtime.read_active() == GENERATION_A

    assert not abandoned.exists()


@pytest.mark.parametrize("kind", ["malformed", "symlink", "hardlink"])
def test_reference_recovery_refuses_unsafe_reserved_temporaries(
    runtime_fixture: RuntimeFixture,
    kind: str,
) -> None:
    name = ".ldp-active-malformed" if kind == "malformed" else ".ldp-active-" + "b" * 32
    temporary = runtime_fixture.root / name
    if kind == "symlink":
        temporary.symlink_to("generations")
    else:
        temporary.write_bytes(b"")
        temporary.chmod(0o600)
        if kind == "hardlink":
            os.link(temporary, runtime_fixture.root / "temporary-alias")

    with (
        runtime_fixture.open() as runtime,
        runtime.locked(),
        pytest.raises(CaddyRuntimeError, match="temporary"),
    ):
        runtime.remove_abandoned_reference_temporaries()


def test_reference_recovery_scan_is_bounded_before_removal(
    runtime_fixture: RuntimeFixture,
) -> None:
    abandoned = runtime_fixture.root / (".ldp-active-" + "c" * 32)
    abandoned.write_bytes(b"")
    abandoned.chmod(0o600)
    with (
        runtime_fixture.open() as runtime,
        runtime.locked(),
        pytest.raises(CaddyRuntimeError, match="recovery scan bound"),
    ):
        runtime.remove_abandoned_reference_temporaries(maximum_entries=0)
    assert abandoned.exists()


def test_active_reference_rejects_symlinks_and_multiply_linked_files(
    runtime_fixture: RuntimeFixture,
) -> None:
    reference = runtime_fixture.root / CADDY_ACTIVE_REFERENCE_NAME
    with runtime_fixture.open() as runtime:
        with runtime.locked():
            runtime.select_active(GENERATION_A)
        reference.unlink()
        reference.symlink_to("generations")
        with runtime.locked(), pytest.raises(CaddyRuntimeError, match="no-follow"):
            runtime.read_active()

        reference.unlink()
        reference.write_bytes(f"{GENERATION_A}\n".encode())
        reference.chmod(CADDY_ACTIVE_REFERENCE_MODE)
        os.link(reference, runtime_fixture.root / "active-alias")
        with runtime.locked(), pytest.raises(CaddyRuntimeError, match="metadata"):
            runtime.read_active()


def test_prepared_execution_stays_on_one_generation_after_reference_replacement(
    runtime_fixture: RuntimeFixture,
) -> None:
    with runtime_fixture.open() as runtime:
        with runtime.locked():
            runtime.select_active(GENERATION_A)
        with prepare_active_caddy_execution(runtime) as prepared:
            with runtime.locked():
                runtime.select_active(GENERATION_B)
            descriptor = prepared.duplicate_configuration_descriptor()
            try:
                assert os.read(descriptor, 65_536) == canonical_json_bytes(_configuration())
            finally:
                os.close(descriptor)
            assert prepared.generation_id == GENERATION_A


def test_launcher_executes_open_binary_and_configuration_with_bounded_environment(
    runtime_fixture: RuntimeFixture,
) -> None:
    captured: CapturedExecution = {}

    def fake_execve(
        binary_fd: int,
        arguments: list[str],
        environment: dict[str, str],
    ) -> None:
        captured["binary"] = os.pread(binary_fd, os.fstat(binary_fd).st_size, 0)
        captured["arguments"] = arguments
        captured["configuration"] = Path(arguments[-1]).read_bytes()
        configuration_fd = int(arguments[-1].rsplit("/", 1)[1])
        captured["configuration_fd"] = configuration_fd
        captured["configuration_inheritable"] = os.get_inheritable(configuration_fd)
        captured["environment"] = environment

    with runtime_fixture.open() as runtime:
        with runtime.locked():
            runtime.select_active(GENERATION_A)
        with prepare_active_caddy_execution(runtime) as prepared:
            with pytest.raises(CaddyRuntimeError, match="unexpectedly returned"):
                prepared.execute(
                    inherited_environment={
                        "HOME": "/should/not/pass",
                        "LISTEN_FDNAMES": "publication-lock",
                        "LISTEN_FDS": "1",
                        "LISTEN_PID": str(os.getpid()),
                        "NOTIFY_SOCKET": "/run/systemd/notify",
                        "INVOCATION_ID": "a" * 32,
                    },
                    execve=fake_execve,
                )
            assert not os.get_inheritable(captured["configuration_fd"])

    assert captured["binary"] == runtime_fixture.binary.read_bytes()
    assert captured["arguments"][:3] == ["caddy", "run", "--config"]
    assert captured["configuration"] == canonical_json_bytes(_configuration())
    assert captured["configuration_inheritable"] is True
    assert captured["environment"] == {
        "CLOUDFLARE_API_TOKEN": "token-a",
        "INVOCATION_ID": "a" * 32,
        "NOTIFY_SOCKET": "/run/systemd/notify",
        "XDG_CONFIG_HOME": "/etc/caddy",
        "XDG_DATA_HOME": "/var/lib/caddy",
    }


def test_launcher_executes_the_selected_binary_by_descriptor(
    runtime_fixture: RuntimeFixture,
) -> None:
    with runtime_fixture.open() as runtime:
        with runtime.locked():
            runtime.select_active(GENERATION_A)
        with prepare_active_caddy_execution(runtime) as prepared:
            child = os.fork()
            if child == 0:
                try:
                    prepared.execute(inherited_environment={})
                except BaseException:
                    os._exit(120)
            waited, status = os.waitpid(child, 0)

    assert waited == child
    assert os.waitstatus_to_exitcode(status) == 0


def test_selection_rejects_a_non_caddy_executable_and_preserves_active(
    runtime_fixture: RuntimeFixture,
) -> None:
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)

    with runtime_fixture.open_validating() as runtime, runtime.locked():
        with pytest.raises(CaddyRuntimeError, match="required module"):
            runtime.select_active(GENERATION_B)
        assert runtime.read_active() == GENERATION_A


def test_selection_bounds_output_from_an_invalid_candidate(
    runtime_fixture: RuntimeFixture,
) -> None:
    descriptor = os.open("/usr/bin/python3", os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(CaddyRuntimeError, match="output exceeded its limit"):
            caddy_runtime_module._run_validation_command(
                descriptor,
                ["-c", "while True: print('unbounded candidate output')"],
                environment={},
                inherited_descriptors=(),
                validation_uid=runtime_fixture.owner,
                validation_gid=runtime_fixture.group,
            )
    finally:
        os.close(descriptor)


def test_root_candidate_validation_has_exact_descendant_resource_boundaries() -> None:
    invocation = caddy_runtime_module._validation_invocation(
        17,
        ["validate", "--config", "/proc/self/fd/18"],
        validation_uid=997,
        validation_gid=998,
        root_execution=True,
        scope_suffix="0123456789abcdef",
    )

    assert invocation.scope_unit == ("lowerduckpond-caddy-validation-0123456789abcdef.scope")
    assert invocation.command == (
        "/usr/bin/systemd-run",
        "--quiet",
        "--scope",
        "--collect",
        "--unit=lowerduckpond-caddy-validation-0123456789abcdef",
        "--property",
        "MemoryMax=256M",
        "--property",
        "MemorySwapMax=0",
        "--property",
        "TasksMax=32",
        "--property",
        "CPUQuota=100%",
        "--property",
        "RuntimeMaxSec=30s",
        "--property",
        "OOMPolicy=kill",
        "--property",
        "KillMode=control-group",
        "--",
        "/usr/bin/setpriv",
        "--reuid=997",
        "--regid=998",
        "--clear-groups",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        "--",
        "/usr/bin/prlimit",
        "--as=536870912",
        "--core=0",
        "--cpu=15",
        "--fsize=16777216",
        "--memlock=0",
        "--nofile=64",
        "--stack=16777216",
        "--",
        "/bin/bash",
        "-c",
        'exec -a caddy "/proc/self/fd/$1" "${@:2}"',
        "lowerduckpond-caddy-validation",
        "17",
        "validate",
        "--config",
        "/proc/self/fd/18",
    )


def test_selection_rejects_configuration_the_pinned_binary_cannot_load(
    runtime_fixture: RuntimeFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)

    isolated_environments: list[dict[str, str]] = []

    def run(
        _binary_fd: int,
        arguments: list[str],
        **options: object,
    ) -> subprocess.CompletedProcess[bytes]:
        environment = options["environment"]
        assert type(environment) is dict
        isolated_environments.append(environment)
        data_roots = {
            environment[name] for name in ("HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME")
        }
        assert len(data_roots) == 1
        assert Path(data_roots.pop()).is_dir()
        assert options["validation_uid"] == runtime_fixture.owner
        assert options["validation_gid"] == runtime_fixture.group
        if arguments[0] == "list-modules":
            return subprocess.CompletedProcess(
                arguments,
                0,
                stdout=b"dns.providers.cloudflare\n",
            )
        return subprocess.CompletedProcess(arguments, 1, stdout=b"")

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.caddy_runtime._run_validation_command",
        run,
    )

    with runtime_fixture.open_validating() as runtime, runtime.locked():
        with pytest.raises(CaddyRuntimeError, match="configuration is invalid"):
            runtime.select_active(GENERATION_B)
        assert runtime.read_active() == GENERATION_A
    validation_directory = isolated_environments[0]["TMPDIR"]
    assert [item["TMPDIR"] for item in isolated_environments] == [
        validation_directory,
        validation_directory,
    ]
    assert Path(validation_directory).parent.parent == Path("/", "dev", "shm")
    assert not Path(validation_directory).exists()


def test_selection_rejects_configuration_that_disagrees_with_route_state(
    runtime_fixture: RuntimeFixture,
) -> None:
    generation_id = "0198d17f-6f4a-7000-8000-000000000006"
    generated = build_platform_only_caddy_routes()
    configuration = _configuration()
    apps = configuration["apps"]
    assert type(apps) is dict
    http = apps["http"]
    assert type(http) is dict
    servers = http["servers"]
    assert type(servers) is dict
    production = servers["production"]
    assert type(production) is dict
    routes = production["routes"]
    assert type(routes) is list
    routes.insert(
        0,
        {
            "handle": [{"body": "unauthorized", "handler": "static_response"}],
            "match": [{"host": ["tenant.lowerduckpond.com"]}],
            "terminal": True,
        },
    )
    with CaddyGenerationStore.open(
        runtime_fixture.root / "generations",
        expected_owner=runtime_fixture.owner,
        expected_group=runtime_fixture.group,
    ) as store:
        store.publish(
            generation_id,
            CaddyGenerationPayload(
                binary=CaddyBinarySource(
                    runtime_fixture.binary,
                    owner=runtime_fixture.owner,
                    group=runtime_fixture.group,
                ),
                environment=b"XDG_CONFIG_HOME=/etc/caddy\n",
                configuration=configuration,
                route_metadata=generated.route_metadata,
            ),
        )

    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        with pytest.raises(CaddyRuntimeError, match="route state disagree"):
            runtime.select_active(generation_id)
        assert runtime.read_active() == GENERATION_A


@pytest.mark.parametrize("mismatch", ["tcp-admin", "additional-app"])
def test_selection_rejects_non_allowlisted_control_plane_configuration(
    runtime_fixture: RuntimeFixture,
    mismatch: str,
) -> None:
    generation_id = "0198d17f-6f4a-7000-8000-000000000007"
    generated = build_platform_only_caddy_routes()
    configuration = _configuration()
    if mismatch == "tcp-admin":
        configuration["admin"] = {"listen": "0.0.0.0:2019"}
    else:
        apps = configuration["apps"]
        assert type(apps) is dict
        apps["tls"] = {"automation": {}}
    with CaddyGenerationStore.open(
        runtime_fixture.root / "generations",
        expected_owner=runtime_fixture.owner,
        expected_group=runtime_fixture.group,
    ) as store:
        store.publish(
            generation_id,
            CaddyGenerationPayload(
                binary=CaddyBinarySource(
                    runtime_fixture.binary,
                    owner=runtime_fixture.owner,
                    group=runtime_fixture.group,
                ),
                environment=b"XDG_CONFIG_HOME=/etc/caddy\n",
                configuration=configuration,
                route_metadata=generated.route_metadata,
            ),
        )

    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        with pytest.raises(CaddyRuntimeError, match="route state disagree"):
            runtime.select_active(generation_id)
        assert runtime.read_active() == GENERATION_A


@pytest.mark.parametrize(
    "assignment",
    [
        "NOTIFY_SOCKET=/attacker-controlled",
        "LISTEN_FDS=1",
        "LISTEN_FDNAMES=publication-lock",
        f"LISTEN_PID={os.getpid()}",
        "LD_PRELOAD=/attacker-controlled",
    ],
)
def test_selection_rejects_systemd_environment_override_and_preserves_active(
    runtime_fixture: RuntimeFixture,
    assignment: str,
) -> None:
    generations = runtime_fixture.root / "generations"
    routes = build_platform_only_caddy_routes()
    generation_id = "0198d17f-6f4a-7000-8000-000000000004"
    with CaddyGenerationStore.open(
        generations,
        expected_owner=runtime_fixture.owner,
        expected_group=runtime_fixture.group,
    ) as store:
        store.publish(
            generation_id,
            CaddyGenerationPayload(
                binary=CaddyBinarySource(
                    runtime_fixture.binary,
                    owner=runtime_fixture.owner,
                    group=runtime_fixture.group,
                ),
                environment=f"{assignment}\n".encode(),
                configuration=_configuration(),
                route_metadata=routes.route_metadata,
            ),
        )

    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        with pytest.raises(CaddyRuntimeError, match="forbidden name"):
            runtime.select_active(generation_id)
        assert runtime.read_active() == GENERATION_A


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda path: path.chmod(0o660), "publication lock metadata"),
        (lambda path: path.write_bytes(b"occupied"), "publication lock metadata"),
        (
            lambda path: os.link(path, path.with_name("lock-alias")),
            "publication lock metadata",
        ),
    ],
)
def test_runtime_refuses_unsafe_publication_lock_metadata(
    runtime_fixture: RuntimeFixture,
    mutate: Callable[[Path], object],
    message: str,
) -> None:
    mutate(runtime_fixture.lock)
    with pytest.raises(CaddyRuntimeError, match=message):
        runtime_fixture.open()
