from __future__ import annotations

import fcntl
import hashlib
import os
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict, cast

import lowerduckpond_static_host_agent.caddy_generation as caddy_generation_module
import lowerduckpond_static_host_agent.caddy_runtime as caddy_runtime_module
import pytest
from lowerduckpond_static_contracts import (
    ContractKind,
    canonical_json_bytes,
    manifest_digest,
)
from lowerduckpond_static_host_agent import (
    CADDY_ACTIVE_REFERENCE_MODE,
    CADDY_ACTIVE_REFERENCE_NAME,
    CADDY_GENERATION_ROOT_MODE,
    CADDY_PUBLICATION_LOCK_MODE,
    CADDY_RUNTIME_ROOT_MODE,
    CaddyBinarySource,
    CaddyGenerationError,
    CaddyGenerationPayload,
    CaddyGenerationStore,
    CaddyRuntime,
    CaddyRuntimeError,
    CaddySelectionBoundary,
    ClosedPublicationGate,
    FilesystemCapacity,
    LockManager,
    LockMode,
    LockName,
    LockOrderError,
    PinnedCaddyGeneration,
    PublicationDisabledError,
    RouteOverlayMode,
    StateInventory,
    StateRecordPath,
    StateRepository,
    StateRevision,
    StoredContract,
    TenantRouteInput,
    TenantRouteOverlay,
    build_platform_only_caddy_routes,
    build_tenant_caddy_routes,
    caddy_route_state_digest,
    prepare_active_caddy_execution,
)

GENERATION_A = "0198d17f-6f4a-7000-8000-000000000001"
GENERATION_B = "0198d17f-6f4a-7000-8000-000000000002"
_ORIGIN_PULL_CA_DER = b"review-only-origin-pull-ca"
_TENANT_ID = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
_DEPLOYMENT_ID = "0191e2ca-49f2-7608-8cf3-f80ab2cab151"
_TENANT_GENERATION = "0198d17f-6f4a-7000-8000-000000000008"
_CADDY_VALIDATION_DATA_MODE = 0o770


def _accept_candidate(_generation: object, _environment: object) -> None:
    pass


def _allow_candidate_capacity(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
) -> None:
    monkeypatch.setattr(
        caddy_generation_module,
        "measure_filesystem_capacity_descriptor",
        lambda _descriptor: FilesystemCapacity(
            device=root.stat().st_dev,
            fragment_size=4096,
            total_blocks=10_000_000,
            available_blocks=9_000_000,
            total_inodes=1_000_000,
            available_inodes=900_000,
        ),
    )


def _configuration() -> dict[str, object]:
    return build_platform_only_caddy_routes(
        origin_pull_ca_der=(_ORIGIN_PULL_CA_DER,),
        origin_pull_required=True,
    ).configuration


def _tenant_routes(
    generation_id: str = _TENANT_GENERATION,
) -> tuple[dict[str, object], dict[str, object]]:
    generated = build_tenant_caddy_routes(
        platform_namespace=_platform_namespace(),
        tenants=(_tenant_input(),),
        runtime_generation_id=generation_id,
        origin_pull_ca_der=(_ORIGIN_PULL_CA_DER,),
        origin_pull_required=True,
    )
    return generated.configuration, generated.route_metadata


def _platform_namespace() -> dict[str, object]:
    return {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "PlatformNamespace",
        "tenantOriginSuffix": "lowerduckpond.com",
        "initializedAt": "2026-09-02T11:00:00Z",
    }


def _tenant_input() -> TenantRouteInput:
    manifest: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "Site",
        "metadata": {
            "id": _TENANT_ID,
            "slug": "duck-repair",
            "canonicalOrigin": ("t-0191e2c48f7a7c3b8d1e5f62047a2100.lowerduckpond.com"),
        },
        "spec": {
            "runtime": "static",
            "desiredState": "active",
            "desiredDeployment": {
                "id": _DEPLOYMENT_ID,
                "archiveSha256": "0" * 64,
            },
            "quotas": {"storageMiB": 100, "entries": 5000},
        },
    }
    observed: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "TenantObservedState",
        "tenantId": _TENANT_ID,
        "desiredManifestDigest": manifest_digest(manifest).to_dict(),
        "observedState": "active",
        "activeDeploymentId": _DEPLOYMENT_ID,
        "runtimeGenerationId": GENERATION_A,
        "reconciledAt": "2026-09-02T13:00:00Z",
    }
    deployment: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "DeploymentRecord",
        "id": _DEPLOYMENT_ID,
        "tenantId": _TENANT_ID,
        "archiveSha256": "0" * 64,
        "releaseTreeDigest": {
            "format": "lowerduckpond-release-tree-v1",
            "algorithm": "sha256",
            "value": "1" * 64,
        },
        "createdAt": "2026-09-02T12:00:00Z",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
    }
    return TenantRouteInput(manifest, observed, deployment)


def _archived_tenant_input() -> TenantRouteInput:
    tenant = _tenant_input()
    manifest = tenant.manifest
    observed = tenant.observed_state
    spec = cast(dict[str, object], manifest["spec"])
    spec["desiredState"] = "archived"
    observed["desiredManifestDigest"] = manifest_digest(manifest).to_dict()
    observed["observedState"] = "archived"
    observed["activeDeploymentId"] = None
    observed["runtimeGenerationId"] = None
    return TenantRouteInput(manifest, observed, tenant.deployment)


class _OpenGate:
    def require_enabled(self) -> None:
        return


class _RouteTransaction:
    def __init__(self, archived: TenantRouteInput | None = None) -> None:
        self.read_count = 0
        self.archived = archived

    def read(self, path: StateRecordPath) -> StoredContract:
        self.read_count += 1
        document: dict[str, object]
        kind: ContractKind
        if path == StateRecordPath.platform_namespace():
            document = _platform_namespace()
            kind = ContractKind.PLATFORM_NAMESPACE
        elif self.archived is not None:
            deployment = self.archived.deployment
            assert deployment is not None
            if path == StateRecordPath.tenant_desired(_TENANT_ID):
                document = self.archived.manifest
                kind = ContractKind.SITE
            elif path == StateRecordPath.tenant_observed(_TENANT_ID):
                document = self.archived.observed_state
                kind = ContractKind.TENANT_OBSERVED_STATE
            elif path == StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID):
                document = deployment
                kind = ContractKind.DEPLOYMENT_RECORD
            elif path == StateRecordPath.tenant_archive(_TENANT_ID, _DEPLOYMENT_ID):
                document = {
                    "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                    "kind": "ArchiveRecord",
                    "tenantId": _TENANT_ID,
                    "deploymentId": _DEPLOYMENT_ID,
                    "releaseTreeDigest": deployment["releaseTreeDigest"],
                    "manifestDigest": manifest_digest(self.archived.manifest).to_dict(),
                    "bundleDigest": {
                        "format": "lowerduckpond-archive-v1",
                        "algorithm": "sha256",
                        "value": "2" * 64,
                    },
                    "bundleSize": 4096,
                    "bucket": "lowerduckpond-net-production-tenant-archives-4f3e6b91",
                    "key": "archives/0198d17f-6f4a-7000-8000-000000000003.zip",
                    "versionId": "3LgY0Q5G-safe-fixture-version",
                    "createdAt": "2026-09-02T12:02:00Z",
                    "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
                }
                kind = ContractKind.ARCHIVE_RECORD
            else:
                raise AssertionError(f"unexpected state read: {path}")
        else:
            raise AssertionError(f"unexpected state read: {path}")
        encoded = canonical_json_bytes(document)
        return StoredContract(
            document,
            StateRevision(
                kind,
                len(encoded),
                hashlib.sha256(encoded).hexdigest(),
            ),
        )

    def measure_inventory(self) -> StateInventory:
        tenant_ids = () if self.archived is None else (_TENANT_ID,)
        return StateInventory(tenant_ids, 0, 0, 0, 0)

    @staticmethod
    def tenant_has_deployment_history(_tenant_id: object) -> bool:
        return False


def _candidate_inputs() -> tuple[_RouteTransaction, TenantRouteOverlay, _OpenGate]:
    return (
        _RouteTransaction(),
        TenantRouteOverlay(RouteOverlayMode.ADD, _tenant_input()),
        _OpenGate(),
    )


@dataclass(frozen=True)
class RuntimeFixture:
    root: Path
    lock: Path
    binary: Path
    binary_sha256: str
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
            expected_binary_sha256=self.binary_sha256,
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
            expected_binary_sha256=self.binary_sha256,
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

    routes = build_platform_only_caddy_routes(
        origin_pull_ca_der=(_ORIGIN_PULL_CA_DER,), origin_pull_required=True
    )
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
    return RuntimeFixture(
        root,
        lock,
        binary,
        hashlib.sha256(binary.read_bytes()).hexdigest(),
        owner,
        group,
    )


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


def test_runtime_composes_with_repository_publication_transaction(
    runtime_fixture: RuntimeFixture,
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    lock_root = state_root / "locks"
    lock_root.mkdir(mode=0o700)
    LockManager.initialize(lock_root, expected_owner=runtime_fixture.owner).close()

    with (
        StateRepository(state_root, expected_owner=runtime_fixture.owner) as repository,
        CaddyRuntime.open(
            runtime_fixture.root,
            lock_root / LockName.PUBLICATION.filename,
            expected_owner=runtime_fixture.owner,
            expected_group=runtime_fixture.group,
            validation_uid=runtime_fixture.owner,
            validation_gid=runtime_fixture.group,
            expected_binary_sha256=runtime_fixture.binary_sha256,
            candidate_validator=_accept_candidate,
        ) as runtime,
        repository.publication_transaction() as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        runtime.select_active(GENERATION_A)
        assert runtime.read_active() == GENERATION_A
        assert transaction is not None


def test_runtime_publishes_and_validates_one_unselected_derived_candidate(
    runtime_fixture: RuntimeFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_candidate_capacity(monkeypatch, runtime_fixture.root)
    transaction, overlay, gate = _candidate_inputs()
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        manifest = runtime.publish_candidate(
            _TENANT_GENERATION,
            transaction=transaction,
            overlay=overlay,
            gate=gate,
        )

        assert manifest.generation_id == _TENANT_GENERATION
        assert transaction.read_count == 1
        assert runtime.read_active() == GENERATION_A
        runtime.select_active(_TENANT_GENERATION)
        assert runtime.read_active() == _TENANT_GENERATION


def test_runtime_publishes_an_unrouted_archived_tenant_candidate(
    runtime_fixture: RuntimeFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_candidate_capacity(monkeypatch, runtime_fixture.root)
    archived = _archived_tenant_input()
    transaction = _RouteTransaction(archived)
    overlay = TenantRouteOverlay(RouteOverlayMode.REPLACE, archived, archived)
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        manifest = runtime.publish_candidate(
            _TENANT_GENERATION,
            transaction=transaction,
            overlay=overlay,
            gate=_OpenGate(),
        )

        snapshot = runtime.read_generation_route_snapshot(manifest.generation_id)
        assert snapshot.tenants == ()
        assert runtime.read_active() == GENERATION_A


def test_runtime_opens_one_explicit_verified_generation(
    runtime_fixture: RuntimeFixture,
) -> None:
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)

        with runtime.open_verified_generation(GENERATION_B) as generation:
            assert generation.manifest.generation_id == GENERATION_B

        assert runtime.read_active() == GENERATION_A


def test_runtime_reads_exact_tenant_snapshot_from_explicit_generation(
    runtime_fixture: RuntimeFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_candidate_capacity(monkeypatch, runtime_fixture.root)
    transaction, overlay, gate = _candidate_inputs()
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        runtime.publish_candidate(
            _TENANT_GENERATION,
            transaction=transaction,
            overlay=overlay,
            gate=gate,
        )

        snapshot = runtime.read_generation_route_snapshot(_TENANT_GENERATION)

        assert snapshot.platform_namespace == _platform_namespace()
        assert snapshot.tenants == (_tenant_input(),)
        assert runtime.read_active() == GENERATION_A


def test_runtime_rejects_a_platform_only_generation_as_tenant_snapshot(
    runtime_fixture: RuntimeFixture,
) -> None:
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)

        with pytest.raises(CaddyRuntimeError, match="no tenant route snapshot"):
            runtime.read_generation_route_snapshot(GENERATION_A)


def test_runtime_refuses_candidate_publication_while_the_gate_is_closed(
    runtime_fixture: RuntimeFixture,
) -> None:
    transaction, overlay, _gate = _candidate_inputs()
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        with pytest.raises(PublicationDisabledError, match="publication_disabled"):
            runtime.publish_candidate(
                _TENANT_GENERATION,
                transaction=transaction,
                overlay=overlay,
                gate=ClosedPublicationGate(),
            )

        assert runtime.read_active() == GENERATION_A
        assert transaction.read_count == 0
        assert not (runtime_fixture.root / "generations" / _TENANT_GENERATION).exists()


def test_runtime_removes_a_candidate_that_fails_validation(
    runtime_fixture: RuntimeFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_candidate_capacity(monkeypatch, runtime_fixture.root)

    def reject_candidate(generation: PinnedCaddyGeneration, _environment: object) -> None:
        if generation.manifest.generation_id == _TENANT_GENERATION:
            raise CaddyRuntimeError("injected candidate rejection")

    transaction, overlay, gate = _candidate_inputs()
    with (
        CaddyRuntime.open(
            runtime_fixture.root,
            runtime_fixture.lock,
            expected_owner=runtime_fixture.owner,
            expected_group=runtime_fixture.group,
            validation_uid=runtime_fixture.owner,
            validation_gid=runtime_fixture.group,
            expected_binary_sha256=runtime_fixture.binary_sha256,
            candidate_validator=reject_candidate,
        ) as runtime,
        runtime.locked(),
    ):
        runtime.select_active(GENERATION_A)
        with pytest.raises(CaddyRuntimeError, match="injected candidate rejection"):
            runtime.publish_candidate(
                _TENANT_GENERATION,
                transaction=transaction,
                overlay=overlay,
                gate=gate,
            )

        assert runtime.read_active() == GENERATION_A
        with pytest.raises(FileNotFoundError):
            runtime.select_active(_TENANT_GENERATION)


def test_runtime_discards_a_corrupt_candidate_after_validation_failure(
    runtime_fixture: RuntimeFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_candidate_capacity(monkeypatch, runtime_fixture.root)

    def corrupt_candidate(generation: PinnedCaddyGeneration, _environment: object) -> None:
        if generation.manifest.generation_id != _TENANT_GENERATION:
            return
        configuration = runtime_fixture.root / "generations" / _TENANT_GENERATION / "caddy.json"
        configuration.chmod(0o640)
        configuration.write_bytes(b"corrupt\n")
        configuration.chmod(0o440)
        raise CaddyRuntimeError("injected corruption")

    transaction, overlay, gate = _candidate_inputs()
    with (
        CaddyRuntime.open(
            runtime_fixture.root,
            runtime_fixture.lock,
            expected_owner=runtime_fixture.owner,
            expected_group=runtime_fixture.group,
            validation_uid=runtime_fixture.owner,
            validation_gid=runtime_fixture.group,
            expected_binary_sha256=runtime_fixture.binary_sha256,
            candidate_validator=corrupt_candidate,
        ) as runtime,
        runtime.locked(),
    ):
        runtime.select_active(GENERATION_A)
        with pytest.raises(CaddyRuntimeError, match="injected corruption"):
            runtime.publish_candidate(
                _TENANT_GENERATION,
                transaction=transaction,
                overlay=overlay,
                gate=gate,
            )

        assert runtime.read_active() == GENERATION_A
        assert not (runtime_fixture.root / "generations" / _TENANT_GENERATION).exists()
        with CaddyGenerationStore.open(
            runtime_fixture.root / "generations",
            expected_owner=runtime_fixture.owner,
            expected_group=runtime_fixture.group,
        ) as store:
            assert store.list_verified() == (
                GENERATION_A,
                GENERATION_B,
            )


def test_runtime_counts_every_existing_generation_before_candidate_admission(
    runtime_fixture: RuntimeFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_candidate_capacity(monkeypatch, runtime_fixture.root)
    next_generation = "0198d17f-6f4a-7000-8000-000000000009"
    transaction, overlay, gate = _candidate_inputs()
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        runtime.publish_candidate(
            _TENANT_GENERATION,
            transaction=transaction,
            overlay=overlay,
            gate=gate,
        )
        with pytest.raises(CaddyGenerationError, match="no Caddy generation slot"):
            runtime.publish_candidate(
                next_generation,
                transaction=transaction,
                overlay=overlay,
                gate=gate,
            )


def test_runtime_discards_only_an_exact_unselected_candidate(
    runtime_fixture: RuntimeFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_candidate_capacity(monkeypatch, runtime_fixture.root)
    transaction, overlay, gate = _candidate_inputs()
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        manifest = runtime.publish_candidate(
            _TENANT_GENERATION,
            transaction=transaction,
            overlay=overlay,
            gate=gate,
        )

        runtime.discard_unselected_candidate(_TENANT_GENERATION, manifest)

        assert runtime.read_active() == GENERATION_A
        with pytest.raises(FileNotFoundError):
            runtime.select_active(_TENANT_GENERATION)


def test_runtime_refuses_to_discard_an_active_generation(
    runtime_fixture: RuntimeFixture,
) -> None:
    with (
        CaddyGenerationStore.open(
            runtime_fixture.root / "generations",
            expected_owner=runtime_fixture.owner,
            expected_group=runtime_fixture.group,
        ) as store,
        store.open_verified(GENERATION_A) as generation,
    ):
        manifest = generation.manifest

    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        with pytest.raises(CaddyRuntimeError, match="cannot discard the active"):
            runtime.discard_unselected_candidate(GENERATION_A, manifest)

        assert runtime.read_active() == GENERATION_A


def test_runtime_prunes_only_generations_outside_active_and_recovery_set(
    runtime_fixture: RuntimeFixture,
) -> None:
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)

        assert runtime.prune_unreferenced_generations((GENERATION_B,)) == ()
        assert runtime.read_active() == GENERATION_A
        assert runtime.prune_unreferenced_generations(()) == (GENERATION_B,)
        assert runtime.read_active() == GENERATION_A

    with CaddyGenerationStore.open(
        runtime_fixture.root / "generations",
        expected_owner=runtime_fixture.owner,
        expected_group=runtime_fixture.group,
    ) as store:
        assert store.list_verified() == (GENERATION_A,)


def test_runtime_can_retain_one_last_known_good_generation(
    runtime_fixture: RuntimeFixture,
) -> None:
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)

        assert runtime.prune_unreferenced_generations((), keep_newest_unprotected=1) == ()

    with CaddyGenerationStore.open(
        runtime_fixture.root / "generations",
        expected_owner=runtime_fixture.owner,
        expected_group=runtime_fixture.group,
    ) as store:
        assert store.list_verified() == (GENERATION_A, GENERATION_B)


def test_runtime_generation_pruning_requires_publication_lock(
    runtime_fixture: RuntimeFixture,
) -> None:
    with (
        runtime_fixture.open() as runtime,
        pytest.raises(CaddyRuntimeError, match="publication lock"),
    ):
        runtime.prune_unreferenced_generations(())


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
                expected_binary_sha256=runtime_fixture.binary_sha256,
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


def test_selection_authenticates_the_binary_before_candidate_execution(
    runtime_fixture: RuntimeFixture,
    tmp_path: Path,
) -> None:
    generation_id = "0198d17f-6f4a-7000-8000-000000000008"
    untrusted_binary = tmp_path / "untrusted-caddy"
    untrusted_binary.write_bytes(Path("/usr/bin/false").read_bytes())
    untrusted_binary.chmod(0o755)
    routes = build_platform_only_caddy_routes(
        origin_pull_ca_der=(_ORIGIN_PULL_CA_DER,), origin_pull_required=True
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
                    untrusted_binary,
                    owner=runtime_fixture.owner,
                    group=runtime_fixture.group,
                ),
                environment=b"CLOUDFLARE_API_TOKEN=real-secret\n",
                configuration=_configuration(),
                route_metadata=routes.route_metadata,
            ),
        )

    candidate_executed = False

    def record_candidate(_generation: object, _environment: object) -> None:
        nonlocal candidate_executed
        candidate_executed = True

    with (
        CaddyRuntime.open(
            runtime_fixture.root,
            runtime_fixture.lock,
            expected_owner=runtime_fixture.owner,
            expected_group=runtime_fixture.group,
            validation_uid=runtime_fixture.owner,
            validation_gid=runtime_fixture.group,
            expected_binary_sha256=runtime_fixture.binary_sha256,
            candidate_validator=record_candidate,
        ) as runtime,
        runtime.locked(),
    ):
        runtime.select_active(GENERATION_A)
        candidate_executed = False
        with pytest.raises(CaddyRuntimeError, match="trusted digest"):
            runtime.select_active(generation_id)
        assert not candidate_executed
        assert runtime.read_active() == GENERATION_A


def test_launcher_reauthenticates_the_active_binary_against_the_external_digest(
    runtime_fixture: RuntimeFixture,
) -> None:
    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)

    with (
        CaddyRuntime.open(
            runtime_fixture.root,
            runtime_fixture.lock,
            expected_owner=runtime_fixture.owner,
            expected_group=runtime_fixture.group,
            validation_uid=runtime_fixture.owner,
            validation_gid=runtime_fixture.group,
            expected_binary_sha256="0" * 64,
            candidate_validator=_accept_candidate,
        ) as runtime,
        pytest.raises(CaddyRuntimeError, match="trusted digest"),
    ):
        prepare_active_caddy_execution(runtime)


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


@pytest.mark.parametrize(
    ("binary_path", "expected_returncode"),
    [(Path("/usr/bin/true"), 0), (Path("/usr/bin/false"), 1)],
)
def test_candidate_validation_tears_down_every_completed_command(
    runtime_fixture: RuntimeFixture,
    monkeypatch: pytest.MonkeyPatch,
    binary_path: Path,
    expected_returncode: int,
) -> None:
    calls: list[str | None] = []
    original = caddy_runtime_module._kill_validation_process

    def record_teardown(
        process: subprocess.Popen[bytes],
        *,
        scope_unit: str | None,
    ) -> None:
        calls.append(scope_unit)
        original(process, scope_unit=scope_unit)

    monkeypatch.setattr(caddy_runtime_module, "_kill_validation_process", record_teardown)
    descriptor = os.open(binary_path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        result = caddy_runtime_module._run_validation_command(
            descriptor,
            [],
            environment={},
            inherited_descriptors=(),
            validation_uid=runtime_fixture.owner,
            validation_gid=runtime_fixture.group,
        )
    finally:
        os.close(descriptor)

    assert result.returncode == expected_returncode
    assert calls == [None]


def test_scope_teardown_requires_an_inactive_or_removed_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Process:
        pid = 999_999_999
        returncode = 0

        @staticmethod
        def kill() -> None:
            raise ProcessLookupError

        @staticmethod
        def wait(*, timeout: int) -> int:
            assert timeout > 0
            return 0

    commands: list[list[str]] = []
    process_groups: list[int] = []

    def run(arguments: list[str], **_options: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(arguments)
        stdout = b"LoadState=not-found\nActiveState=inactive\n" if "show" in arguments else b""
        return subprocess.CompletedProcess(arguments, 0, stdout=stdout)

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(os, "killpg", lambda pid, _signal: process_groups.append(pid))

    caddy_runtime_module._kill_validation_process(
        cast("subprocess.Popen[bytes]", Process()),
        scope_unit="lowerduckpond-caddy-validation-0123456789abcdef.scope",
    )

    assert [command[1] for command in commands] == ["kill", "stop", "show"]
    assert process_groups == []


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
        "--slice=lowerduckpond-static-workers.slice",
        "--collect",
        "--expand-environment=no",
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
        "--no-new-privs",
        "--",
        "/usr/bin/prlimit",
        "--core=0",
        "--cpu=15",
        "--fsize=16777216",
        "--memlock=0",
        "--nofile=64",
        "--stack=16777216",
        "--",
        "/usr/bin/bash",
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
        data_root = Path(data_roots.pop())
        assert data_root.is_dir()
        assert data_root.stat().st_mode & 0o777 == _CADDY_VALIDATION_DATA_MODE
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
    assert "CLOUDFLARE_API_TOKEN" not in isolated_environments[0]
    assert isolated_environments[1]["CLOUDFLARE_API_TOKEN"] == "0" * 40
    assert all("token-b" not in environment.values() for environment in isolated_environments)
    assert Path(validation_directory).parent.parent == Path("/", "dev", "shm")
    assert not Path(validation_directory).exists()


def test_selection_and_launch_reject_configuration_that_disagrees_with_route_state(
    runtime_fixture: RuntimeFixture,
) -> None:
    generation_id = "0198d17f-6f4a-7000-8000-000000000006"
    generated = build_platform_only_caddy_routes(
        origin_pull_ca_der=(_ORIGIN_PULL_CA_DER,), origin_pull_required=True
    )
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
                environment=b"CLOUDFLARE_API_TOKEN=token-a\nXDG_CONFIG_HOME=/etc/caddy\n",
                configuration=configuration,
                route_metadata=generated.route_metadata,
            ),
        )

    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        with pytest.raises(CaddyRuntimeError, match="route state disagree"):
            runtime.select_active(generation_id)
        assert runtime.read_active() == GENERATION_A

    reference = runtime_fixture.root / CADDY_ACTIVE_REFERENCE_NAME
    reference.write_bytes(f"{generation_id}\n".encode())
    with (
        runtime_fixture.open() as runtime,
        pytest.raises(CaddyRuntimeError, match="route state disagree"),
    ):
        prepare_active_caddy_execution(runtime)


def test_selection_and_launch_independently_rederive_tenant_capable_routes(
    runtime_fixture: RuntimeFixture,
) -> None:
    configuration, route_metadata = _tenant_routes()
    with CaddyGenerationStore.open(
        runtime_fixture.root / "generations",
        expected_owner=runtime_fixture.owner,
        expected_group=runtime_fixture.group,
    ) as store:
        store.publish(
            _TENANT_GENERATION,
            CaddyGenerationPayload(
                binary=CaddyBinarySource(
                    runtime_fixture.binary,
                    owner=runtime_fixture.owner,
                    group=runtime_fixture.group,
                ),
                environment=b"CLOUDFLARE_API_TOKEN=token-a\nXDG_CONFIG_HOME=/etc/caddy\n",
                configuration=configuration,
                route_metadata=route_metadata,
            ),
        )

    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(_TENANT_GENERATION)
        selected = runtime.open_active_verified()
        try:
            assert selected.generation_id == _TENANT_GENERATION
        finally:
            selected.generation.close()

    with (
        runtime_fixture.open() as runtime,
        prepare_active_caddy_execution(runtime) as prepared,
    ):
        descriptor = prepared.duplicate_configuration_descriptor()
        try:
            assert os.read(descriptor, os.fstat(descriptor).st_size) == canonical_json_bytes(
                configuration
            )
        finally:
            os.close(descriptor)


@pytest.mark.parametrize("mismatch", ["generation", "route-set"])
def test_selection_rejects_self_consistent_but_false_tenant_route_metadata(
    runtime_fixture: RuntimeFixture,
    mismatch: str,
) -> None:
    configuration, route_metadata = _tenant_routes()
    route_state = route_metadata["routeState"]
    assert type(route_state) is dict
    if mismatch == "generation":
        route_state["runtimeGenerationId"] = GENERATION_B
    else:
        tenant_states = route_state["tenantStates"]
        assert type(tenant_states) is list
        tenant_state = tenant_states[0]
        assert type(tenant_state) is dict
        tenant_state["routeSet"] = "absent"
    route_metadata["routeStateDigest"] = caddy_route_state_digest(route_state).to_dict()

    with CaddyGenerationStore.open(
        runtime_fixture.root / "generations",
        expected_owner=runtime_fixture.owner,
        expected_group=runtime_fixture.group,
    ) as store:
        store.publish(
            _TENANT_GENERATION,
            CaddyGenerationPayload(
                binary=CaddyBinarySource(
                    runtime_fixture.binary,
                    owner=runtime_fixture.owner,
                    group=runtime_fixture.group,
                ),
                environment=b"CLOUDFLARE_API_TOKEN=token-a\nXDG_CONFIG_HOME=/etc/caddy\n",
                configuration=configuration,
                route_metadata=route_metadata,
            ),
        )

    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        with pytest.raises(CaddyRuntimeError, match="route"):
            runtime.select_active(_TENANT_GENERATION)
        assert runtime.read_active() == GENERATION_A


@pytest.mark.parametrize("mismatch", ["tcp-admin", "additional-app"])
def test_selection_rejects_non_allowlisted_control_plane_configuration(
    runtime_fixture: RuntimeFixture,
    mismatch: str,
) -> None:
    generation_id = "0198d17f-6f4a-7000-8000-000000000007"
    generated = build_platform_only_caddy_routes(
        origin_pull_ca_der=(_ORIGIN_PULL_CA_DER,), origin_pull_required=True
    )
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
                environment=b"CLOUDFLARE_API_TOKEN=token-a\nXDG_CONFIG_HOME=/etc/caddy\n",
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
    routes = build_platform_only_caddy_routes(
        origin_pull_ca_der=(_ORIGIN_PULL_CA_DER,), origin_pull_required=True
    )
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
    "environment",
    [
        b"XDG_CONFIG_HOME=/etc/caddy\n",
        b"CLOUDFLARE_API_TOKEN=\nXDG_CONFIG_HOME=/etc/caddy\n",
    ],
)
def test_selection_rejects_a_missing_or_empty_dns_credential(
    runtime_fixture: RuntimeFixture,
    environment: bytes,
) -> None:
    generations = runtime_fixture.root / "generations"
    routes = build_platform_only_caddy_routes(
        origin_pull_ca_der=(_ORIGIN_PULL_CA_DER,), origin_pull_required=True
    )
    generation_id = "0198d17f-6f4a-7000-8000-000000000005"
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
                environment=environment,
                configuration=_configuration(),
                route_metadata=routes.route_metadata,
            ),
        )

    with runtime_fixture.open() as runtime, runtime.locked():
        runtime.select_active(GENERATION_A)
        with pytest.raises(CaddyRuntimeError, match="no DNS credential"):
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
