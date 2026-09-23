"""Build and select a fresh complete runtime solely from reviewed host inputs."""

from __future__ import annotations

import hashlib
import os
import ssl
import stat
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from lowerduckpond_static_domain import generate_uuid7

from lowerduckpond_static_host_agent.caddy_bootstrap import require_exact_file
from lowerduckpond_static_host_agent.caddy_generation import (
    MAX_CADDY_BINARY_BYTES,
    MAX_CADDY_ENVIRONMENT_BYTES,
    CaddyBinarySource,
    CaddyGenerationPayload,
    CaddyGenerationStore,
)
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.caddy_startup import (
    CaddyStartMode,
    CaddyStartPhase,
    CaddyStartupStore,
    start_target,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_inputs import (
    INPUT_ROOT,
    RestoreInputs,
    file_sha256,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_mapping import (
    RuntimeMapping,
    _read_inputs,
    apply_runtime_mapping,
    commit_runtime_mapping,
    prepare_runtime_inputs,
)
from lowerduckpond_static_host_agent.host_restore_materialize import _private_target
from lowerduckpond_static_host_agent.repository import StateRepository
from lowerduckpond_static_host_agent.route_snapshot import snapshot_tenant_routes

MAX_CA_BYTES = 32 * 1024


def _entropy(length: int) -> bytes:
    return os.urandom(length)


def _generation_id() -> str:
    return generate_uuid7(clock=lambda: time.time_ns() // 1_000_000, entropy=_entropy)


@dataclass(frozen=True)
class TrustedCaddy:
    binary: CaddyBinarySource
    environment: bytes = field(repr=False)
    original_ca: tuple[bytes, ...]
    current_ca: tuple[bytes, ...]
    current_pem: tuple[bytes, ...]

    def require_inputs(self, inputs: RestoreInputs) -> None:
        policy = inputs.caddy
        if (
            file_sha256(
                self.binary.path,
                owner=self.binary.owner,
                group=self.binary.group,
                mode=self.binary.mode,
                maximum=MAX_CADDY_BINARY_BYTES,
            )
            != policy["binarySha256"]
            or hashlib.sha256(self.environment).hexdigest() != policy["environmentSha256"]
            or [hashlib.sha256(value).hexdigest() for value in self.original_ca]
            != policy["originalOriginPullCaSha256"]
            or [hashlib.sha256(value).hexdigest() for value in self.current_ca]
            != policy["originPullCaSha256"]
            or tuple(ssl.PEM_cert_to_DER_cert(value.decode("ascii")) for value in self.current_pem)
            != self.current_ca
        ):
            raise HostRestoreError("restore_runtime_trusted_files_changed")

    @classmethod
    def load(
        cls,
        inputs: RestoreInputs,
        *,
        caddy_group: int,
        root: Path = Path("/etc/caddy"),
        input_root: Path = INPUT_ROOT,
        owner: int = 0,
    ) -> TrustedCaddy:
        current = tuple(
            require_exact_file(
                root / f"origin-pull-ca-{index}.pem",
                owner=owner,
                group=caddy_group,
                modes=(0o440,),
                maximum_bytes=MAX_CA_BYTES,
            )
            for index in range(len(cast(list[str], inputs.caddy["originPullCaSha256"])))
        )
        original = tuple(
            require_exact_file(
                input_root / f"original-origin-pull-ca-{index}.pem",
                owner=owner,
                group=owner,
                modes=(0o600,),
                maximum_bytes=MAX_CA_BYTES,
            )
            for index in range(len(cast(list[str], inputs.caddy["originalOriginPullCaSha256"])))
        )
        result = cls(
            CaddyBinarySource(
                Path(str(inputs.caddy["binaryPath"])), owner=owner, group=owner, mode=0o755
            ),
            require_exact_file(
                root / "environment",
                owner=owner,
                group=caddy_group,
                modes=(0o640,),
                maximum_bytes=MAX_CADDY_ENVIRONMENT_BYTES,
            ),
            tuple(ssl.PEM_cert_to_DER_cert(value.decode("ascii")) for value in original),
            tuple(ssl.PEM_cert_to_DER_cert(value.decode("ascii")) for value in current),
            current,
        )
        result.require_inputs(inputs)
        return result


def _directory(parent: int, name: str, *, owner: int, group: int, mode: int) -> None:
    with suppress(FileExistsError):
        os.mkdir(name, mode=0o700, dir_fd=parent)
    descriptor = os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != owner
            or metadata.st_gid not in {owner, group}
            or stat.S_IMODE(metadata.st_mode) not in {0o700, mode}
        ):
            raise HostRestoreError("restore_runtime_directory_unsafe")
        os.fchown(descriptor, owner, group)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        os.fsync(parent)
    finally:
        os.close(descriptor)


def _input(  # noqa: PLR0913 - exact input bytes and complete inode policy
    directory: DurableDirectory, name: str, raw: bytes, *, owner: int, group: int, mode: int
) -> None:
    parent = directory.duplicate_descriptor()
    descriptor = -1
    try:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            # Uniform private creation mode keeps all abandoned publication
            # temporaries safely classifiable after an interrupted input copy.
            directory.create_immutable((name,), raw, mode=0o600)
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
        )
        metadata = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner
            or metadata.st_gid not in {owner, group}
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) not in {0o600, mode}
            or metadata.st_size != len(raw)
            or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
            or directory.read_regular(
                (name,),
                expected_owner=owner,
                expected_mode=stat.S_IMODE(metadata.st_mode),
                maximum_bytes=len(raw),
            )
            != raw
        ):
            raise HostRestoreError("restore_runtime_input_copy_changed")
        os.fchown(descriptor, owner, group)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        os.fsync(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _layout(store: RestoreStore, root: Path, files: TrustedCaddy, group: int) -> None:
    _private_target(store, "caddy", root, {"owner": store.owner, "group": group, "mode": 0o750})
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fchown(descriptor, store.owner, group)
        os.fchmod(descriptor, 0o750)
        os.fsync(descriptor)
        for name, mode, child_group in (
            ("generations", 0o750, group),
            ("intents", 0o700, store.owner),
            ("routes.d", 0o750, group),
        ):
            _directory(descriptor, name, owner=store.owner, group=child_group, mode=mode)
    finally:
        os.close(descriptor)
    with DurableDirectory.open(
        root, expected_owner=store.owner, expected_directory_mode=0o750
    ) as directory:
        directory.remove_abandoned_publication_temporaries(
            expected_owner=store.owner, expected_mode=0o600, maximum_entries=64
        )
        expected = {
            "active",
            "generations",
            "intents",
            "routes.d",
            "environment",
            *(f"origin-pull-ca-{index}.pem" for index in range(len(files.current_pem))),
        }
        descriptor = directory.duplicate_descriptor()
        try:
            with os.scandir(descriptor) as entries:
                if any(entry.name not in expected for entry in entries):
                    raise HostRestoreError("restore_runtime_layout_unclassified")
        finally:
            os.close(descriptor)
        _input(
            directory, "environment", files.environment, owner=store.owner, group=group, mode=0o640
        )
        for index, pem in enumerate(files.current_pem):
            _input(
                directory,
                f"origin-pull-ca-{index}.pem",
                pem,
                owner=store.owner,
                group=group,
                mode=0o440,
            )
        with directory.open_descendant(("routes.d",)) as routes:
            descriptor = routes.duplicate_descriptor()
            try:
                with os.scandir(descriptor) as entries:
                    if next(entries, None) is not None:
                        raise HostRestoreError("restore_runtime_legacy_routes_present")
            finally:
                os.close(descriptor)


def prepare_restored_runtime(  # noqa: PLR0913,PLR0917 - complete trusted inputs and private destination
    store: RestoreStore,
    repository: StateRepository,
    root: Path,
    publication_lock: Path,
    descriptor: dict[str, object],
    inputs: RestoreInputs,
    files: TrustedCaddy,
    *,
    caddy_uid: int,
    caddy_gid: int,
    generation_id: Callable[[], str] = _generation_id,
    failure_hook: Callable[[str], None] = lambda _boundary: None,
) -> RuntimeMapping:
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.RECONCILED:
        raise HostRestoreError("restore_runtime_requires_reconciled_state")
    files.require_inputs(inputs)
    try:
        plan = _read_inputs(store)
    except FileNotFoundError:
        with repository.publication_transaction() as transaction:
            snapshot = snapshot_tenant_routes(transaction)
        plan = prepare_runtime_inputs(
            store,
            snapshot,
            descriptor,
            inputs,
            generation_id(),
            files.original_ca,
            files.current_ca,
        )
    plan.require_journal(journal)
    if (
        plan.trusted.digest != inputs.digest
        or plan.document["backupDescriptor"] != descriptor
        or plan.original_ca != files.original_ca
        or plan.current_ca != files.current_ca
    ):
        raise HostRestoreError("restore_runtime_prepared_inputs_changed")
    _layout(store, root, files, caddy_gid)
    failure_hook("layout")
    routes = plan.routes()
    payload = CaddyGenerationPayload(
        files.binary, files.environment, routes.configuration, routes.route_metadata
    )
    with (
        CaddyRuntime.open(
            root,
            publication_lock,
            expected_owner=store.owner,
            expected_group=caddy_gid,
            validation_uid=caddy_uid,
            validation_gid=caddy_gid,
            expected_binary_sha256=str(inputs.caddy["binarySha256"]),
            expected_lock_owner=store.owner,
            expected_lock_group=store.owner,
        ) as runtime,
        CaddyGenerationStore.open(
            root / "generations", expected_owner=store.owner, expected_group=caddy_gid
        ) as generations,
        CaddyStartupStore.open(root / "intents", expected_owner=store.owner) as startup,
        repository.publication_transaction() as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        generations.remove_abandoned_temporaries()
        retained = generations.list_verified()
        if retained not in ((), (plan.generation_id,)):
            raise HostRestoreError("restore_runtime_unrelated_generation")
        if retained:
            with generations.open_verified(plan.generation_id) as published:
                manifest = published.manifest
        else:
            generations.admit_candidate(payload, ())
            manifest = generations.publish(plan.generation_id, payload)
        mapping = RuntimeMapping(plan, manifest)
        commit_runtime_mapping(store, mapping)
        failure_hook("mapping")
        startup.reconcile_temporaries()
        intent = startup.begin_host_restore(
            candidate=start_target(plan.generation_id, manifest.to_bytes()),
            restore_id=journal.restore_id,
        )
        if intent.mode is not CaddyStartMode.HOST_RESTORE or intent.phase not in {
            CaddyStartPhase.CANDIDATE_PREPARED,
            CaddyStartPhase.RESTART_REQUIRED,
        }:
            raise HostRestoreError("restore_runtime_started_before_installation")
        try:
            selected = runtime.read_active()
        except FileNotFoundError:
            selected = None
        if selected not in {None, plan.generation_id}:
            raise HostRestoreError("restore_runtime_selection_changed")
        runtime.select_active(plan.generation_id)
        failure_hook("selection")
        if intent.phase is CaddyStartPhase.CANDIDATE_PREPARED:
            startup.mark_restart_required(intent)
        failure_hook("startup")
        apply_runtime_mapping(
            store, transaction, mapping, failure_hook=lambda _tenant: failure_hook("observation")
        )
        if runtime.read_generation_route_snapshot(plan.generation_id) != snapshot_tenant_routes(
            transaction
        ):
            raise HostRestoreError("restore_runtime_route_snapshot_changed")
    failure_hook("prepared")
    return mapping
