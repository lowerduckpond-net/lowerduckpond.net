from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from multiprocessing import get_context
from pathlib import Path

import lowerduckpond_static_host_agent.caddy_generation as caddy_generation_module
import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import (
    CADDY_BINARY_NAME,
    CADDY_CONFIGURATION_NAME,
    CADDY_ENVIRONMENT_NAME,
    CADDY_GENERATION_MODE,
    CADDY_GENERATION_ROOT_MODE,
    CADDY_MANIFEST_NAME,
    CADDY_ROUTE_METADATA_NAME,
    CADDY_ROUTE_METADATA_SCHEMA,
    CaddyBinarySource,
    CaddyGenerationAlreadyExistsError,
    CaddyGenerationBoundary,
    CaddyGenerationError,
    CaddyGenerationPayload,
    CaddyGenerationStore,
    CapacityRejectedError,
    FilesystemCapacity,
    caddy_route_state_digest,
)

_GENERATION_ID = "0198d17f-6f4a-7000-8000-000000000001"
_SECOND_GENERATION_ID = "0198d17f-6f4a-7000-8000-000000000002"
_THIRD_GENERATION_ID = "0198d17f-6f4a-7000-8000-000000000003"
_FOURTH_GENERATION_ID = "0198d17f-6f4a-7000-8000-000000000004"
_PAYLOAD_NAMES = {
    CADDY_BINARY_NAME,
    CADDY_ENVIRONMENT_NAME,
    CADDY_CONFIGURATION_NAME,
    CADDY_ROUTE_METADATA_NAME,
}
_CRASH_EXIT_STATUS = 91
_PROCESS_TIMEOUT_SECONDS = 10


class InjectedGenerationFailureError(RuntimeError):
    pass


def _raise_at(
    expected: CaddyGenerationBoundary,
) -> Callable[[CaddyGenerationBoundary], None]:
    def hook(actual: CaddyGenerationBoundary) -> None:
        if actual is expected:
            raise InjectedGenerationFailureError(expected)

    return hook


def _make_root(tmp_path: Path) -> Path:
    root = tmp_path / "generations"
    root.mkdir(mode=CADDY_GENERATION_ROOT_MODE)
    root.chmod(CADDY_GENERATION_ROOT_MODE)
    return root


def _make_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "staged-caddy"
    binary.write_bytes(b"pinned-caddy-binary\n")
    binary.chmod(0o755)
    return binary


def _route_metadata(*, publication_enabled: bool = False) -> dict[str, object]:
    state: dict[str, object] = {
        "platformRoutes": ["lowerduckpond.net"],
        "publicationEnabled": publication_enabled,
        "tenantRoutes": [],
    }
    return {
        "routeState": state,
        "routeStateDigest": caddy_route_state_digest(state).to_dict(),
        "schema": CADDY_ROUTE_METADATA_SCHEMA,
    }


def _payload(tmp_path: Path) -> CaddyGenerationPayload:
    return _payload_for_binary(_make_binary(tmp_path))


def _payload_for_binary(binary: Path) -> CaddyGenerationPayload:
    return CaddyGenerationPayload(
        binary=CaddyBinarySource(
            path=binary,
            owner=os.geteuid(),
            group=os.getegid(),
        ),
        environment=b"CADDY_ADMIN=127.0.0.1:2019\nCADDY_DEBUG=false\n",
        configuration={
            "admin": {"listen": "127.0.0.1:2019"},
            "apps": {"http": {"servers": {}}},
        },
        route_metadata=_route_metadata(),
    )


def _crash_during_publish(root: str, binary: str, boundary_value: str) -> None:
    boundary = CaddyGenerationBoundary(boundary_value)

    def crash(actual: CaddyGenerationBoundary) -> None:
        if actual is boundary:
            os._exit(_CRASH_EXIT_STATUS)

    with _open_store(Path(root)) as store:
        store.publish(
            _GENERATION_ID,
            _payload_for_binary(Path(binary)),
            failure_hook=crash,
            temporary_name_source=lambda: f".ldp-generation-{'2' * 32}",
        )


def _open_store(root: Path) -> CaddyGenerationStore:
    return CaddyGenerationStore.open(
        root,
        expected_owner=os.geteuid(),
        expected_group=os.getegid(),
    )


def test_publish_writes_one_exact_complete_immutable_generation(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    payload = _payload(tmp_path)

    with _open_store(root) as store:
        manifest = store.publish(_GENERATION_ID, payload)

    generation = root / _GENERATION_ID
    assert {item.name for item in generation.iterdir()} == {
        *_PAYLOAD_NAMES,
        CADDY_MANIFEST_NAME,
    }
    assert stat.S_IMODE(generation.stat().st_mode) == CADDY_GENERATION_MODE
    for path in generation.iterdir():
        assert path.stat().st_uid == os.geteuid()
        assert path.stat().st_gid == os.getegid()
        expected_mode = 0o550 if path.name == CADDY_BINARY_NAME else 0o440
        assert stat.S_IMODE(path.stat().st_mode) == expected_mode

    manifest_bytes = (generation / CADDY_MANIFEST_NAME).read_bytes()
    assert manifest_bytes == canonical_json_bytes(
        json.loads(manifest_bytes),
        maximum_bytes=len(manifest_bytes),
    )
    assert json.loads(manifest_bytes) == manifest.to_dict()
    assert {item.name for item in manifest.files} == _PAYLOAD_NAMES
    assert (generation / CADDY_BINARY_NAME).read_bytes() == b"pinned-caddy-binary\n"
    assert (generation / CADDY_ENVIRONMENT_NAME).read_bytes() == payload.environment


def test_open_verified_pins_every_manifest_verified_payload(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    payload = _payload(tmp_path)

    with _open_store(root) as store:
        published = store.publish(_GENERATION_ID, payload)
        with store.open_verified(_GENERATION_ID) as pinned:
            assert pinned.manifest == published
            descriptor = pinned.duplicate_payload_descriptor(CADDY_CONFIGURATION_NAME)
            try:
                assert os.read(descriptor, 4096) == canonical_json_bytes(payload.configuration)
            finally:
                os.close(descriptor)


def test_pinned_payload_survives_later_namespace_replacement(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    payload = _payload(tmp_path)

    with _open_store(root) as store:
        store.publish(_GENERATION_ID, payload)
        with store.open_verified(_GENERATION_ID) as pinned:
            descriptor = pinned.duplicate_payload_descriptor(CADDY_BINARY_NAME)
            (root / _GENERATION_ID).rename(root / "retired")
            try:
                assert os.read(descriptor, 4096) == b"pinned-caddy-binary\n"
            finally:
                os.close(descriptor)


def test_each_payload_descriptor_has_an_independent_file_offset(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    with _open_store(root) as store:
        store.publish(_GENERATION_ID, _payload(tmp_path))
        with store.open_verified(_GENERATION_ID) as pinned:
            first = pinned.duplicate_payload_descriptor(CADDY_BINARY_NAME)
            second = pinned.duplicate_payload_descriptor(CADDY_BINARY_NAME)
            try:
                assert os.read(first, 6) == b"pinned"
                assert os.read(second, 6) == b"pinned"
                assert os.read(first, 6) == b"-caddy"
                assert os.read(second, 6) == b"-caddy"
            finally:
                os.close(first)
                os.close(second)


def test_publish_never_replaces_an_existing_generation(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    payload = _payload(tmp_path)

    with _open_store(root) as store:
        first = store.publish(_GENERATION_ID, payload)
        with pytest.raises(CaddyGenerationAlreadyExistsError):
            store.publish(_GENERATION_ID, payload)
        with store.open_verified(_GENERATION_ID) as pinned:
            assert pinned.manifest == first

    assert list(root.glob(".ldp-generation-*")) == []


@pytest.mark.parametrize(
    ("boundary", "published"),
    [
        (CaddyGenerationBoundary.BINARY_SYNC, False),
        (CaddyGenerationBoundary.ENVIRONMENT_SYNC, False),
        (CaddyGenerationBoundary.CONFIGURATION_SYNC, False),
        (CaddyGenerationBoundary.ROUTE_METADATA_SYNC, False),
        (CaddyGenerationBoundary.MANIFEST_SYNC, False),
        (CaddyGenerationBoundary.DIRECTORY_SYNC, False),
        (CaddyGenerationBoundary.RENAME, True),
        (CaddyGenerationBoundary.PARENT_SYNC, True),
    ],
)
def test_failure_exposes_only_absence_or_one_complete_generation(
    tmp_path: Path,
    boundary: CaddyGenerationBoundary,
    published: bool,
) -> None:
    root = _make_root(tmp_path)
    payload = _payload(tmp_path)

    with _open_store(root) as store, pytest.raises(InjectedGenerationFailureError):
        store.publish(
            _GENERATION_ID,
            payload,
            failure_hook=_raise_at(boundary),
            temporary_name_source=lambda: f".ldp-generation-{'1' * 32}",
        )

    assert (root / _GENERATION_ID).exists() is published
    assert list(root.glob(".ldp-generation-*")) == []
    if published:
        with _open_store(root) as store, store.open_verified(_GENERATION_ID):
            pass


@pytest.mark.parametrize(
    ("boundary", "published"),
    [
        (CaddyGenerationBoundary.BINARY_SYNC, False),
        (CaddyGenerationBoundary.ENVIRONMENT_SYNC, False),
        (CaddyGenerationBoundary.CONFIGURATION_SYNC, False),
        (CaddyGenerationBoundary.ROUTE_METADATA_SYNC, False),
        (CaddyGenerationBoundary.MANIFEST_SYNC, False),
        (CaddyGenerationBoundary.DIRECTORY_SYNC, False),
        (CaddyGenerationBoundary.RENAME, True),
        (CaddyGenerationBoundary.PARENT_SYNC, True),
    ],
)
def test_process_exit_is_recoverable_to_absence_or_one_complete_generation(
    tmp_path: Path,
    boundary: CaddyGenerationBoundary,
    published: bool,
) -> None:
    root = _make_root(tmp_path)
    binary = _make_binary(tmp_path)
    process = get_context("spawn").Process(
        target=_crash_during_publish,
        args=(str(root), str(binary), boundary.value),
    )
    process.start()
    process.join(_PROCESS_TIMEOUT_SECONDS)
    if process.is_alive():
        process.terminate()
        process.join(_PROCESS_TIMEOUT_SECONDS)
        pytest.fail("generation crash subprocess did not terminate")

    assert process.exitcode == _CRASH_EXIT_STATUS
    with _open_store(root) as store:
        assert store.remove_abandoned_temporaries() == (0 if published else 1)
        if published:
            with store.open_verified(_GENERATION_ID):
                pass
    assert list(root.glob(".ldp-generation-*")) == []


def test_abandoned_temporary_cleanup_is_bounded_and_fails_closed(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    malformed = root / ".ldp-generation-attacker"
    malformed.mkdir(mode=0o700)
    with (
        _open_store(root) as store,
        pytest.raises(
            CaddyGenerationError,
            match="name is malformed",
        ),
    ):
        store.remove_abandoned_temporaries()

    malformed.rmdir()
    (root / "ordinary-generation").mkdir()
    with (
        _open_store(root) as store,
        pytest.raises(
            CaddyGenerationError,
            match="scan bound",
        ),
    ):
        store.remove_abandoned_temporaries(maximum_entries=0)


def test_abandoned_pre_normalization_modes_are_recoverable(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    temporary = root / f".ldp-generation-{'3' * 32}"
    temporary.mkdir(mode=0o700)
    partial = temporary / CADDY_BINARY_NAME
    partial.write_bytes(b"partial")
    partial.chmod(0o500)

    with _open_store(root) as store:
        assert store.remove_abandoned_temporaries() == 1

    assert not temporary.exists()


def test_generation_scans_do_not_leak_descriptors(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    descriptor_root = Path("/proc/self/fd")
    with _open_store(root) as store:
        store.publish(_GENERATION_ID, _payload(tmp_path))
        before = len(list(descriptor_root.iterdir()))
        for _ in range(100):
            with store.open_verified(_GENERATION_ID):
                pass
            assert store.remove_abandoned_temporaries() == 0
        after = len(list(descriptor_root.iterdir()))

    assert after == before


def test_retention_keeps_only_protected_and_newest_preceding_generation(
    tmp_path: Path,
) -> None:
    root = _make_root(tmp_path)
    payload = _payload(tmp_path)
    with _open_store(root) as store:
        for generation_id in (
            _GENERATION_ID,
            _SECOND_GENERATION_ID,
            _THIRD_GENERATION_ID,
            _FOURTH_GENERATION_ID,
        ):
            store.publish(generation_id, payload)
        removed = store.prune_unreferenced(
            {_FOURTH_GENERATION_ID},
            keep_newest_unprotected=1,
        )
        assert removed == (_GENERATION_ID, _SECOND_GENERATION_ID)
        assert store.list_verified() == (_THIRD_GENERATION_ID, _FOURTH_GENERATION_ID)


def test_retired_generation_crash_staging_is_reconciled(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    with _open_store(root) as store:
        store.publish(_GENERATION_ID, _payload(tmp_path))
    (root / _GENERATION_ID).rename(root / f".ldp-retired-{_GENERATION_ID}")

    with _open_store(root) as store:
        assert store.remove_abandoned_temporaries() == 1
        assert store.list_verified() == ()


def test_candidate_admission_requires_one_of_three_slots(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    payload = _payload(tmp_path)
    with _open_store(root) as store:
        retained = (_GENERATION_ID, _SECOND_GENERATION_ID, _THIRD_GENERATION_ID)
        for generation_id in retained:
            store.publish(generation_id, payload)
        with pytest.raises(CaddyGenerationError, match="slot remains"):
            store.admit_candidate(payload, retained)


def test_candidate_admission_enforces_the_aggregate_allocation_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _make_root(tmp_path)
    payload = _payload(tmp_path)
    device = root.stat().st_dev
    monkeypatch.setattr(
        caddy_generation_module,
        "measure_filesystem_capacity_descriptor",
        lambda _descriptor: FilesystemCapacity(
            device=device,
            fragment_size=4096,
            total_blocks=10_000_000,
            available_blocks=9_000_000,
            total_inodes=1_000_000,
            available_inodes=900_000,
        ),
    )
    monkeypatch.setattr(
        caddy_generation_module,
        "MAX_CADDY_GENERATION_ALLOCATED_BYTES",
        1,
    )
    with (
        _open_store(root) as store,
        pytest.raises(
            CapacityRejectedError,
            match="byte ceiling",
        ),
    ):
        store.admit_candidate(payload, ())


def test_tampered_payload_fails_manifest_verification(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    payload = _payload(tmp_path)
    with _open_store(root) as store:
        store.publish(_GENERATION_ID, payload)

    target = root / _GENERATION_ID / CADDY_CONFIGURATION_NAME
    target.chmod(0o640)
    target.write_bytes(b'{"tampered":true}\n')
    target.chmod(0o440)

    with _open_store(root) as store, pytest.raises(CaddyGenerationError):
        store.open_verified(_GENERATION_ID)


def test_generation_with_an_extra_entry_fails_closed(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    with _open_store(root) as store:
        store.publish(_GENERATION_ID, _payload(tmp_path))

    generation = root / _GENERATION_ID
    generation.chmod(0o750)
    (generation / "unbound").write_bytes(b"not in the manifest")
    generation.chmod(CADDY_GENERATION_MODE)

    with (
        _open_store(root) as store,
        pytest.raises(
            CaddyGenerationError,
            match="inventory is not exact",
        ),
    ):
        store.open_verified(_GENERATION_ID)


def test_multiply_linked_payload_fails_closed(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    with _open_store(root) as store:
        store.publish(_GENERATION_ID, _payload(tmp_path))

    os.link(root / _GENERATION_ID / CADDY_BINARY_NAME, tmp_path / "binary-alias")
    with (
        _open_store(root) as store,
        pytest.raises(
            CaddyGenerationError,
            match="metadata is unsafe",
        ),
    ):
        store.open_verified(_GENERATION_ID)


def test_symlinked_staged_binary_is_rejected_without_publication(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    binary = _make_binary(tmp_path)
    link = tmp_path / "caddy-link"
    link.symlink_to(binary)
    payload = CaddyGenerationPayload(
        binary=CaddyBinarySource(link, os.geteuid(), os.getegid()),
        environment=b"CADDY_ADMIN=127.0.0.1:2019\n",
        configuration={"apps": {}},
        route_metadata=_route_metadata(),
    )

    with (
        _open_store(root) as store,
        pytest.raises(
            CaddyGenerationError,
            match="no-follow regular file",
        ),
    ):
        store.publish(_GENERATION_ID, payload)

    assert list(root.iterdir()) == []


@pytest.mark.parametrize(
    "environment",
    [
        b"",
        b"CADDY_ADMIN=value",
        b"CADDY_ADMIN=value\r\n",
        b"CADDY_ADMIN=value\nCADDY_ADMIN=other\n",
        b"lowercase=value\n",
        b"NO_EQUALS\n",
        b"VALUE=contains\0nul\n",
    ],
)
def test_environment_must_be_normalized_and_unambiguous(
    tmp_path: Path,
    environment: bytes,
) -> None:
    with pytest.raises(CaddyGenerationError):
        CaddyGenerationPayload(
            binary=CaddyBinarySource(_make_binary(tmp_path), os.geteuid(), os.getegid()),
            environment=environment,
            configuration={"apps": {}},
            route_metadata=_route_metadata(),
        )


def test_route_metadata_must_bind_its_exact_state(tmp_path: Path) -> None:
    metadata = _route_metadata()
    route_state = metadata["routeState"]
    assert type(route_state) is dict
    route_state["publicationEnabled"] = True

    with pytest.raises(CaddyGenerationError, match="state digest does not match"):
        CaddyGenerationPayload(
            binary=CaddyBinarySource(_make_binary(tmp_path), os.geteuid(), os.getegid()),
            environment=b"CADDY_ADMIN=127.0.0.1:2019\n",
            configuration={"apps": {}},
            route_metadata=metadata,
        )


def test_generation_root_metadata_and_final_symlinks_fail_closed(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    root.chmod(0o755)
    with pytest.raises(CaddyGenerationError, match="root metadata is unsafe"):
        _open_store(root)

    real_root = tmp_path / "real"
    real_root.mkdir(mode=CADDY_GENERATION_ROOT_MODE)
    real_root.chmod(CADDY_GENERATION_ROOT_MODE)
    link = tmp_path / "linked"
    link.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(CaddyGenerationError, match="no-follow directory"):
        _open_store(link)


def test_closed_store_and_generation_reject_descriptor_use(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    store = _open_store(root)
    store.publish(_SECOND_GENERATION_ID, _payload(tmp_path))
    pinned = store.open_verified(_SECOND_GENERATION_ID)
    pinned.close()
    store.close()

    with pytest.raises(ValueError, match="closed"):
        pinned.duplicate_payload_descriptor(CADDY_BINARY_NAME)
    with pytest.raises(ValueError, match="closed"):
        store.open_verified(_SECOND_GENERATION_ID)
