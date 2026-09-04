from __future__ import annotations

import hashlib
import os
from pathlib import Path

import lowerduckpond_static_host_agent.caddy_admin as caddy_admin_module
import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import (
    CADDY_CONFIGURATION_NAME,
    CADDY_GENERATION_ROOT_MODE,
    CaddyAdminError,
    CaddyBinarySource,
    CaddyGenerationPayload,
    CaddyGenerationStore,
    PinnedCaddyGeneration,
    build_platform_only_caddy_routes,
    load_caddy_configuration,
    reload_caddy_generation,
    restore_caddy_generation,
    verify_running_caddy,
)

_GENERATION_A = "0198d17f-6f4a-7000-8000-000000000001"
_GENERATION_B = "0198d17f-6f4a-7000-8000-000000000002"
_CADDY_PID = 123


def _payload(tmp_path: Path, *, binary: bytes = b"caddy\n") -> CaddyGenerationPayload:
    binary_path = tmp_path / hashlib.sha256(binary).hexdigest()
    binary_path.write_bytes(binary)
    binary_path.chmod(0o755)
    routes = build_platform_only_caddy_routes(
        origin_pull_ca_der=(b"review-only-origin-pull-ca",),
        origin_pull_required=True,
    )
    return CaddyGenerationPayload(
        CaddyBinarySource(binary_path, os.geteuid(), os.getegid()),
        b"CLOUDFLARE_API_TOKEN=review-only-token\n",
        routes.configuration,
        routes.route_metadata,
    )


def _large_payload(tmp_path: Path) -> CaddyGenerationPayload:
    payload = _payload(tmp_path)
    configuration = dict(payload.configuration)
    configuration["review-only-padding"] = "x" * (17 * 1024)
    return CaddyGenerationPayload(
        payload.binary,
        payload.environment,
        configuration,
        payload.route_metadata,
    )


def _store(tmp_path: Path) -> CaddyGenerationStore:
    root = tmp_path / "generations"
    root.mkdir(mode=CADDY_GENERATION_ROOT_MODE)
    root.chmod(CADDY_GENERATION_ROOT_MODE)
    return CaddyGenerationStore.open(
        root,
        expected_owner=os.geteuid(),
        expected_group=os.getegid(),
    )


def _configuration(generation: PinnedCaddyGeneration) -> bytes:
    descriptor = generation.duplicate_payload_descriptor(CADDY_CONFIGURATION_NAME)
    try:
        return os.read(descriptor, 2 * 1024 * 1024)
    finally:
        os.close(descriptor)


def test_reload_verifies_previous_loads_candidate_and_verifies_candidate(
    tmp_path: Path,
) -> None:
    events: list[tuple[str, str]] = []
    with _store(tmp_path) as store:
        payload = _payload(tmp_path)
        store.publish(_GENERATION_A, payload)
        store.publish(_GENERATION_B, payload)
        with (
            store.open_verified(_GENERATION_A) as previous,
            store.open_verified(_GENERATION_B) as candidate,
        ):
            reload_caddy_generation(
                previous,
                candidate,
                verifier=lambda generation: events.append(
                    ("verify", generation.manifest.generation_id)
                ),
                loader=lambda generation: events.append(
                    ("load", generation.manifest.generation_id)
                ),
            )

    assert events == [
        ("verify", _GENERATION_A),
        ("load", _GENERATION_B),
        ("verify", _GENERATION_B),
    ]


def test_reload_rejects_same_generation_or_changed_host_inputs(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        store.publish(_GENERATION_A, _payload(tmp_path))
        store.publish(_GENERATION_B, _payload(tmp_path, binary=b"different-caddy\n"))
        with (
            store.open_verified(_GENERATION_A) as previous,
            store.open_verified(_GENERATION_B) as candidate,
        ):
            with pytest.raises(CaddyAdminError, match="host input"):
                reload_caddy_generation(previous, candidate)
            with pytest.raises(CaddyAdminError, match="distinct"):
                reload_caddy_generation(previous, previous)


def test_restore_loads_before_verifying_known_good_generation(tmp_path: Path) -> None:
    events: list[str] = []
    with _store(tmp_path) as store:
        store.publish(_GENERATION_A, _payload(tmp_path))
        with store.open_verified(_GENERATION_A) as generation:
            restore_caddy_generation(
                generation,
                loader=lambda _generation: events.append("load"),
                verifier=lambda _generation: events.append("verify"),
            )

    assert events == ["load", "verify"]


def test_load_sends_exact_pinned_configuration(tmp_path: Path) -> None:
    requests: list[bytes] = []

    def accept(request: bytes) -> bytes:
        requests.append(request)
        return b"HTTP/1.0 200 OK\r\n\r\n"

    with _store(tmp_path) as store:
        store.publish(_GENERATION_A, _payload(tmp_path))
        with store.open_verified(_GENERATION_A) as generation:
            expected = _configuration(generation)
            load_caddy_configuration(generation, requester=accept)

    head, separator, body = requests[0].partition(b"\r\n\r\n")
    assert separator
    assert head.startswith(b"POST /load HTTP/1.0\r\n")
    assert f"Content-Length: {len(expected)}".encode("ascii") in head.split(b"\r\n")
    assert (
        body
        == expected
        == canonical_json_bytes(
            build_platform_only_caddy_routes(
                origin_pull_ca_der=(b"review-only-origin-pull-ca",),
                origin_pull_required=True,
            ).configuration
        )
    )


def test_live_load_restores_worker_access_to_replaced_admin_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(
        caddy_admin_module,
        "_send_admin_request",
        lambda _request: b"HTTP/1.0 200 OK\r\n\r\n",
    )
    monkeypatch.setattr(
        caddy_admin_module,
        "_normalize_admin_socket",
        lambda: events.append("normalize"),
    )

    with _store(tmp_path) as store:
        store.publish(_GENERATION_A, _payload(tmp_path))
        with store.open_verified(_GENERATION_A) as generation:
            load_caddy_configuration(generation)

    assert events == ["normalize"]


def test_load_and_verifier_accept_a_valid_configuration_over_16_kib(
    tmp_path: Path,
) -> None:
    requests: list[bytes] = []

    def accept(request: bytes) -> bytes:
        requests.append(request)
        return b"HTTP/1.0 200 OK\r\n\r\n"

    with _store(tmp_path) as store:
        store.publish(_GENERATION_A, _large_payload(tmp_path))
        with store.open_verified(_GENERATION_A) as generation:
            expected = _configuration(generation)
            assert len(expected) > 16 * 1024
            load_caddy_configuration(
                generation,
                requester=accept,
            )
            verify_running_caddy(
                generation,
                main_pid_source=lambda: str(_CADDY_PID),
                executable_digest_source=lambda _pid: hashlib.sha256(b"caddy\n").hexdigest(),
                configuration_source=lambda: expected,
            )

    assert requests[0].endswith(expected)


def test_load_rejects_admin_failure(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        store.publish(_GENERATION_A, _payload(tmp_path))
        with (
            store.open_verified(_GENERATION_A) as generation,
            pytest.raises(CaddyAdminError, match="response is invalid"),
        ):
            load_caddy_configuration(
                generation,
                requester=lambda _request: b"HTTP/1.0 400 Bad Request\r\n\r\n",
            )


def test_running_verifier_matches_pid_binary_and_configuration(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        payload = _payload(tmp_path)
        store.publish(_GENERATION_A, payload)
        with store.open_verified(_GENERATION_A) as generation:
            verify_running_caddy(
                generation,
                main_pid_source=lambda: str(_CADDY_PID),
                executable_digest_source=lambda pid: (
                    hashlib.sha256(b"caddy\n").hexdigest()
                    if pid == _CADDY_PID
                    else pytest.fail("unexpected PID")
                ),
                configuration_source=lambda: _configuration(generation),
            )


def test_running_verifier_rejects_invalid_pid_or_mismatch(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        store.publish(_GENERATION_A, _payload(tmp_path))
        with store.open_verified(_GENERATION_A) as generation:
            with pytest.raises(CaddyAdminError, match="PID"):
                verify_running_caddy(generation, main_pid_source=lambda: "0")
            with pytest.raises(CaddyAdminError, match="binary disagrees"):
                verify_running_caddy(
                    generation,
                    main_pid_source=lambda: str(_CADDY_PID),
                    executable_digest_source=lambda _pid: "0" * 64,
                )


def test_runtime_verifier_fences_configuration_to_one_verified_invocation(
    tmp_path: Path,
) -> None:
    invocation = (_CADDY_PID, "a" * 32)
    identities = iter((invocation, invocation))
    with _store(tmp_path) as store:
        store.publish(_GENERATION_A, _payload(tmp_path))
        with store.open_verified(_GENERATION_A) as generation:
            verify_running_caddy(
                generation,
                configuration_source=lambda: _configuration(generation),
                service_identity_source=lambda: next(identities),
            )


def test_runtime_verifier_rejects_an_invocation_change(tmp_path: Path) -> None:
    identities = iter(
        (
            (_CADDY_PID, "a" * 32),
            (_CADDY_PID + 1, "b" * 32),
        )
    )
    with _store(tmp_path) as store:
        store.publish(_GENERATION_A, _payload(tmp_path))
        with (
            store.open_verified(_GENERATION_A) as generation,
            pytest.raises(CaddyAdminError, match="invocation changed"),
        ):
            verify_running_caddy(
                generation,
                configuration_source=lambda: _configuration(generation),
                service_identity_source=lambda: next(identities),
            )
