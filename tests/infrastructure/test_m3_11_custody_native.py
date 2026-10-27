"""All seven durable deliveries, real SDK guards and current remote close checks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from botocore.awsrequest import AWSResponse  # type: ignore[import-untyped]

from scripts import m3_11_custody_context as native
from scripts.m3_11_custody_domain import DomainDocker
from scripts.m3_11_custody_entry import Proof
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_retirement_files import RetirementError
from scripts.m3_11_unattended.connect_api import Response
from scripts.m3_11_unattended.model import ROLES, Credential, instant

from .test_m3_11_frozen_native import Raw
from .test_m3_11_storage_admission import prepared


@pytest.fixture
def owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> native.NativeCustody:
    _directory, lease, _docker, config, _store = prepared(tmp_path, monkeypatch)
    for path in lease.directory.glob("use-*.json"):
        path.unlink()
    now = instant(lease.manifest().created_at) + timedelta(minutes=1)
    monkeypatch.setattr(native, "datetime", SimpleNamespace(now=lambda _zone: now))
    monkeypatch.setattr(native, "require_remaining", lambda _seconds: None)
    instance = native.NativeCustody(
        configuration=config,
        historical={},
        invocation={},
        docker=cast(DomainDocker, object()),
        revalidate_custody_and_cleanup=lambda: "a" * 64,
        require_cleanup_current=lambda _seconds: None,
    )
    instance.held, instance.manifest, instance.lease = True, lease.manifest(), lease
    instance.plan = {"current_manifest_sha256": instance.manifest.sha256}
    instance.deliveries = {
        intent.role: lease.credential(intent) for intent in instance.manifest.intents
    }
    instance.guard()
    return instance


@pytest.mark.parametrize("role", sorted(ROLES))
def test_guard_requires_every_current_private_delivery(
    owner: native.NativeCustody, role: str
) -> None:
    (owner.lease.directory / ("credential-" + role + ".json")).unlink()
    with pytest.raises((ValueError, OSError)):
        owner.guard()


@pytest.mark.parametrize("fault", ["use", "closing", "issuer", "expired", "unlocked"])
def test_guard_never_adopts_users_or_terminal_or_expired_current_authority(
    owner: native.NativeCustody,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    if fault == "use":
        write_private(owner.lease.directory / "use-foreign.json", {})
    elif fault == "closing":
        write_private(owner.lease.directory / "close-finish.json", {})
    elif fault == "issuer":
        (owner.lease.directory / "issuer-stopped.json").unlink()
    elif fault == "expired":
        monkeypatch.setattr(
            native,
            "datetime",
            SimpleNamespace(now=lambda _zone: instant(owner.manifest.intents[0].deadline)),
        )
    else:
        owner.held = False
    with pytest.raises((ValueError, OSError)):
        owner.guard()


@pytest.mark.parametrize("closing", [False, True])
def test_real_sdk_checks_remote_close_at_wire_boundary_and_never_retries(
    monkeypatch: pytest.MonkeyPatch,
    closing: bool,
) -> None:
    instance: Any = native.NativeCustody.__new__(native.NativeCustody)
    instance.deliveries = {
        "archive": Credential("synthetic-id", "synthetic-secret", {}),
        "operator": Credential("synthetic-observer", "synthetic-other", {}),
    }
    instance.plan = {
        "archive": {
            "bucket": "test-archives",
            "key": "archives/example.zip",
            "version": "exact-version",
        }
    }
    instance.config = SimpleNamespace(
        targets=SimpleNamespace(region="nyc3", archive_bucket="test-archives"),
        journal_vault="v" * 26,
    )
    instance.manifest = SimpleNamespace(lease_id="synthetic-current")
    instance.deletes = instance.reads = 0
    instance.guard = lambda: None
    instance.cleanup_current = lambda _seconds: None
    calls = {"journal": 0, "wire": 0}

    def request(method: str, path: str) -> Response:
        assert method == "GET" and path == "/v1/vaults/" + "v" * 26 + "/items"
        calls["journal"] += 1
        return Response(
            200, [{"title": "m3-11-lease-synthetic-current-close-finish"}] if closing else []
        )

    instance.inventory = SimpleNamespace(client=SimpleNamespace(request=request))
    monkeypatch.setattr(native, "require_remaining", lambda _seconds: None)
    client: Any = instance.client("archive")

    def send(request: Any) -> AWSResponse:  # noqa: ANN401 - actual botocore transport
        calls["wire"] += 1
        assert request.method == "DELETE" and "versionId=exact-version" in request.url
        return AWSResponse(request.url, 204, {"x-amz-version-id": "exact-version"}, Raw(b""))

    monkeypatch.setattr(client._endpoint.http_session, "send", send)
    arguments = {
        "Bucket": "test-archives",
        "Key": "archives/example.zip",
        "VersionId": "exact-version",
    }
    if closing:
        with pytest.raises(RetirementError, match="closing remotely"):
            client.delete_object(**arguments)
    else:
        client.delete_object(**arguments)
    assert calls == {"journal": 1, "wire": 0 if closing else 1}
    with pytest.raises(RetirementError, match="unapproved mutation"):
        client.delete_object(**arguments)
    observer: Any = instance.client("operator")
    with pytest.raises(RetirementError, match="unapproved mutation"):
        observer.delete_object(**arguments)
    assert calls["wire"] == (0 if closing else 1)


def test_post_effect_reserve_covers_all_bounded_observation_requests() -> None:
    assert native.POST_EFFECT_RESERVE > 8 * 40 + 2 * 9 * 30 + 120


def test_native_cleanup_proof_must_cover_the_whole_post_effect_allowance() -> None:
    proof = Proof({})
    proof.valid_until = datetime.now(UTC) + timedelta(seconds=200)
    proof.current()
    original = proof.valid_until
    with pytest.raises(ValueError, match="complete effect reserve"):
        proof.current(native.POST_EFFECT_RESERVE + 40)
    assert proof.valid_until == original
    proof.valid_until = datetime.now(UTC) + timedelta(seconds=1300)
    proof.current(native.POST_EFFECT_RESERVE + 40)
