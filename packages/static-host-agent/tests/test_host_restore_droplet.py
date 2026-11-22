"""Disposable Droplet recovery tests with synthetic identity and a real native journal."""

from __future__ import annotations

import base64
import os
from dataclasses import replace
from pathlib import Path
from typing import cast
from uuid import uuid7

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object
from lowerduckpond_static_host_agent import (
    droplet_enrollment,
)
from lowerduckpond_static_host_agent import (
    host_restore_activation as activation,
)
from lowerduckpond_static_host_agent import (
    host_restore_droplet as droplet_restore,
)
from lowerduckpond_static_host_agent import (
    host_restore_fence as fence,
)
from lowerduckpond_static_host_agent import (
    host_restore_gate as gate,
)
from lowerduckpond_static_host_agent import (
    host_restore_services as services,
)
from lowerduckpond_static_host_agent.backup_descriptor import (
    LAUNCH_DIGEST_FORMAT,
    decode_backup_descriptor,
    encode_backup_descriptor,
)
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.host_restore_authority import begin_restore_authority
from lowerduckpond_static_host_agent.host_restore_delivery import (
    delivery_readback,
    publication_files,
)
from lowerduckpond_static_host_agent.host_restore_gate import (
    INGRESS,
    close_gate,
    restore_admission,
)
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    DROPLET_BINDING,
    DROPLET_SCOPE_FORMAT,
    GATE,
    PHASES,
    HostRestoreError,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_snapshot import RestoreSnapshot
from lowerduckpond_static_host_agent.platform_launch import (
    _launch_bytes,
    require_local_launch_binding,
    verify_launch,
)
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401 - shared fixture
from test_backup_capture import capture as capture  # noqa: PLC0414
from test_backup_capture import fixture as fixture  # noqa: PLC0414
from test_host_restore_inputs import configuration as configuration  # noqa: PLC0414
from test_host_restore_snapshot import restic as restic  # noqa: PLC0414

from scripts import m3_12_droplet_observe as observe
from scripts.m3_12_contracts import (
    COMMON_SLOTS,
    DISPOSABLE,
    Document,
    ValidationError,
    digest,
    encode,
)
from scripts.m3_12_droplet_inventory import (
    ApprovedAllocation,
    ConnectedDroplet,
    ProviderIdentity,
    enrollment_records,
)


@pytest.fixture
def destination(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    owner = os.geteuid()
    authority = tmp_path / droplet_enrollment.PUBLICATION_VIEW
    authority.mkdir(mode=0o700)
    for name, value in (
        ("MACHINE_ID", b"b" * 32 + b"\n"),
        ("SYSTEM_UUID", b"22222222-3333-4444-5555-666666666666\n"),
        ("HOST_KEY", b"ssh-ed25519 " + base64.b64encode(observe.ED25519_WIRE_HEADER + b"B" * 32)),
    ):
        path = tmp_path / name
        path.write_bytes(value)
        path.chmod(0o600)
        monkeypatch.setattr(observe, name, path)
    monkeypatch.setattr(droplet_enrollment, "DOCKER_MARKER", tmp_path / "not-docker")
    monkeypatch.setattr(droplet_restore, "AUTHORITY", authority)
    monkeypatch.setattr(droplet_restore, "STATE", tmp_path / "no-launch")
    artifact = tmp_path / ("b" * 64)
    artifact.mkdir(mode=0o700)
    selected = tmp_path / "current"
    selected.symlink_to(artifact)
    monkeypatch.setattr(observe, "SELECTION", selected)
    run_id = str(uuid7())
    host = observe.host_identity(owner)
    identity = ProviderIdentity("a" * 64, 102, "192.0.2.19")
    allocation = ApprovedAllocation(
        run_id=run_id,
        role="restore",
        state_sha256="c" * 64,
        allocation_sha256="d" * 64,
        inventory_sha256="e" * 64,
        transaction_namespace_sha256="f" * 64,
        identity=identity,
    )
    connected = ConnectedDroplet(identity, 102, identity.ipv4, host, host["hostKeySha256"])
    exclusions = {
        "format": "lowerduckpond-m3-12-droplet-production-exclusions-v1",
        "dropletIds": [999],
        "addresses": ["192.0.2.20"],
        "identityDigests": ["1" * 64],
    }
    target, enrollment = enrollment_records(allocation, connected, encode(exclusions))
    for name, doc in (
        (droplet_enrollment.TARGET, target),
        (droplet_enrollment.ENROLLMENT, enrollment),
        (droplet_enrollment.EXCLUSIONS, exclusions),
    ):
        path = authority / name
        path.write_bytes(encode(doc))
        path.chmod(0o600)
    return run_id, digest(target)


def launched_snapshot(
    snapshot: RestoreSnapshot, configuration: Document, run_id: str, state: Path
) -> tuple[RestoreSnapshot, str, str]:
    # These component fixtures exercise native verification of a restored chain.
    target = {
        "targetKind": DISPOSABLE,
        "purpose": "disposable-qualification",
        **{
            field: digest({"fixtureSource": field})
            for field in (
                "enrollmentSha256",
                "allocationSha256",
                "leaseDomainSha256",
                "inventorySha256",
                "stateSha256",
                "addressSetSha256",
                "transactionNamespaceSha256",
            )
        },
        "transport": {"kind": "ssh", "identitySha256": "4" * 64},
        "droplet": {
            "projectIdSha256": "a" * 64,
            "dropletId": 101,
            "providerIdentitySha256": "5" * 64,
            "metadataIdentitySha256": "6" * 64,
        },
    }
    candidate = {
        "revision": "a" * 40,
        "hostAgentSha256": configuration["originalArtifactSha256"],
        **{
            field: digest({"fixtureArtifact": field})
            for field in (
                "inputPolicySha256",
                "inputFingerprintSha256",
                "toolchainSha256",
                "requirementsSha256",
            )
        },
    }
    platform = {
        "namespaceSha256": digest(configuration["namespace"]),
        "storageTargetSha256": "7" * 64,
        "storageBackend": "spaces",
        "cloudflareNetworkSetSha256": "8" * 64,
        "trustedPlatformDomain": "lowerduckpond.net",
        "aliasSuffix": "lowerduckpond.com",
        "tenantOriginSuffix": "lowerduckpond.com",
        "cookiePolicyVersion": "lowerduckpond-cookie-policy-v1",
        "edgePolicyVersion": "lowerduckpond-edge-policy-v1",
    }
    source_target_sha256 = digest(target)
    binding = {
        "targetKind": target["targetKind"],
        "purpose": target["purpose"],
        "runId": run_id,
        "targetSha256": source_target_sha256,
        "candidateSha256": digest(candidate),
        "platformSha256": digest(platform),
    }
    admission = {
        "format": "lowerduckpond-m3-12-admission-v1",
        "binding": binding,
        "target": target,
        "candidate": candidate,
        "platform": platform,
        "invocationId": str(uuid7()),
        "authoritySha256": target["enrollmentSha256"],
        "leaseSha256": "9" * 64,
        "preparedAt": "2026-09-21T04:30:00Z",
        "prerequisites": {slot: digest({"fixturePrerequisite": slot}) for slot in COMMON_SLOTS},
    }
    intent = {
        "format": "lowerduckpond-m3-12-launch-intent-v1",
        "binding": binding,
        "admissionSha256": digest(admission),
        "invocationId": admission["invocationId"],
        "leaseSha256": admission["leaseSha256"],
        "intendedAt": "2026-09-21T04:55:00Z",
    }
    raw_launch, raw_receipt = _launch_bytes(admission, intent)
    launch = decode_json_object(raw_launch)
    configuration.update(launch=launch, publicationEnabled=True)
    state.mkdir(mode=0o700)
    (state / "platform").mkdir(mode=0o700)
    (state / "locks").mkdir(mode=0o700)
    (state / "locks/tenant-state.lock").touch(mode=0o600)
    for file, value in (
        (state / "platform/launch.json", launch),
        (state / "platform/namespace.json", configuration["namespace"]),
        (droplet_restore.AUTHORITY / "admission.json", admission),
        (droplet_restore.AUTHORITY / "launch-intent.json", intent),
        (droplet_restore.AUTHORITY / "launch-receipt.json", decode_json_object(raw_receipt)),
    ):
        file.write_bytes(encode(value))
        file.chmod(0o600)
    descriptor = decode_backup_descriptor(snapshot.descriptor)
    descriptor["launchDigest"] = framed_digest(LAUNCH_DIGEST_FORMAT, encode(launch))
    scoped = replace(snapshot, descriptor=encode_backup_descriptor(descriptor))
    return scoped, source_target_sha256, digest(decode_json_object(raw_receipt))


@pytest.fixture(params=[False, True], ids=["dark", "launched"])
def native_recovery(  # noqa: PLR0913,PLR0917 - independent fixture artifacts and policy
    request: pytest.FixtureRequest,
    restic: tuple[RestoreSnapshot, dict[str, dict[str, object]]],
    configuration: dict[str, object],
    destination: tuple[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, RestoreInputs]:
    owner = os.geteuid()
    snapshot, _ = restic
    run_id, target = destination
    source_target = "2" * 64
    launch_receipt = None
    if request.param:
        snapshot, source_target, launch_receipt = launched_snapshot(
            snapshot, configuration, run_id, droplet_restore.STATE
        )
    source = tmp_path / "fenced-source"
    source.mkdir(mode=0o700)
    monkeypatch.setattr(fence, "close_public_ingress", lambda: None)
    monkeypatch.setattr(
        fence,
        "quiesce_host",
        lambda: tuple(
            sorted(
                (
                    *services.ORDINARY_ACTIVATORS,
                    *services.ORDINARY_SERVICES,
                    *services.TEMPLATES,
                    "caddy.service",
                )
            )
        ),
    )
    monkeypatch.setattr(fence, "require_quiescent", lambda: None)
    with RestoreStore.locked(source, owner=owner) as store:
        raw = fence.source_fence_receipt(
            store, snapshot, cast(str, configuration["restoreId"]), "a" * 32, "b" * 64
        )
    policy = RestoreInputs.from_bytes(
        canonical_json_bytes(
            {
                **configuration,
                "repositoryBinding": snapshot.identity.binding(),
                "sourceFenceDigest": framed_digest(fence.FENCE_SCHEMA, raw),
                DROPLET_BINDING: {
                    "format": DROPLET_SCOPE_FORMAT,
                    "runId": run_id,
                    "sourceTargetSha256": source_target,
                    "destinationTargetSha256": target,
                    "sourceLaunchReceiptSha256": launch_receipt,
                },
            }
        )
    )
    root = tmp_path / "restored-recovery"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(gate, "RECOVERY_ROOT", root)
    with RestoreStore.locked(root, owner=owner) as store:
        current = begin_restore_authority(
            store, snapshot, policy, raw, destination_id="b" * 32, artifact_sha256="b" * 64
        )
        assert current.bindings[DROPLET_BINDING] == policy.droplet_scope_digest
        close_gate(store, current.restore_id)
        for phase in PHASES[1:]:
            current = store.advance(current, phase, {})
    return root, policy


def test_droplet_activation_and_ingress_resume_require_the_original_destination(
    native_recovery: tuple[Path, RestoreInputs],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, inputs = native_recovery
    owner = os.geteuid()
    caddy = tmp_path / "activation-caddy"
    caddy.mkdir(mode=0o750)
    (caddy / "intents").mkdir(mode=0o700)
    config = tmp_path / "static-publication.json"
    config.write_bytes(
        encode(
            {
                "format": "lowerduckpond-static-publication-gate-v1",
                "static_publication_enabled": False,
            }
        )
    )
    config.chmod(0o400)
    ready = tmp_path / "run/schedules-ready"
    events: list[str] = []
    monkeypatch.setattr(services, "restore_schedules", lambda **kwargs: events.append("schedules"))
    monkeypatch.setattr(services, "remove_public_gate", lambda: events.append("ingress"))
    with RestoreStore.locked(root, owner=owner) as store:
        original = observe.MACHINE_ID.read_bytes()
        observe.MACHINE_ID.write_bytes(b"c" * 32 + b"\n")
        with pytest.raises(ValidationError, match="droplet-enrollment-changed"):
            activation.activate_completed_restore(
                store, inputs, caddy, configuration=config, ready=ready
            )
        assert not events and not ready.exists() and (root / GATE[0]).exists()

        observe.MACHINE_ID.write_bytes(original)
        receipt = None
        if inputs.document["launch"] is not None:
            receipt = verify_launch(droplet_restore.STATE, droplet_restore.AUTHORITY, owner=owner)
            with pytest.raises(ValidationError, match="droplet-restore-admission-pending"):
                require_local_launch_binding(
                    droplet_restore.AUTHORITY, receipt, disposable=False, owner=owner
                )

        def interrupt(boundary: str) -> None:
            if boundary == "gate":
                raise RuntimeError("interrupted after admission commit")

        with pytest.raises(RuntimeError, match="interrupted"):
            activation.activate_completed_restore(
                store, inputs, caddy, configuration=config, ready=ready, failure_hook=interrupt
            )
        assert events == ["schedules"] and (root / INGRESS[0]).exists()
        observe.MACHINE_ID.write_bytes(b"c" * 32 + b"\n")
        with pytest.raises(ValidationError, match="droplet-enrollment-changed"):
            activation.finish_public_ingress(store)
        assert events == ["schedules"] and (root / INGRESS[0]).exists()
        observe.MACHINE_ID.write_bytes(original)
        activation.finish_public_ingress(store)
        assert events == ["schedules", "ingress"]
        assert restore_admission(root, owner=owner, boot=True)
        if receipt is not None:
            require_local_launch_binding(
                droplet_restore.AUTHORITY, receipt, disposable=False, owner=owner
            )
            assert (
                verify_launch(droplet_restore.STATE, droplet_restore.AUTHORITY, owner=owner)
                == receipt
            )

        if receipt is not None:
            scope = inputs.droplet_scope
            assert scope is not None
            other = {
                **receipt,
                "binding": {**receipt["binding"], "targetSha256": scope["destinationTargetSha256"]},
            }
            with pytest.raises(HostRestoreError, match="droplet_restore_source_launch_changed"):
                require_local_launch_binding(
                    droplet_restore.AUTHORITY, other, disposable=False, owner=owner
                )

        (droplet_restore.AUTHORITY / "revoked").touch(mode=0o600)
        with pytest.raises(ValidationError, match="droplet-enrollment-conflicts"):
            restore_admission(root, owner=owner, boot=True)


@pytest.mark.parametrize("change", ["target", "artifact"])
def test_droplet_authority_is_rechecked_before_publication_configuration_changes(
    native_recovery: tuple[Path, RestoreInputs],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    root, inputs = native_recovery
    caddy = tmp_path / "activation-caddy"
    caddy.mkdir(mode=0o750)
    (caddy / "intents").mkdir(mode=0o700)
    config = tmp_path / "static-publication.json"
    original = encode(
        {"format": "lowerduckpond-static-publication-gate-v1", "static_publication_enabled": False}
    )
    config.write_bytes(original)
    config.chmod(0o400)
    monkeypatch.setattr(
        services, "restore_schedules", lambda **kwargs: pytest.fail("schedules started")
    )
    monkeypatch.setattr(services, "remove_public_gate", lambda: pytest.fail("ingress opened"))

    def substitute(boundary: str) -> None:
        if boundary == "startup":
            if change == "target":
                path = droplet_restore.AUTHORITY / droplet_enrollment.TARGET
                target = decode_json_object(path.read_bytes())
                target["stateSha256"] = "3" * 64
                path.write_bytes(encode(target))
            else:
                other = tmp_path / ("3" * 64)
                other.mkdir(mode=0o700)
                observe.SELECTION.unlink()
                observe.SELECTION.symlink_to(other)

    with (
        RestoreStore.locked(root, owner=os.geteuid()) as store,
        pytest.raises(HostRestoreError, match="droplet_restore_destination_changed"),
    ):
        activation.activate_completed_restore(
            store, inputs, caddy, configuration=config, failure_hook=substitute
        )
    assert config.read_bytes() == original
    assert (root / GATE[0]).exists() and not (root / INGRESS[0]).exists()


def test_droplet_scope_remains_required_even_when_activation_files_are_missing(
    native_recovery: tuple[Path, RestoreInputs], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, inputs = native_recovery
    monkeypatch.setattr(
        services, "remove_public_gate", lambda: pytest.fail("ingress opened without authority")
    )
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        (root / "trusted-inputs.json").unlink()
        with pytest.raises(FileNotFoundError):
            activation.activate_completed_restore(store, inputs, root / "no-caddy")
        assert (root / GATE[0]).exists()


def test_installed_delivery_readback_requires_the_original_bundle_and_present_host(
    native_recovery: tuple[Path, RestoreInputs],
) -> None:
    _, inputs = native_recovery
    owner = os.geteuid()
    authority = droplet_restore.AUTHORITY
    artifact = cast(str, inputs.document["originalArtifactSha256"])
    manifest = publication_files(authority, inputs, owner=owner)
    confirmed = delivery_readback(inputs, artifact, owner=owner, authority=authority)
    assert confirmed == {
        "restoreId": inputs.restore_id,
        "trustedInputsDigest": inputs.digest,
        "activationScopeDigest": inputs.droplet_scope_digest,
        "publicationFiles": manifest,
    }
    with pytest.raises(HostRestoreError, match="droplet_restore_destination_changed"):
        delivery_readback(inputs, "d" * 64, owner=owner, authority=authority)
    observe.MACHINE_ID.write_bytes(b"d" * 32 + b"\n")
    with pytest.raises(ValidationError, match="droplet-enrollment-changed"):
        delivery_readback(inputs, artifact, owner=owner, authority=authority)


def test_consistent_droplet_delivery_remains_unavailable_in_docker(
    native_recovery: tuple[Path, RestoreInputs], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recovery, inputs = native_recovery
    owner = os.geteuid()
    authority = droplet_restore.AUTHORITY
    artifact = cast(str, inputs.document["originalArtifactSha256"])
    files = publication_files(authority, inputs, owner=owner)
    marker = tmp_path / "docker-marked"
    marker.touch()
    monkeypatch.setattr(droplet_enrollment, "DOCKER_MARKER", marker)
    with pytest.raises(ValidationError, match="droplet-enrollment-conflicts"):
        delivery_readback(inputs, artifact, owner=owner, authority=authority)
    assert publication_files(authority, inputs, owner=owner) == files
    assert not restore_admission(recovery, owner=owner)
