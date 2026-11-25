"""Source delivery and the installed preflight before Caddy/Restic effects."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from lowerduckpond_static_host_agent import (
    droplet_enrollment,
    installed_routing,
    source_bootstrap,
    successor_rollback,
)
from lowerduckpond_static_host_agent.caddy_routes import build_platform_only_caddy_routes
from lowerduckpond_static_host_agent.disposable_routes import project_native_routes
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError

from infrastructure.test_m3_12_contracts import _pin_droplet_attempt
from infrastructure.test_m3_12_contracts import droplet_attempt as droplet_attempt  # noqa: PLC0414
from infrastructure.test_m3_12_disposable_routing import _native_firewall
from infrastructure.test_m3_12_droplet_journey import fixture as fixture  # noqa: PLC0414
from infrastructure.test_m3_12_droplet_journey import proof
from infrastructure.test_m3_12_droplet_journey import records as records  # noqa: PLC0414
from scripts import m3_11_production_lease as lease
from scripts import m3_12_droplet as droplet
from scripts.m3_12_contracts import Document, ValidationError, digest, encode
from scripts.m3_12_diagnostic_store import Attempt
from scripts.m3_12_droplet_scope import ReviewedJourney


@pytest.fixture
def handoff(
    fixture: tuple[Attempt, Document, ReviewedJourney],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Document, Path, Path]:
    _, scope, review = fixture
    source = scope["resources"]["hosts"]["source"]
    enrollment = source["enrollment"]
    authority = tmp_path / "m3-12" / droplet_enrollment.PUBLICATION_VIEW
    caddy = tmp_path / "caddy"
    caddy.mkdir(mode=0o750)
    caddy.chmod(0o750)
    for module in (source_bootstrap, installed_routing):
        monkeypatch.setattr(module, "AUTHORITY", authority)
        monkeypatch.setattr(module, "CADDY_ROOT", caddy)
    monkeypatch.setattr(droplet_enrollment, "DOCKER_MARKER", tmp_path / "absent-fixture-marker")
    monkeypatch.setattr(
        droplet_enrollment,
        "host_identity",
        lambda _owner: {
            label: enrollment[label]
            for label in ("hostKeySha256", "machineSha256", "systemUuidSha256")
        },
    )
    monkeypatch.setattr(source_bootstrap, "boot_sha256", lambda _owner: proof("source boot"))
    monkeypatch.setattr(source_bootstrap, "predecessor_digest", lambda: scope["predecessorSha256"])
    monkeypatch.setattr(source_bootstrap, "publication_state", lambda _owner: "dark")
    monkeypatch.setattr(
        source_bootstrap,
        "metadata_identity",
        lambda: (source["target"]["droplet"]["dropletId"], enrollment["ipv4"]),
    )
    monkeypatch.setattr(
        source_bootstrap.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=os.getgid())
    )

    def observe(*command: str) -> str:
        if command[0] == "/usr/sbin/nft":
            assert command[-1] == "lowerduckpond_restore"
            return json.dumps(_native_firewall())
        assert command == (
            "/usr/bin/systemctl",
            "show",
            "--property=ActiveState",
            "--property=UnitFileState",
            "caddy.service",
        )
        return "ActiveState=inactive\nUnitFileState=masked-runtime"

    monkeypatch.setattr(source_bootstrap, "_command", observe)
    bundle = {
        "format": source_bootstrap.FORMAT,
        "artifactSha256": scope["candidate"]["hostAgentSha256"],
        "bootSha256": proof("source boot"),
        "predecessorSha256": scope["predecessorSha256"],
        "repository": "s3:https://abc7.digitaloceanspaces.com/source-restic/runs/example",
        "backupRegion": "abc7",
        "archiveBucket": "source-archive",
        "archiveRegion": "abc7",
        "routing": {
            "format": "lowerduckpond-m3-12-disposable-routing-v1",
            "allocationSha256": digest(scope),
            "runId": scope["runId"],
            "invocationId": scope["invocationId"],
            "sourceTargetSha256": digest(source["target"]),
            "restoreTargetSha256": digest(scope["resources"]["hosts"]["restore"]["target"]),
            "platform": "source.platform.example",
            "tenantScope": "source.tenant.example",
            "tenants": [],
        },
        "enrollment": {
            droplet_enrollment.TARGET: source["target"],
            droplet_enrollment.ENROLLMENT: enrollment,
            droplet_enrollment.EXCLUSIONS: json.loads(review.production_exclusions)["hosts"],
        },
    }
    return bundle, authority, caddy


def test_source_delivery_pins_then_checks_effective_site_inputs(
    handoff: tuple[Document, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    document, authority, caddy = handoff
    artifact, owner = document["artifactSha256"], os.geteuid()
    raw = encode(document)
    assert source_bootstrap.receive(raw, artifact, owner=owner) == digest(document)
    assert source_bootstrap.receive(raw, artifact, owner=owner) == digest(document)
    routing = installed_routing.installed_projection(owner=owner)
    assert routing is not None
    installed_routing.require_role(routing, "source", owner=owner)
    source_bootstrap.require_source_projection(routing, owner=owner)
    configuration = project_native_routes(
        build_platform_only_caddy_routes(
            origin_pull_ca_der=(b"fixture public CA",), origin_pull_required=True
        ),
        routing,
    ).configuration
    assert set(configuration["apps"]["tls"]["automation"]["policies"][0]["subjects"]) == {
        "*.source.platform.example",
        "*.source.tenant.example",
        "source.platform.example",
        "source.tenant.example",
    }
    request = {key: document[key] for key in source_bootstrap.INPUTS}
    source_bootstrap.verify(request, artifact, owner=owner)
    for wrong in (
        {"repository": "s3:https://abc7.digitaloceanspaces.com/wrong/runs/example"},
        {"archiveBucket": "wrong-archive"},
    ):
        with pytest.raises(ValidationError, match="droplet-source-site-inputs-changed"):
            source_bootstrap.verify({**request, **wrong}, artifact, owner=owner)
    monkeypatch.setattr(source_bootstrap, "_command", lambda *_args: "{}")
    with pytest.raises(ValidationError, match="droplet-source-ingress-open"):
        source_bootstrap.verify(request, artifact, owner=owner)
    assert (authority / installed_routing.SOURCE_BOOTSTRAP).read_bytes() == raw
    assert (caddy / installed_routing.PROJECTION).stat().st_mode & 0o777 == 0o440  # noqa: PLR2004 - Caddy view


@pytest.mark.parametrize("invalid", ["boot", "role", "open-ingress", "active-caddy", "production"])
def test_source_delivery_refuses_before_creating_local_authority(
    handoff: tuple[Document, Path, Path], monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    document, authority, caddy = handoff
    if invalid == "boot":
        document["bootSha256"] = proof("prior boot")
    elif invalid == "role":
        document["routing"]["sourceTargetSha256"] = proof("foreign source")
    elif invalid == "open-ingress":
        monkeypatch.setattr(source_bootstrap, "_command", lambda *_args: "{}")
    elif invalid == "active-caddy":
        original = source_bootstrap._command
        monkeypatch.setattr(
            source_bootstrap,
            "_command",
            lambda *args: "active" if args[0] == "/usr/bin/systemctl" else original(*args),
        )
    else:
        (authority.parent).mkdir(mode=0o700)
        (authority.parent / "transaction.json").touch(mode=0o600)
    with pytest.raises(ValidationError):
        source_bootstrap.receive(encode(document), document["artifactSha256"], owner=os.geteuid())
    assert not authority.exists()
    assert not (caddy / installed_routing.PROJECTION).exists()


def test_pending_delivery_cannot_start_caddy_with_canonical_subjects(
    handoff: tuple[Document, Path, Path],
) -> None:
    document, authority, _ = handoff
    authority.mkdir(mode=0o700, parents=True)
    original = authority / installed_routing.SOURCE_BOOTSTRAP
    original.write_bytes(encode(document))
    original.chmod(0o600)
    with pytest.raises(HostRestoreError, match="restore_disposable_routing_role_missing"):
        installed_routing.require_caddy_routing(None)


def test_enabled_site_handoff_requires_the_original_verified_launch(
    handoff: tuple[Document, Path, Path],
    droplet_attempt: tuple[Document, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document, _, caddy = handoff
    admission, state, authority = droplet_attempt
    owner = os.geteuid()
    artifact = admission["candidate"]["hostAgentSha256"]
    document["artifactSha256"] = artifact
    document["routing"].update(
        runId=admission["binding"]["runId"], sourceTargetSha256=digest(admission["target"])
    )
    for name in document["enrollment"]:
        document["enrollment"][name] = json.loads((authority / name).read_bytes())
    receipt = authority / installed_routing.SOURCE_BOOTSTRAP
    original = encode(document)
    receipt.write_bytes(original)
    receipt.chmod(0o600)
    routing = source_bootstrap.DisposableRoutes.from_bytes(encode(document["routing"]))
    role = authority / installed_routing.ROLE
    role.write_bytes(encode(routing.role_document("source")))
    role.chmod(0o600)
    projection = caddy / installed_routing.PROJECTION
    projection.write_bytes(encode(routing.document()))
    projection.chmod(0o440)
    monkeypatch.setattr(source_bootstrap, "AUTHORITY", authority)
    monkeypatch.setattr(installed_routing, "AUTHORITY", authority)
    monkeypatch.setattr(source_bootstrap, "STATE", state)
    request = {key: document[key] for key in source_bootstrap.INPUTS}
    with pytest.raises(FileNotFoundError, match=r"admission\.json"):
        source_bootstrap.verify(request, artifact, publication_enabled=True, owner=owner)

    with lease.controller(droplet.LEASE, owner=owner, drain=lambda: None) as token:
        _pin_droplet_attempt(authority, admission, token)
        droplet.launch(token, encode(admission), owner=owner)

    source_bootstrap.verify(request, artifact, publication_enabled=True, owner=owner)
    monkeypatch.setattr(source_bootstrap, "publication_state", lambda _owner: "enabled")
    monkeypatch.setattr(source_bootstrap, "boot_sha256", lambda _owner: proof("current reboot"))
    source_bootstrap.verify(request, artifact, publication_enabled=True, owner=owner)
    with pytest.raises(ValidationError, match="droplet-source-site-inputs-changed"):
        source_bootstrap.verify(
            {**request, "archiveBucket": "foreign"}, artifact, publication_enabled=True, owner=owner
        )
    with monkeypatch.context() as changed:
        changed.setattr(droplet, "SELECTION", caddy / "missing-selector")
        with pytest.raises(ValidationError, match="droplet-source-launch-changed"):
            source_bootstrap.verify(request, artifact, publication_enabled=True, owner=owner)
    with monkeypatch.context() as changed:
        changed.setattr(source_bootstrap, "_command", lambda *_: "{}")
        with pytest.raises(ValidationError, match="droplet-source-ingress-open"):
            source_bootstrap.verify(request, artifact, publication_enabled=True, owner=owner)
    authority.joinpath(*successor_rollback.FENCE).touch(mode=0o600)
    with pytest.raises(ValidationError, match="successor-publication-fenced"):
        source_bootstrap.verify(request, artifact, publication_enabled=True, owner=owner)
    assert receipt.read_bytes() == original
