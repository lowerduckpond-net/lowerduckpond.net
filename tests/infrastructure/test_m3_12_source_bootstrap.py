"""Source delivery and the installed preflight before Caddy/Restic effects."""

from __future__ import annotations

import json
import os
import ssl
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
from lowerduckpond_static_host_agent import (
    caddy_runtime,
    droplet_enrollment,
    entrypoints,
    installed_routing,
    source_bootstrap,
    successor_rollback,
)
from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_GENERATION_ROOT_MODE,
    CaddyBinarySource,
    CaddyGenerationPayload,
    CaddyGenerationStore,
    caddy_route_state_digest,
)
from lowerduckpond_static_host_agent.caddy_routes import build_platform_only_caddy_routes
from lowerduckpond_static_host_agent.caddy_runtime import CADDY_PUBLICATION_LOCK_MODE
from lowerduckpond_static_host_agent.caddy_startup import CaddyStartupStore
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
from scripts import m3_12_droplet_observe
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


def _installed_bootstrap_command(
    caddy: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> Callable[..., tuple[int, str, str]]:
    for name, mode in (("generations", CADDY_GENERATION_ROOT_MODE), ("intents", 0o700)):
        (caddy / name).mkdir(mode=mode)
        (caddy / name).chmod(mode)
    lock = tmp_path / "publication.lock"
    lock.touch(mode=CADDY_PUBLICATION_LOCK_MODE)
    lock.chmod(CADDY_PUBLICATION_LOCK_MODE)
    monkeypatch.setattr(entrypoints, "_CADDY_RUNTIME_ROOT", caddy)
    monkeypatch.setattr(entrypoints, "_CADDY_GENERATION_ROOT", caddy / "generations")
    monkeypatch.setattr(entrypoints, "_CADDY_INTENT_ROOT", caddy / "intents")
    monkeypatch.setattr(entrypoints, "_PUBLICATION_LOCK", lock)
    monkeypatch.setattr(entrypoints.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=0))
    monkeypatch.setattr(entrypoints.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=0))
    binary = tmp_path / "caddy-bin"
    binary.write_bytes(Path("/usr/bin/true").read_bytes())
    binary.chmod(0o755)
    environment = tmp_path / "environment"
    environment.write_bytes(b"CLOUDFLARE_API_TOKEN=fixture\n")
    environment.chmod(0o640)
    ca = tmp_path / "ca.pem"
    der = b"fixture public CA"
    ca.write_text(ssl.DER_cert_to_PEM_cert(der))
    ca.chmod(0o440)
    args = [
        "--origin-pull-required",
        str(binary),
        sha256(binary.read_bytes()).hexdigest(),
        str(environment),
        str(ca),
    ]

    def command(*flags: str) -> tuple[int, str, str]:
        status = entrypoints.caddy_bootstrap_main([*flags, *args])
        output = capfd.readouterr()
        return status, output.out.strip(), output.err.strip()

    # systemd's transient validation scope is outside the local filesystem fixture.
    monkeypatch.setattr(caddy_runtime, "_validate_generation_candidate", lambda *_args, **_kw: None)
    return command


def _select_forged_predecessor(caddy: Path, tmp_path: Path, drift: str) -> None:
    # Publish a manifest-consistent forgery, including a new metadata digest.
    routes = build_platform_only_caddy_routes(
        origin_pull_ca_der=(b"fixture public CA",), origin_pull_required=True
    )
    if drift == "configuration":
        routes.configuration["apps"]["http"]["servers"].clear()
    else:
        routes.route_metadata["routeState"]["platformDomain"] = "other.example"
        routes.route_metadata["routeStateDigest"] = caddy_route_state_digest(
            routes.route_metadata["routeState"]
        ).to_dict()
    bad = "0198d17f-6f4a-7000-8000-000000000099"
    with CaddyGenerationStore.open(
        caddy / "generations", expected_owner=0, expected_group=0
    ) as store:
        store.publish(
            bad,
            CaddyGenerationPayload(
                CaddyBinarySource(tmp_path / "caddy-bin", 0, 0),
                (tmp_path / "environment").read_bytes(),
                routes.configuration,
                routes.route_metadata,
            ),
        )
    (caddy / "active").write_bytes(bad.encode() + b"\n")


def _interrupt_before_selection(
    caddy: Path,
    previous: bytes,
    command: Callable[..., tuple[int, str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def stop(*_args: object, **_kwargs: object) -> None:
        raise caddy_runtime.CaddyRuntimeError("fixture interruption before selection")

    with monkeypatch.context() as patch:
        patch.setattr(caddy_runtime.CaddyRuntime, "select_active", stop)
        assert command() == (1, "", "caddy_generation_bootstrap_failed")
    assert (caddy / "active").read_bytes() == previous
    with monkeypatch.context() as patch:
        patch.setattr(source_bootstrap, "_command", lambda *_args: "{}")
        assert command("--check") == (1, "", "caddy_generation_bootstrap_failed")
        assert command() == (1, "", "caddy_generation_bootstrap_failed")
    assert (caddy / "active").read_bytes() == previous
    assert command("--check") == (0, "pending", "")


@pytest.mark.skipif(os.geteuid() != 0, reason="installed bootstrap verifies root ownership")
@pytest.mark.parametrize(
    "drift",
    [
        "none",
        "configuration",
        "metadata",
        "ingress",
        "launch",
        "wrong-artifact",
        "active-caddy",
        "interrupted",
    ],
)
def test_installed_source_platform_transition(
    handoff: tuple[Document, Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    drift: str,
) -> None:
    document, _, caddy = handoff
    artifact = document["artifactSha256"]
    command = _installed_bootstrap_command(caddy, tmp_path, monkeypatch, capfd)
    # Seed the native predecessor before installing any disposable route authority.
    assert command() == (0, "changed", "")
    previous = (caddy / "active").read_bytes()
    assert command("--check") == (0, "unchanged", "")
    if drift in ("configuration", "metadata"):
        _select_forged_predecessor(caddy, tmp_path, drift)
        previous = (caddy / "active").read_bytes()
    selector = tmp_path / "current"
    target = tmp_path / artifact
    target.mkdir(mode=0o755)
    selector.symlink_to(target)

    monkeypatch.setattr(m3_12_droplet_observe, "SELECTION", selector)
    monkeypatch.setattr(source_bootstrap, "LAUNCH", tmp_path / "absent-launch", raising=False)
    source_bootstrap.receive(encode(document), artifact, owner=0)
    if drift == "ingress":
        monkeypatch.setattr(source_bootstrap, "_command", lambda *_: "{}")
    if drift == "launch":
        (tmp_path / "absent-launch").touch()
    if drift == "wrong-artifact":
        selector.unlink()
    if drift == "active-caddy":
        command_readback = source_bootstrap._command
        monkeypatch.setattr(
            source_bootstrap,
            "_command",
            lambda *args: (
                "ActiveState=active" if args[0] == "/usr/bin/systemctl" else command_readback(*args)
            ),
        )
    if drift not in ("none", "interrupted"):
        for flags in (("--check",), ()):
            assert command(*flags) == (1, "", "caddy_generation_bootstrap_failed")
        assert (caddy / "active").read_bytes() == previous
        assert not list((caddy / "intents").iterdir())
        return
    assert command("--check") == (0, "changed", "")
    assert (caddy / "active").read_bytes() == previous
    if drift == "interrupted":
        _interrupt_before_selection(caddy, previous, command, monkeypatch)
    assert command() == (0, "changed", "")
    selected = (caddy / "active").read_text().strip()
    assert selected.encode() + b"\n" != previous
    assert command("--check") == (0, "pending", "")
    with CaddyStartupStore.open(caddy / "intents", expected_owner=0) as startup:
        pending = startup.read()
        assert pending is not None and pending.previous is not None
        assert pending.previous.generation_id == previous.decode().strip()
        assert pending.candidate.generation_id == selected
        invocation = "5" * 32
        startup.prepare_start(active=pending.candidate, invocation_id=invocation)
        startup.commit_success(
            startup.require_matching_success(active=pending.candidate, invocation_id=invocation)
        )
    assert command("--check") == (0, "unchanged", "")
    assert command() == (0, "unchanged", "")
    assert (caddy / "active").read_text().strip() == selected
