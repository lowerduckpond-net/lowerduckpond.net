"""Offline executions of real journal/reservation/closure adapters.

Only transport boundaries are synthetic. No Docker socket, provider, Connect
server, GitHub endpoint, DNS or CA is contacted by these tests.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import uuid
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

import pytest

from scripts import m3_11_isolation_preparation as preparation
from scripts import m3_11_isolation_watch as watch
from scripts.m3_11_isolation_contract import Intent, Plan
from scripts.m3_11_isolation_host import Host
from scripts.m3_11_isolation_journal import Journal, collect, validate
from scripts.m3_11_isolation_lease import Lease, Provider
from scripts.m3_11_isolation_manifest import Manifest
from scripts.m3_11_isolation_runtime import Evidence, Fence
from scripts.m3_11_isolation_seal import functional, native
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.docker import (
    ADMISSION,
    CLEANUP_VOLUME,
    EVIDENCE_VOLUME,
    OWNER,
    SOCKET,
    Docker,
    helper_volume,
)
from scripts.m3_11_unattended.http import Api
from scripts.m3_11_unattended.model import AuthorityGeneration, digest
from scripts.m3_11_unattended.state import replace_private

from .test_m3_11_lease_inventory import ConnectDouble
from .test_m3_11_public_isolation import NOW, SECRET, START, FakeProvider, issue
from .test_m3_11_public_isolation import intents as intents  # noqa: PLC0414 - pytest fixture export
from .test_m3_11_public_isolation import plan as plan  # noqa: PLC0414 - pytest fixture export


@pytest.fixture(autouse=True)
def no_live_transports(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("live transport forbidden in offline isolation tests")

    monkeypatch.setattr(Docker, "command", forbidden)
    monkeypatch.setattr(Api, "request", forbidden)


@pytest.fixture
def prepared(plan: Plan) -> dict[str, Any]:
    actors = {}
    for index, role in enumerate(("source", "destination", "acme", "archive", "controller"), 1):
        suffix = "host" if role == "source" else role
        actors[role] = {
            "id": str(index) * 64,
            "name": "/ldp-m311-public-ca-" + plan.run_id.replace("-", "")
            if role == "controller"
            else f"/ldp-m3-{plan.run_id.replace('-', '')}-{suffix}",
            "image": "sha256:"
            + (
                plan.controller_sha256
                if role == "controller"
                else plan.archive_image_sha256
                if role == "archive"
                else plan.fixture_image_sha256
            ),
            "owner": plan.run_id.replace("-", ""),
        }
    daemon = {
        "ID": "synthetic",
        "Name": "synthetic",
        "DockerRootDir": "/synthetic",
        "ServerVersion": "29.9.2",
    }
    return preparation.parse(
        {
            "format": preparation.FORMAT,
            "run_id": plan.run_id,
            "source_revision": plan.source_revision,
            "artifact_sha256": plan.artifact_sha256,
            "caddy_binary_sha256": plan.caddy_binary_sha256,
            "daemon_sha256": digest(daemon),
            "original_inputs_sha256": "1" * 64,
            "source_fence_sha256": "2" * 64,
            "guest_program_sha256": digest("synthetic-program"),
            "restore": {
                "restore_id": str(uuid.uuid7()),
                "journal_sha256": "3" * 64,
                "binary_sha256": plan.caddy_binary_sha256,
                "public_store_absent": True,
            },
            "actors": actors,
            "captured_at": START,
            "topology": {
                "docker_endpoint": plan.docker_endpoint,
                "daemon": daemon,
                "network_modes": {
                    role: "host" if role == "controller" else "bridge" for role in actors
                },
            },
        }
    )


@pytest.fixture
def manifest(intents: tuple[Intent, ...], prepared: dict[str, Any]) -> Manifest:
    selected = replace(
        intents[0].plan,
        preparation_sha256=digest(prepared),
        daemon_sha256=cast(str, prepared["daemon_sha256"]),
    )
    intents = tuple(replace(item, plan=selected) for item in intents)
    gen = str(uuid.uuid7())

    def generation(role: str, fingerprint: str) -> AuthorityGeneration:
        return AuthorityGeneration(
            gen,
            role,
            "1" * 64,
            {
                "spaces": "team",
                "cloudflare-account": selected.account_id,
                "cloudflare-user": "d" * 32,
            },
            dict.fromkeys(("spaces", "cloudflare-account", "cloudflare-user"), fingerprint),
            dict.fromkeys(
                ("spaces", "cloudflare-account", "cloudflare-user"), "2026-12-01T00:00:00Z"
            ),
            "2026-12-01T00:00:00Z",
            "2026-10-01T00:00:00Z",
            "2026-11-01T00:00:00Z",
        )

    server, vault = "i" * 26, "j" * 26
    access = {
        "server_sha256": hashlib.sha256(server.encode()).hexdigest(),
        "token_id_sha256": "4" * 64,
        "expires_at": "2026-12-01T00:00:00Z",
        "exact_native_and_signed_policy": True,
        "signed_grants_by_vault_sha256": {
            hashlib.sha256(vault.encode()).hexdigest(): 1008,
            "5" * 64: 48,
        },
        "authenticated": False,
        "create_verified": False,
    }
    return Manifest(
        intents,
        "6" * 64,
        vault,
        server,
        access,
        generation("provision", "e" * 64),
        generation("cleanup", "d" * 64),
    )


@pytest.fixture
def graph(
    tmp_path: Path, manifest: Manifest, prepared: dict[str, Any]
) -> tuple[Host, Journal, Mock]:
    mount = tmp_path / "evidence"
    mount.mkdir(mode=0o700)
    volume = {
        "Name": EVIDENCE_VOLUME,
        "Driver": "local",
        "CreatedAt": START,
        "Mountpoint": "/native/volume",
        "Labels": {OWNER: "true"},
    }
    docker = Mock(spec=Docker)
    docker.endpoint = manifest.plan.docker_endpoint
    daemon = prepared["topology"]["daemon"]
    docker.info.return_value = daemon
    ticket = {
        "format": "lowerduckpond-isolated-public-ca-admission-v1",
        "run_id": manifest.plan.run_id,
        "source_revision": manifest.plan.source_revision,
        "image": "sha256:" + manifest.plan.controller_sha256,
        "daemon": daemon,
        "evidence_volume": volume,
        "container_id": "f" * 64,
    }
    actors = deepcopy(prepared["actors"])
    for value in actors.values():
        value.update(running=True, pid=42, paused=False, restarting=False, restart_policy="no")
    owned = {
        "Id": "5" * 64,
        "Image": ticket["image"],
        "Mounts": [
            {
                "Type": "volume",
                "Name": EVIDENCE_VOLUME,
                "Source": volume["Mountpoint"],
                "Destination": str(mount),
                "RW": True,
            }
        ],
    }
    admission = {
        "Id": "f" * 64,
        "Name": "/" + ADMISSION,
        "Image": ticket["image"],
        "Config": {
            "Cmd": ["true"],
            "Labels": {
                OWNER: "true",
                OWNER + ".public-ca": manifest.plan.run_id,
                OWNER + ".source": manifest.plan.source_revision,
            },
        },
        "HostConfig": {"NetworkMode": "none", "RestartPolicy": {"Name": "no"}},
        "State": {"Running": False, "Pid": 0},
    }
    docker.owned.side_effect = lambda selected: deepcopy(
        admission if selected == "f" * 64 else owned
    )

    def command(*args: str, **kwargs: object) -> bytes:
        if args[:2] == ("volume", "inspect"):
            return json.dumps([volume]).encode()
        if args[:1] == ("exec",):
            stat = mount.stat()
            return json.dumps([stat.st_dev, stat.st_ino, os.geteuid()]).encode()
        if args[:2] == ("inspect", "--format"):
            actor = next(item for item in actors.values() if item["id"] == args[-1])
            role = next(role for role, value in actors.items() if value is actor)
            return json.dumps(
                {**actor, "network_mode": "host" if role == "controller" else "bridge"}
            ).encode()
        if args[0] in {"stop", "kill", "update"}:
            actor = next(item for item in actors.values() if item["id"] == args[-1])
            actor.update(running=False, pid=0, restart_policy="no")
            return b""
        raise AssertionError(args)

    docker.command.side_effect = command
    fence = Fence(cast(Docker, docker), ticket)
    evidence = Evidence(cast(Docker, docker), fence, actor_id="5" * 64, root=mount / "public-ca")
    root = evidence.root / "runs" / manifest.plan.run_id
    root.mkdir(mode=0o700, parents=True)
    (root / "phase").mkdir(mode=0o700)
    write_private(root / "phase/isolation-prepared.json", prepared)
    host = Host(manifest, evidence, directory_path=root, docker=cast(Docker, docker))
    connect = ConnectDouble(manifest.journal_vault)
    journal = Journal(
        connect, manifest, spool=root / "pending", reservation=evidence, guard=host.require
    )
    journal.put("manifest", manifest.document())
    journal.put("prepared", prepared)
    journal.put(
        "confirmed",
        {
            "run_id": 1,
            "run_attempt": 1,
            "event": "workflow_dispatch",
            "helper_revision": manifest.plan.source_revision,
            "observed_at": START,
            "independent_server_id": manifest.independent_server_id,
            "authentication_sha256": "7" * 64,
        },
    )
    return host, journal, docker


def test_real_connect_journal_native_reservation_issue_and_remote_closure(
    graph: tuple[Host, Journal, Mock],
) -> None:
    host, journal, _ = graph
    provider = FakeProvider(host.manifest.plan)
    lease = Lease(host.credentials, host.manifest.intents, journal)
    ids = issue(lease, provider)
    assert len(ids) == len(host.manifest.intents)
    host.stop(journal)
    closure = lease.cleanup(
        cast(Provider, provider), require_issuer_stopped=host.controller_stopped
    )
    remote = Lease(None, host.manifest.intents, Journal(journal.client, host.manifest))
    result = remote.independent_readback(
        cast(Provider, provider), expected=closure, require_issuer_stopped=host.controller_stopped
    )
    assert result["provider_absent"] is True
    assert not provider.items
    with pytest.raises((ValueError, FileExistsError)):
        issue(lease, provider)
    # A different private spool/output cannot defeat the native volume latch.
    with pytest.raises(FileExistsError):
        host.evidence.consume(host.manifest, {"another": "directory"})
    assert SECRET not in json.dumps(journal.all_records())


def test_lost_ack_is_not_reposted_from_pending_spool(graph: tuple[Host, Journal, Mock]) -> None:
    _, journal, _ = graph
    client = cast(ConnectDouble, journal.client)
    client.hidden, client.lose_reply = True, True
    # Journal cannot hide existing immutable prerequisites and publish a new
    # confirmation into an apparently empty namespace.
    with pytest.raises((ValueError, RuntimeError)):
        journal.put("manifest", journal.manifest.document())
    posts = client.posts
    with pytest.raises((ValueError, RuntimeError)):
        journal.put("manifest", journal.manifest.document())
    assert client.posts == posts


def test_quiescence_rejects_replaced_same_name_container(graph: tuple[Host, Journal, Mock]) -> None:
    host, journal, _ = graph
    provider = FakeProvider(host.manifest.plan)
    issue(Lease(host.credentials, host.manifest.intents, journal), provider)
    stopped = host.stop(journal)
    cast(dict[str, Any], stopped["actors"])["destination"]["id"] = "8" * 64
    row = validate(
        {
            "format": "lowerduckpond-isolated-public-ca-journal-v1",
            "manifest_sha256": host.manifest.sha256,
            "kind": "quiesced",
            "payload": stopped,
        },
        host.manifest,
    )
    with pytest.raises(ValueError):
        collect(
            [record for record in journal.all_records() if record["kind"] != "quiesced"] + [row],
            host.manifest,
        )


def test_shadow_mount_cannot_serve_as_durable_reservation(
    graph: tuple[Host, Journal, Mock],
) -> None:
    host, _, docker = graph
    old = docker.owned.side_effect

    def shadow(selected: str) -> dict[str, object]:
        value = cast(dict[str, Any], old(selected))
        if selected != "f" * 64:
            value["Mounts"].append(
                {
                    "Type": "bind",
                    "Destination": str(host.evidence.root / "reservations"),
                    "Source": "/fake",
                    "RW": True,
                }
            )
        return value

    docker.owned.side_effect = shadow
    with pytest.raises(ValueError, match="shadowed"):
        host.evidence.require()


def test_expired_remote_outage_revoke_does_not_claim_not_submitted(
    graph: tuple[Host, Journal, Mock],
) -> None:
    host, journal, _ = graph
    provider = FakeProvider(host.manifest.plan)
    issue(Lease(host.credentials, host.manifest.intents, journal), provider)
    cast(ConnectDouble, journal.client).fail_list = True
    result = Lease(None, host.manifest.intents, journal).revoke_remote(
        cast(Provider, provider), require_issuer_stopped=lambda: None, allow_not_submitted=False
    )
    assert not provider.items
    assert result["status"] == "awaiting-host-denial-proof"
    assert all(
        row["authentication"] == "unavailable"
        for row in cast(dict[str, Any], result["roles"]).values()
    )


def test_native_envelope_digest_is_not_a_status_label() -> None:
    value = {"storage": {"acme/one.key": "1" * 64}, "pid_one": "100"}
    assert native({"sha256": digest(value), "value": value}) == value
    with pytest.raises(ValueError):
        native({"sha256": "0" * 64, "value": value})
    with pytest.raises(ValueError):
        native({"status": "passed"})


def test_closed_consumers_do_not_imply_functional_public_recovery(
    graph: tuple[Host, Journal, Mock],
) -> None:
    host, journal, _ = graph
    issue(Lease(host.credentials, host.manifest.intents, journal), FakeProvider(host.manifest.plan))
    host.stop(journal)
    with pytest.raises(FileNotFoundError):
        functional(host)
    with pytest.raises(TypeError):
        cast(Any, host.evidence.fence).release(host.manifest, prerequisite={"status": "passed"})


def test_watchdog_command_has_cleanup_only_access_and_no_issuance(
    graph: tuple[Host, Journal, Mock],
) -> None:
    host, _, _ = graph
    args = watch.arguments(host.manifest, socket="/synthetic/docker.sock")
    assert args[-3:] == ["-m", "scripts.m3_11_isolation_watch", host.manifest.plan.run_id]
    assert all(
        word not in " ".join(args)
        for word in ("provision", "production", "spaces", "page-rules", SECRET)
    )
    assert "source=ldp-m311-cleanup-config,target=/cleanup,readonly" in " ".join(args)
    assert watch.due(host, now=NOW) is False
    assert watch.due(host, now=NOW + timedelta(hours=4)) is True


def test_local_fencing_precedes_unavailable_cleanup_access(
    graph: tuple[Host, Journal, Mock],
) -> None:
    host, journal, _ = graph
    issue(Lease(host.credentials, host.manifest.intents, journal), FakeProvider(host.manifest.plan))
    access = Mock()
    access.client.side_effect = OSError(SECRET)
    result = host.cleanup(access)
    assert result["status"] == "pending"
    assert "cleanup-authority-unavailable" in cast(list[str], result["failures"])
    assert all(
        host.actor(role)["running"] is False
        for role in ("controller", "source", "destination", "acme", "archive")
    )
    assert SECRET not in json.dumps(result)


def test_journal_outage_does_not_suppress_known_local_revocations(
    graph: tuple[Host, Journal, Mock],
) -> None:
    host, journal, _ = graph
    provider = FakeProvider(host.manifest.plan)
    issue(Lease(host.credentials, host.manifest.intents, journal), provider)
    cast(ConnectDouble, journal.client).fail_list = True
    access = Mock()
    access.client.return_value = journal.client
    access.provider.return_value = provider
    result = host.cleanup(access)
    assert result["status"] == "pending"
    assert not provider.items
    assert len(provider.deleted) == len(host.manifest.intents)
    assert not (host.credentials / "closed.json").exists()


def test_unsafe_context_cannot_skip_remaining_pinned_stops(
    graph: tuple[Host, Journal, Mock],
) -> None:
    host, journal, _ = graph
    issue(Lease(host.credentials, host.manifest.intents, journal), FakeProvider(host.manifest.plan))
    path = host.phase / "isolation-context.json"
    path.write_text(SECRET)
    path.chmod(0o644)
    with pytest.raises(ValueError):
        host.stop(None)
    assert all(
        host.actor(role)["running"] is False
        for role in ("controller", "source", "destination", "acme", "archive")
    )


def test_watchdog_restart_due_path_does_not_require_connect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    host = Mock(spec=Host)
    host.root = tmp_path
    host.manifest = Mock()
    host.manifest.sha256 = "a" * 64
    host.evidence = Mock()
    host.evidence.fence.ticket = {"synthetic": True}
    host.cleanup.return_value = {"status": "verified"}
    access = Mock()
    access.client.side_effect = OSError(SECRET)
    monkeypatch.setattr(watch, "due", lambda *args, **kwargs: True)
    watch.run(host, access, actor_id="1" * 64)
    host.cleanup.assert_called_once_with(access)
    access.client.assert_not_called()
    assert read_private(tmp_path / "watchdog.json")["cleanup_access_verified"] is False


@pytest.mark.parametrize(
    "fault", [None, "entrypoint", "environment", "socket", "shadow", "command", "heartbeat"]
)
def test_actual_prearm_checks_pin_runtime_not_just_actor_name(
    graph: tuple[Host, Journal, Mock], fault: str | None
) -> None:

    host, _, docker = graph
    manifest = host.manifest
    old_owned, old_command = docker.owned.side_effect, docker.command.side_effect
    socket = "/synthetic/outer/docker.sock"
    command = watch.arguments(manifest, socket=socket)
    command = command[command.index("sha256:" + manifest.plan.controller_sha256) + 1 :]
    env = ["PATH=/synthetic", "DOCKER_HOST=unix://" + SOCKET, "PYTHONDONTWRITEBYTECODE=1"]
    actor: dict[str, Any] = {
        "Id": "6" * 64,
        "Name": "/" + watch.name(manifest),
        "Image": "sha256:" + manifest.plan.controller_sha256,
        "Config": {
            "Cmd": command,
            "Entrypoint": ["/usr/local/bin/mise", "exec", "--"],
            "WorkingDir": "/opt/lifecycle",
            "Env": env,
            "Labels": {OWNER: "true", OWNER + ".public-ca": manifest.plan.run_id},
        },
        "State": {"Running": True},
        "HostConfig": {
            "NetworkMode": "host",
            "ReadonlyRootfs": True,
            "RestartPolicy": {"Name": "on-failure"},
        },
        "Mounts": [
            {"Type": "volume", "Name": volume, "Destination": destination, "RW": writable}
            for volume, destination, writable in (
                (helper_volume(manifest.plan.source_revision), "/opt/lifecycle", False),
                (EVIDENCE_VOLUME, "/evidence", True),
                (CLEANUP_VOLUME, "/cleanup", False),
            )
        ]
        + [{"Type": "bind", "Source": socket, "Destination": SOCKET, "RW": True}],
    }

    def owned(selected: str) -> dict[str, object]:
        if selected == watch.name(manifest):
            return deepcopy(actor)
        value = cast(dict[str, Any], old_owned(selected))
        if selected == "5" * 64:
            value["Mounts"].append(
                {"Type": "bind", "Source": socket, "Destination": SOCKET, "RW": True}
            )
        return value

    def dispatch(*args: str, **kwargs: object) -> bytes:
        if args[:2] == ("image", "inspect"):
            return json.dumps(
                [
                    {
                        "Id": "sha256:" + manifest.plan.controller_sha256,
                        "Config": {"Env": ["PATH=/synthetic"]},
                    }
                ]
            ).encode()
        return cast(bytes, old_command(*args, **kwargs))

    docker.owned.side_effect, docker.command.side_effect = owned, dispatch
    heartbeat = {
        "manifest_sha256": manifest.sha256,
        "container_id": actor["Id"],
        "admission_sha256": digest(host.evidence.fence.ticket),
        "cleanup_access_verified": True,
        "observed_at": START,
    }
    replace_private(host.root / "watchdog.json", heartbeat)
    if fault == "entrypoint":
        actor["Config"]["Entrypoint"] = ["sleep"]
    elif fault == "environment":
        actor["Config"]["Env"].append("PYTHONPATH=/untrusted")
    elif fault == "socket":
        actor["Mounts"][-1]["Source"] = "/another/docker.sock"
    elif fault == "shadow":
        actor["Mounts"].append(
            {
                "Type": "bind",
                "Destination": "/opt/lifecycle/scripts",
                "Source": "/shadow",
                "RW": True,
            }
        )
    elif fault == "command":
        actor["Config"]["Cmd"] = ["sleep", "infinity"]
    elif fault == "heartbeat":
        replace_private(
            host.root / "watchdog.json", {**heartbeat, "cleanup_access_verified": False}
        )
    if fault is None:
        watch.require_armed(host, now=NOW)
    else:
        with pytest.raises(ValueError):
            watch.require_armed(host, now=NOW)


def test_installed_entry_loads_pinned_native_helpers_without_test_import_setup() -> None:

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from scripts.m3_11_isolation_controller import installed_adapter; "
            "m=installed_adapter(); "
            "assert m.__name__.endswith('isolated_public_ca_recovery')",
        ],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()


def test_changed_cold_observation_program_never_executes(graph: tuple[Host, Journal, Mock]) -> None:
    host, journal, docker = graph
    provider = FakeProvider(host.manifest.plan)
    issue(Lease(host.credentials, host.manifest.intents, journal), provider)
    write_private(
        host.phase / "isolation-guest-program.json",
        {"program": "raise RuntimeError('changed synthetic program')"},
    )
    access = Mock()
    access.client.return_value, access.provider.return_value = journal.client, provider
    result = host.cleanup(access)
    assert result["status"] == "pending"
    assert "cold-observation-unverified" in cast(list[str], result["failures"])
    assert not any(
        call.args[:2] == ("exec", "--interactive") for call in docker.command.call_args_list
    )
    assert not provider.items


def test_stop_intent_write_failure_cannot_skip_any_owned_stop(
    graph: tuple[Host, Journal, Mock], monkeypatch: pytest.MonkeyPatch
) -> None:
    host, journal, _ = graph
    issue(Lease(host.credentials, host.manifest.intents, journal), FakeProvider(host.manifest.plan))

    def unavailable(*args: object, **kwargs: object) -> None:
        raise OSError("synthetic evidence write failure")

    monkeypatch.setattr("scripts.m3_11_isolation_host.record", unavailable)
    with pytest.raises((ValueError, OSError)):
        host.stop(None)
    assert all(
        host.actor(role)["running"] is False
        for role in ("controller", "source", "destination", "acme", "archive")
    )


def test_heartbeat_write_failure_still_services_due_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    host = Mock(spec=Host)
    host.root, host.manifest, host.evidence = tmp_path, Mock(), Mock()
    host.manifest.sha256 = "a" * 64
    host.evidence.fence.ticket = {"synthetic": True}
    host.cleanup.return_value = {"status": "verified"}
    monkeypatch.setattr(watch, "due", lambda *args, **kwargs: True)

    def unavailable(*args: object, **kwargs: object) -> None:
        raise OSError("synthetic evidence write failure")

    monkeypatch.setattr(watch, "replace_private", unavailable)
    with pytest.raises(OSError):
        watch.run(host, Mock(), actor_id="1" * 64)
    host.cleanup.assert_called_once()
