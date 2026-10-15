"""Replay the exact deployed reader, without services or provider credentials.

The ledger fixture is byte-for-byte from the installed 0b5b198 helper. Only its
removed checkpoint type/title alias are supplied by this harness; the actual
class, publication, readback, snapshot and acknowledgement code are executed.
"""

from __future__ import annotations

import ast
import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, NamedTuple, cast

import pytest

from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import legacy_actors, legacy_diagnostics
from scripts.m3_11_unattended import legacy_bridge_contract as contract
from scripts.m3_11_unattended import legacy_import_reader as bridge
from scripts.m3_11_unattended.connect_activate import publish_import
from scripts.m3_11_unattended.connect_api import Response
from scripts.m3_11_unattended.docker import CLEANUP_VOLUME, EVIDENCE_VOLUME, OWNER, Docker
from scripts.m3_11_unattended.journal import TAG, event, migration, record_title
from scripts.m3_11_unattended.model import LifecycleError, digest, stamp
from scripts.m3_11_unattended.operator_records import migration_body

from .operator_host_support import IMAGE
from .test_m3_11_lease_inventory import ConnectDouble
from .test_m3_11_lease_migration import note
from .test_m3_11_legacy_discovery import DiscoveryCase

VAULT = "j" * 26
AUTHOR = "A" * 26
ANCHOR = "a" * 26
IMPORT = "i" * 26
FIXTURE = Path(__file__).parent / "fixtures/m3_11_legacy_connect_ledger.py.txt"
Row = dict[str, Any]


class Stored(NamedTuple):
    identity: int
    sha256: str


def legacy_module() -> ModuleType:
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == bridge.LEDGER_SHA256
    source = ast.parse(FIXTURE.read_text(), filename=str(FIXTURE))
    for node in list(source.body):
        if isinstance(node, ast.ImportFrom):
            if node.module == "scripts.m3_11_unattended.connect_checkpoint":
                source.body.remove(node)
            elif node.module == "scripts.m3_11_unattended.journal":
                node.names = [name for name in node.names if name.name != "OpJournal"]
    module = ModuleType("deployed_legacy_ledger")
    module.__file__ = str(FIXTURE)
    module.__dict__.update(Stored=Stored, OpJournal=SimpleNamespace(_title=record_title))
    exec(compile(source, str(FIXTURE), "exec"), module.__dict__)  # noqa: S102 - hash-pinned test evidence
    return module


def native(item_id: str, title: str, tag: str, body: Row) -> Row:
    return {
        "id": item_id,
        "title": title,
        "category": "SECURE_NOTE",
        "tags": [tag],
        "vault": {"id": VAULT},
        "lastEditedBy": AUTHOR,
        "version": 1,
        "createdAt": "2026-10-14T00:00:00Z",
        "updatedAt": "2026-10-14T00:00:00Z",
        "fields": [
            {"id": "notesPlain", "purpose": "NOTES", "value": canonical_bytes(body).decode()}
        ],
    }


class Service:
    def __init__(self) -> None:
        self.original = event("heartbeat", "01900000-0000-7000-8000-000000000001", {"test": True})
        self.mapping = {"format": "lowerduckpond-m3-11-legacy-import-v2", "synthetic": True}
        self.expected = digest(self.mapping)
        self.items = {ANCHOR: native(ANCHOR, record_title(self.original), TAG, self.original)}
        self.count_offset = 0
        self.duplicate = False
        self.lists = 0
        self.posts = 0
        self.grow = False
        self.uncertain = False

    def add_import(self) -> None:
        self.items[IMPORT] = native(
            IMPORT, "m3-11-import-" + self.expected, bridge.IMPORT_TAG, self.mapping
        )

    def item(self, vault: str, item_id: str) -> Row:
        assert vault == VAULT
        return deepcopy(self.items[item_id])

    def request(self, method: str, path: str, body: Row | None = None) -> Response:
        assert path.startswith("/v1/vaults/" + VAULT)
        if method == "POST":
            self.posts += 1
            assert body is not None
            if self.uncertain:
                raise LifecycleError("synthetic lost POST")
            self.items["p" * 26] = native(
                "p" * 26, body["title"], TAG, json.loads(body["fields"][0]["value"])
            )
            return Response(200, self.items["p" * 26])
        assert method == "GET"
        if path.endswith("/items"):
            self.lists += 1
            if self.grow and self.lists == 2:  # noqa: PLR2004 - second side of snapshot
                self.add_import()
            rows = list(deepcopy(self.items).values())
            return Response(200, rows + rows[:1] if self.duplicate else rows)
        return Response(
            200, {"id": VAULT, "items": len(self.items) + self.count_offset, "contentVersion": 1}
        )


def ledger(tmp_path: Path, service: Service, *, patched: bool = True) -> Any:  # noqa: ANN401 - exact old module
    module = legacy_module()
    observations: list[dict[str, object]] = []
    if patched:
        bridge.install(module, vault=VAULT, expected=service.expected, observe=observations.append)
    result = module.ConnectLedger(
        service,
        VAULT,
        spool=tmp_path,
        anchor=ANCHOR,
        anchor_sha256=digest(service.original),
        minimum={service.original["event_id"]: digest(service.original)},
        readback_seconds=0,
    )
    result.observations = observations
    return result


def test_actual_old_reader_rejects_import_and_bridge_preserves_logical_checkpoint(
    tmp_path: Path,
) -> None:
    service = Service()
    original = ledger(tmp_path / "old", service, patched=False)
    assert original.records() == [service.original]
    service.add_import()
    with pytest.raises(LifecycleError, match="metadata"):
        original.records()
    reader = ledger(tmp_path / "bridge", service)
    assert reader.records() == [service.original]
    assert reader._known == original._known
    assert reader._items == original._items
    assert reader._metadata == original._metadata
    assert reader.observed_records() == [service.original]
    assert reader.authors(service.original) == {AUTHOR}
    assert reader.observations[-1]["physical_items"] == 2  # noqa: PLR2004 - import plus original
    assert reader.observations[-1]["legacy_records"] == 1
    assert reader.observations[-1]["import_visible"] is True
    assert service.posts == 0


def test_existing_independent_acknowledgement_remains_a_legacy_event(tmp_path: Path) -> None:
    service = Service()
    service.add_import()
    reader = ledger(tmp_path, service)
    arguments = {"independent_server": "B" * 26, "independent_author": AUTHOR, "binding": {}}
    assert not reader.confirmed(service.original, **arguments)
    acknowledgement = event(
        "heartbeat",
        str(service.original["run_id"]),
        {
            "format": "lowerduckpond-m3-11-connect-ack-v1",
            "event_id": service.original["event_id"],
            "event_sha256": digest(service.original),
            "binding": {},
            "github_run_id": 1,
            "github_run_attempt": 1,
            "independent_server_id": "B" * 26,
            "checkpoint": {"identity": 1, "sha256": "f" * 64},
        },
    )
    service.items["k" * 26] = native("k" * 26, record_title(acknowledgement), TAG, acknowledgement)
    assert reader.confirmed(service.original, **arguments)
    assert set(reader._known) == {service.original["event_id"], acknowledgement["event_id"]}
    assert service.posts == 0


@pytest.mark.parametrize(
    "fault",
    [
        "count",
        "duplicate-id",
        "unknown-note",
        "wrong-hash",
        "wrong-tag",
        "changed-version",
        "duplicate-import",
        "noncanonical",
        "metadata",
        "missing-anchor",
        "changed-original",
    ],
)
def test_bridge_never_turns_invalid_inventory_into_cleanup_evidence(
    tmp_path: Path, fault: str
) -> None:
    service = Service()
    service.add_import()
    reader = ledger(tmp_path, service)
    assert reader.records() == [service.original]
    imported = service.items[IMPORT]
    if fault == "count":
        service.count_offset = 1
    elif fault == "duplicate-id":
        service.duplicate = True
    elif fault == "unknown-note":
        service.items["u" * 26] = native("u" * 26, "not-a-lifecycle-fact", "other", {})
    elif fault == "wrong-hash":
        imported["fields"][0]["value"] = canonical_bytes(
            {**service.mapping, "changed": True}
        ).decode()
    elif fault == "wrong-tag":
        imported["tags"] = [TAG]
    elif fault == "changed-version":
        imported["version"] = 2
    elif fault == "duplicate-import":
        service.items["d" * 26] = {**deepcopy(imported), "id": "d" * 26}
    elif fault == "noncanonical":
        imported["fields"][0]["value"] += "\n"
    elif fault == "metadata":
        imported["lastEditedBy"] = "B" * 26
    elif fault == "missing-anchor":
        del service.items[ANCHOR]
    else:
        service.items[ANCHOR]["title"] = service.items[ANCHOR]["title"][:-64] + "f" * 64
    with pytest.raises((LifecycleError, ValueError)):
        reader.records()
    assert reader.observations[-1]["status"] == "unresolved"
    assert service.posts == 0


@pytest.mark.parametrize("replace", [False, True])
def test_import_identity_is_pinned_across_reader_restart(tmp_path: Path, replace: bool) -> None:
    service = Service()
    service.add_import()
    ledger(tmp_path, service).records()
    removed = service.items.pop(IMPORT)
    if replace:
        service.items["r" * 26] = {**removed, "id": "r" * 26}
    with pytest.raises(LifecycleError, match=r"identity changed|disappeared"):
        ledger(tmp_path, service).records()


def test_import_appearance_requires_a_new_complete_snapshot(tmp_path: Path) -> None:
    service = Service()
    service.grow = True
    reader = ledger(tmp_path, service)
    with pytest.raises(LifecycleError, match="synchronized"):
        reader.records()
    assert reader.records() == [service.original]


@pytest.mark.parametrize("uncertain", [False, True])
def test_existing_publication_keeps_pending_and_never_replays_post(
    tmp_path: Path, uncertain: bool
) -> None:
    service = Service()
    service.add_import()
    service.uncertain = uncertain
    reader = ledger(tmp_path, service)
    genuine = event(
        "heartbeat", str(service.original["run_id"]), {"synthetic-existing-protocol": True}
    )
    if uncertain:
        with pytest.raises(LifecycleError, match="uncertain"):
            reader.stage(genuine)
        with pytest.raises(LifecycleError, match="uncertain"):
            ledger(tmp_path, service).stage(genuine)
    else:
        assert reader.stage(genuine)
        assert ledger(tmp_path, service).stage(genuine)
    assert service.posts == 1
    assert json.loads((tmp_path / (str(genuine["event_id"]) + ".json")).read_text()) == genuine


def test_unbound_or_twice_patched_source_is_rejected() -> None:
    module = legacy_module()
    bridge.install(module, vault=VAULT, expected="a" * 64)
    with pytest.raises(ValueError, match="binding"):
        bridge.install(module, vault=VAULT, expected="a" * 64)
    module = legacy_module()
    module.__file__ = __file__
    with pytest.raises(ValueError, match="binding"):
        bridge.install(module, vault=VAULT, expected="a" * 64)


class Host:
    def __init__(self) -> None:
        self.bridge_sha256 = hashlib.sha256(Path(bridge.__file__).read_bytes()).hexdigest()
        self.old: Row = {
            "Id": "a" * 64,
            "Name": "/ldp-m311-watchdog-" + bridge.LEGACY_REVISION[:12],
            "Config": {
                "Cmd": [
                    "uv",
                    "run",
                    "--no-sync",
                    "--frozen",
                    "python",
                    "-m",
                    "scripts.m3_11_unattended.cleanup",
                    "--config",
                    "/cleanup/cleanup.json",
                    "--actor",
                    "watchdog",
                    "--watch",
                    "--runs",
                    "/evidence/runs",
                ],
                "Entrypoint": list(contract.ENTRYPOINT),
            },
            "State": {"Running": False, "Restarting": False, "Paused": False, "Dead": False},
            "HostConfig": {"RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}},
        }
        self.bridged: Row = {
            "Id": "b" * 64,
            "Image": IMAGE,
            "Name": "/ldp-m311-import-watchdog-" + self.bridge_sha256[:12],
            "Config": {
                "Labels": {OWNER + ".source": bridge.LEGACY_REVISION},
                "Cmd": bridge.watchdog_command(VAULT, "a" * 64),
                "Entrypoint": list(contract.ENTRYPOINT),
                "Env": [key + "=" + value for key, value in contract.ENVIRONMENT.items()],
                "WorkingDir": "/opt/lifecycle",
                "User": "",
            },
            "State": {"Running": True, "Restarting": False, "Paused": False, "Dead": False},
            "HostConfig": {
                "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
                "NetworkMode": "host",
                "Runtime": "runc",
                "ReadonlyRootfs": False,
                "Privileged": False,
                "AutoRemove": False,
            },
            "Mounts": [
                {"Type": "volume", "Name": name, "Destination": destination, "RW": writable}
                for destination, name, writable in (
                    ("/cleanup", CLEANUP_VOLUME, False),
                    ("/evidence", EVIDENCE_VOLUME, True),
                    ("/opt/lifecycle", "ldp-m311-helper-" + bridge.LEGACY_REVISION, False),
                    ("/opt/import-bridge", "ldp-m311-import-bridge-" + self.bridge_sha256, False),
                )
            ]
            + [
                {
                    "Type": "bind",
                    "Source": "/docker-sock/docker.sock",
                    "Propagation": "rprivate",
                    "Destination": "/var/run/docker.sock",
                    "RW": True,
                }
            ],
        }
        self.rows = [self.old, self.bridged]
        self.source_head = bridge.LEGACY_REVISION
        self.source_status = b""

    def command(self, *args: str) -> bytes:
        if args[0] == "exec":
            assert args[1] == self.bridged["Id"]
            if not self.bridged["State"]["Running"]:
                raise LifecycleError("synthetic Docker exec: container is stopped")
            assert args[2:10] == (
                "/usr/bin/git",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-C",
                "/opt/lifecycle",
            )
            if args[10:] == ("rev-parse", "HEAD"):
                return (self.source_head + "\n").encode()
            assert args[10:] == ("status", "--porcelain=v1", "--untracked-files=all")
            return self.source_status
        assert args == (
            "ps",
            "--all",
            "--filter",
            "label=" + OWNER + "=true",
            "--no-trunc",
            "--format",
            "{{.ID}} {{.Names}}",
        )
        return "\n".join(row["Id"] + " " + row["Name"][1:] for row in self.rows).encode()

    def owned(self, item_id: str) -> Row:
        return next(row for row in self.rows if row["Id"] == item_id)


def attach_bridge(case: DiscoveryCase, monkeypatch: pytest.MonkeyPatch) -> Host:
    """Expose an exact synthetic bridge to every Docker client in the real host utility."""
    from scripts.m3_11_private_inputs import read_private  # noqa: PLC0415 - fixture setup

    monkeypatch.setattr(bridge, "LEGACY_REVISION", case.intent.helper_revision)
    host = Host()
    approved = read_private(case.studio / "migration/legacy-import.json")
    host.bridged["Config"]["Cmd"] = bridge.watchdog_command(
        str(cast(dict[str, object], case.services.manifest["vaults"])["journal"]), digest(approved)
    )
    host.bridged["Config"]["Labels"][OWNER] = "true"
    case.host.rows[host.bridged["Name"].removeprefix("/")] = host.bridged
    hashes = {
        bridge.PROGRAM: host.bridge_sha256,
        "/opt/lifecycle/scripts/m3_11_unattended/connect_ledger.py": bridge.LEDGER_SHA256,
        "/opt/lifecycle/scripts/m3_11_unattended/connect_auth.py": bridge.INSPECTOR_SHA256,
    }
    monkeypatch.setattr(legacy_diagnostics, "script_digest", lambda _host, _id, path: hashes[path])
    command = case.host.command

    def external(arguments: list[str], stdin: bytes | None = None) -> bytes:
        if arguments[:2] == ["exec", host.bridged["Id"]]:
            return host.command(*arguments)
        return command(arguments, stdin)

    case.services.docker_handler = external
    return host


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "running-old",
        "restart-old",
        "no-bridge",
        "stopped-bridge",
        "only-bridge-stopped",
        "missing-restart-policy",
        "restart-disabled",
        "restart-on-failure",
        "restart-always",
        "restart-retry-limit",
        "wrong-binding",
        "wrong-program",
        "wrong-ledger",
        "wrong-authentication",
        "wrong-command",
    ],
)
def test_all_host_readers_are_compatible_or_fenced_before_import(
    monkeypatch: pytest.MonkeyPatch,
    fault: str | None,
) -> None:
    host = Host()
    restart_faults = {
        "missing-restart-policy": {},
        "restart-disabled": {"RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}},
        "restart-on-failure": {"RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 0}},
        "restart-always": {"RestartPolicy": {"Name": "always", "MaximumRetryCount": 0}},
        "restart-retry-limit": {
            "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 3}
        },
    }
    hashes = {
        bridge.PROGRAM: host.bridge_sha256,
        "/opt/lifecycle/scripts/m3_11_unattended/connect_ledger.py": bridge.LEDGER_SHA256,
        "/opt/lifecycle/scripts/m3_11_unattended/connect_auth.py": bridge.INSPECTOR_SHA256,
    }
    monkeypatch.setattr(legacy_diagnostics, "script_digest", lambda _host, _id, path: hashes[path])
    if fault == "running-old":
        host.old["State"]["Running"] = True
    elif fault == "restart-old":
        host.old["HostConfig"]["RestartPolicy"]["Name"] = "unless-stopped"
    elif fault == "no-bridge":
        host.rows.pop()
    elif fault == "stopped-bridge":
        host.bridged["State"]["Running"] = False
    elif fault == "only-bridge-stopped":
        host.rows.remove(host.old)
        host.bridged["State"]["Running"] = False
    elif fault in restart_faults:
        host.bridged["HostConfig"].pop("RestartPolicy")
        host.bridged["HostConfig"].update(restart_faults[fault])
    elif fault == "wrong-binding":
        host.bridged["Config"]["Cmd"] = bridge.watchdog_command(VAULT, "b" * 64)
    elif fault == "wrong-program":
        hashes[bridge.PROGRAM] = "f" * 64
    elif fault in {"wrong-ledger", "wrong-authentication"}:
        module = "connect_ledger" if fault == "wrong-ledger" else "connect_auth"
        hashes["/opt/lifecycle/scripts/m3_11_unattended/" + module + ".py"] = "f" * 64
    elif fault == "wrong-command":
        host.bridged["Config"]["Cmd"].append("--other")
    if fault is not None:
        with pytest.raises(LifecycleError):
            legacy_actors.require_import_readers(
                cast(Docker, host), vault=VAULT, expected="a" * 64, images={IMAGE}
            )
    else:
        legacy_actors.require_import_readers(
            cast(Docker, host), vault=VAULT, expected="a" * 64, images={IMAGE}
        )


@pytest.mark.parametrize(
    "destination", ["/cleanup", "/evidence", "/opt/lifecycle", "/opt/import-bridge"]
)
@pytest.mark.parametrize(
    "fault",
    [
        None,
        "missing",
        "wrong-volume",
        "bind",
        "wrong-mode",
        "missing-mode",
        "duplicate",
        "shadow",
        "subpath",
    ],
)
def test_import_requires_exact_bridge_mounts(
    monkeypatch: pytest.MonkeyPatch, destination: str, fault: str | None
) -> None:
    host = Host()
    hashes = {
        bridge.PROGRAM: host.bridge_sha256,
        "/opt/lifecycle/scripts/m3_11_unattended/connect_ledger.py": bridge.LEDGER_SHA256,
        "/opt/lifecycle/scripts/m3_11_unattended/connect_auth.py": bridge.INSPECTOR_SHA256,
    }
    monkeypatch.setattr(legacy_diagnostics, "script_digest", lambda _host, _id, path: hashes[path])
    mounts = host.bridged["Mounts"]
    mount = next(row for row in mounts if row["Destination"] == destination)
    if fault == "missing":
        mounts.remove(mount)
    elif fault == "wrong-volume":
        mount["Name"] += "-other"
    elif fault == "bind":
        mount["Type"] = "bind"
        mount["Source"] = "/some/other/directory"
    elif fault == "wrong-mode":
        mount["RW"] = not mount["RW"]
    elif fault == "missing-mode":
        del mount["RW"]
    elif fault == "duplicate":
        mounts.append(deepcopy(mount))
    elif fault == "shadow":
        child = {
            "/cleanup": "cleanup.json",
            "/evidence": "runs",
            "/opt/lifecycle": "scripts/m3_11_unattended/connect_access.py",
            "/opt/import-bridge": "legacy_import_reader.py",
        }[destination]
        mounts.append({**mount, "Destination": destination + "/" + child})
    elif fault == "subpath":
        host.bridged["HostConfig"]["Mounts"] = [
            {"Type": "volume", "Target": destination, "VolumeOptions": {"Subpath": "other"}}
        ]
    if fault is None:
        legacy_actors.require_import_readers(
            cast(Docker, host), vault=VAULT, expected="a" * 64, images={IMAGE}
        )
        assert host.bridged["Id"] not in legacy_actors.inventory(
            cast(Docker, host), reader_images={IMAGE}
        )
    else:
        # Correct scripts, command and running/restart state cannot mask a bad mount.
        with pytest.raises(LifecycleError, match="unbridged legacy reader"):
            legacy_actors.require_import_readers(
                cast(Docker, host), vault=VAULT, expected="a" * 64, images={IMAGE}
            )
        assert host.bridged["Id"] in legacy_actors.inventory(
            cast(Docker, host), reader_images={IMAGE}
        )


@pytest.mark.parametrize("mounts", [None, {}, [], [None], [{"Destination": 42}]])
def test_import_rejects_missing_or_malformed_mount_inventory(
    monkeypatch: pytest.MonkeyPatch, mounts: object
) -> None:
    host = Host()
    host.bridged["Mounts"] = mounts
    monkeypatch.setattr(
        legacy_diagnostics, "script_digest", lambda *_: pytest.fail("invalid mounts reached exec")
    )
    with pytest.raises(LifecycleError, match="unbridged legacy reader"):
        legacy_actors.require_import_readers(
            cast(Docker, host), vault=VAULT, expected="a" * 64, images={IMAGE}
        )


@pytest.mark.parametrize(
    "fault",
    [
        "stopped",
        "restart-disabled",
        "missing-cleanup",
        "wrong-evidence",
        "missing-socket",
        "wrong-endpoint",
        "removed-after-discovery",
        "removed-after-original-publication",
    ],
)
def test_import_rechecks_reader_after_publishing_originals(  # noqa: PLR0915 - full pending continuation
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = DiscoveryCase(tmp_path, monkeypatch)
    monkeypatch.setattr(bridge, "LEGACY_REVISION", case.intent.helper_revision)
    client = ConnectDouble()
    created = case.originals[2]
    for original in case.originals:
        if original != created:
            note(client, original, tag=TAG, title=record_title(original))
    docker = case.docker
    host = Host()
    host.bridged["Id"] = "c" * 64
    original_mounts = deepcopy(host.bridged["Mounts"])
    original_environment = deepcopy(host.bridged["Config"]["Env"])
    hashes = {
        bridge.PROGRAM: host.bridge_sha256,
        "/opt/lifecycle/scripts/m3_11_unattended/connect_ledger.py": bridge.LEDGER_SHA256,
        "/opt/lifecycle/scripts/m3_11_unattended/connect_auth.py": bridge.INSPECTOR_SHA256,
    }
    monkeypatch.setattr(legacy_diagnostics, "script_digest", lambda _host, _id, path: hashes[path])
    command, owned = docker.command, docker.owned

    def inventory(*args: str) -> bytes:
        if args[0] == "exec" and args[1] == host.bridged["Id"]:
            return host.command(*args)
        output = command(*args)
        return output + host.command(*args) if args[-1] == "{{.ID}} {{.Names}}" else output

    monkeypatch.setattr(docker, "command", inventory)
    monkeypatch.setattr(
        docker,
        "owned",
        lambda selected: (
            host.owned(selected)
            if selected in {host.old["Id"], host.bridged["Id"]}
            else owned(selected)
        ),
    )
    mapping = migration(
        {
            **migration_body(case.collect()),
            "approved_at": stamp(datetime.now(UTC)),
            "approval_reference": "synthetic bridge consent",
        }
    )
    expected = digest(mapping)
    host.bridged["Config"]["Cmd"] = bridge.watchdog_command(client.vault, expected)
    if fault == "removed-after-discovery":
        host.rows.clear()
    request = client.request

    def lose_reader(method: str, path: str, body: Row | None = None) -> Response:
        response = request(method, path, body)
        if method == "POST" and body is not None and body["tags"] == [TAG]:
            if fault == "removed-after-original-publication":
                host.rows.clear()
            elif fault == "stopped":
                host.bridged["State"]["Running"] = False
            elif fault == "restart-disabled":
                host.bridged["HostConfig"]["RestartPolicy"]["Name"] = "no"
            elif fault == "missing-cleanup":
                host.bridged["Mounts"] = [
                    row for row in host.bridged["Mounts"] if row["Destination"] != "/cleanup"
                ]
            elif fault == "missing-socket":
                host.bridged["Mounts"].pop()
            elif fault == "wrong-endpoint":
                host.bridged["Config"]["Env"].append("DOCKER_CONTEXT=other")
            elif fault == "wrong-evidence":
                for row in host.bridged["Mounts"]:
                    if row["Destination"] == "/evidence":
                        row["Name"] += "-other"
        return response

    monkeypatch.setattr(client, "request", lose_reader)
    spool = tmp_path / "pending"
    before = client.posts
    with pytest.raises(
        LifecycleError,
        match=r"compatible host cleanup reader|unbridged legacy reader|container is stopped",
    ):
        publish_import(client, vault=client.vault, approved=mapping, spool=spool, docker=docker)
    assert client.posts == before + 1  # Only the legacy-safe original was submitted.
    assert not (spool / ("import-" + expected + ".json")).exists()
    assert all(item["title"] != "m3-11-import-" + expected for item in client.items.values())
    originals = {path: path.read_bytes() for path in spool.glob("original-*.json")}
    assert len(originals) == 1

    # Recovery only needs the restored bridge; an absent predecessor is not authority.
    host.rows = [host.bridged]
    host.bridged["State"]["Running"] = True
    host.bridged["HostConfig"]["RestartPolicy"]["Name"] = "unless-stopped"
    host.bridged["Mounts"] = original_mounts
    host.bridged["Config"]["Env"] = original_environment
    assert (
        publish_import(client, vault=client.vault, approved=mapping, spool=spool, docker=docker)
        == expected
    )
    assert client.posts == before + 2  # Reconciles the original without replay; imports once.
    assert all(path.read_bytes() == raw for path, raw in originals.items())
