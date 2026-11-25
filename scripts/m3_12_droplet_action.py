"""One live, fixed-unit lease for a fenced disposable source converge."""

from __future__ import annotations

import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

from lowerduckpond_static_contracts import decode_json_object
from lowerduckpond_static_host_agent import source_bootstrap
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_paths import private_directory
from lowerduckpond_static_host_agent.installed_routing import SOURCE_BOOTSTRAP

from scripts import m3_11_production_lease as lease
from scripts.m3_12_contracts import MAX_RECORD_BYTES, encode, require
from scripts.m3_12_droplet import LEASE
from scripts.m3_12_native import drain_unit
from scripts.m3_12_successor import stage_configuration

UNIT = "lowerduckpond-m3-12-droplet-action.service"
CGROUP = Path("/proc/self/cgroup")
ACTION_ARGUMENTS = 2
CGROUP_EVENTS = Path("/sys/fs/cgroup/system.slice") / UNIT / "cgroup.events"


def _lease_record(token: str) -> tuple[str]:
    return (f"source-action-{sha256(token.encode()).hexdigest()}.json",)


def _owner(artifact: str, raw: bytes, *, owner: int = 0) -> None:
    document, routing = source_bootstrap._document(raw)
    require(document["artifactSha256"] == artifact, "droplet-source-lease-artifact-changed")
    # Refuse before writing any action authority if host/boot/fence are wrong.
    source_bootstrap.require_delivery(document, routing, artifact, owner=owner)
    private_directory(LEASE.parent, owner=owner)
    private_directory(LEASE, owner=owner)
    with lease.controller(
        LEASE, owner=owner, drain=lambda: drain_unit(UNIT, CGROUP_EVENTS)
    ) as token:
        received = source_bootstrap.receive(raw, artifact, owner=owner)
        with DurableDirectory.open(
            LEASE.parent, expected_owner=owner, expected_directory_mode=0o700
        ) as runtime:
            runtime.create_immutable(_lease_record(token), encode({"handoffSha256": received}))
        print(token, flush=True)
        require(
            sys.stdin.buffer.read(8) in {b"", b"release\n"},
            "droplet-source-owner-control-invalid",
        )


def require_current(artifact: str, token: str, *, owner: int = 0) -> None:
    lease.require_action(LEASE, owner=owner, token=token)
    with (
        DurableDirectory.open(
            LEASE.parent, expected_owner=owner, expected_directory_mode=0o700
        ) as runtime,
        DurableDirectory.open(
            source_bootstrap.AUTHORITY, expected_owner=owner, expected_directory_mode=0o700
        ) as protected,
    ):
        raw = protected.read_regular(
            (SOURCE_BOOTSTRAP,),
            expected_owner=owner,
            expected_mode=0o600,
            maximum_bytes=MAX_RECORD_BYTES,
        )
        expected = encode({"handoffSha256": sha256(raw).hexdigest()})
        require(
            runtime.read_regular(
                _lease_record(token),
                expected_owner=owner,
                expected_mode=0o600,
                maximum_bytes=len(expected),
            )
            == expected,
            "droplet-source-lease-handoff-changed",
        )
        document = decode_json_object(raw)
        source_bootstrap.verify(
            {key: document[key] for key in source_bootstrap.INPUTS}, artifact, owner=owner
        )


def dispatch(artifact: str, operation: str, arguments: list[str], *, owner: int = 0) -> int:
    require(os.geteuid() == owner, "droplet-source-root-required")
    if operation == "owner" and not arguments:
        raw = sys.stdin.buffer.readline(MAX_RECORD_BYTES + 1)
        require(len(raw) <= MAX_RECORD_BYTES, "droplet-source-handoff-too-large")
        _owner(artifact, raw, owner=owner)
        return 0
    require(
        CGROUP.read_text(encoding="ascii") == f"0::/system.slice/{UNIT}\n",
        "droplet-source-outside-action",
    )
    if operation == "gate" and len(arguments) == 1:
        require_current(artifact, arguments[0], owner=owner)
        request = decode_json_object(sys.stdin.buffer.read(MAX_RECORD_BYTES + 1))
        require(
            encode(request) == encode(stage_configuration("dark-staging", artifact)),
            "droplet-source-stage-inputs-changed",
        )
        print("dark-staging")
        return 0
    require(
        operation == "action" and len(arguments) == ACTION_ARGUMENTS,
        "droplet-source-action-invalid",
    )
    token, command = arguments
    require(bool(command) and "\0" not in command, "droplet-source-action-invalid")
    with lease.action(LEASE, owner=owner, token=token):
        require_current(artifact, token, owner=owner)
        return subprocess.call(["/bin/sh", "-c", command])  # noqa: S603 - leased Ansible action
