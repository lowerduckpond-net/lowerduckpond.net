"""Original producer facts for one managed attempt's partial fixture graph.

The controller's run lease serializes these writes. A begun allocation is never
retried: a lost command or inspection leaves it unresolved for cleanup.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import fields, uuid7
from scripts.m3_11_unattended.inputs import BINDING, MANAGED_ENV
from scripts.m3_11_unattended.model import LifecycleError, digest, fingerprint
from scripts.m3_11_unattended.state import replace_private
from scripts.qualification_context import RUN_ENV, host_name
from scripts.qualification_probe import bounded_command

FORMAT = "lowerduckpond-m3-11-allocation-v1"
PROOF_FORMAT = "lowerduckpond-m3-11-quiescence-v2"
ROLES = ("host", "archive", "destination", "acme")
IDENTITY = {"id", "name", "image", "owner"}
LABEL = "lowerduckpond.qualification.run"


def parse(value: object) -> dict[str, object]:
    result = fields(
        value,
        {"format", "binding_sha256", "daemon", "endpoint", "fixture_run_id", "owner", "roles"},
    )
    fingerprint(result["binding_sha256"])
    fields(result["daemon"], {"ID", "Name", "DockerRootDir", "ServerVersion"})
    if (
        result["format"] != FORMAT
        or uuid7(result["fixture_run_id"]).hex != result["owner"]
        or not isinstance(result["endpoint"], str)
        or not result["endpoint"].startswith("unix:///")
    ):
        raise LifecycleError("allocation context is invalid")
    roles = fields(result["roles"], set(ROLES))
    ids: set[str] = set()
    for role, raw in roles.items():
        row = fields(raw, {"state", "name", "image_input", "identity", "command_drained"})
        if row["name"] != f"/ldp-m3-{result['owner']}-{role}":
            raise LifecycleError("allocation role belongs to another owner")
        state = row["state"]
        if state not in {"not-attempted", "begun-uncertain", "created", "completed-empty"}:
            raise LifecycleError("allocation state is invalid")
        if type(row["command_drained"]) is not bool:
            raise LifecycleError("allocation command outcome is invalid")
        if state == "not-attempted":
            if row["image_input"] is not None or row["command_drained"] is not False:
                raise LifecycleError("unattempted allocation has contradictory evidence")
        elif not isinstance(row["image_input"], str) or not row["image_input"]:
            raise LifecycleError("allocation lacks original image inputs")
        if state == "created":
            observed = fields(row["identity"], IDENTITY)
            selected = fingerprint(observed["id"])
            if (
                selected in ids
                or observed["owner"] != result["owner"]
                or observed["name"] != row["name"]
                or re.fullmatch(r"sha256:[0-9a-f]{64}", str(observed["image"])) is None
            ):
                raise LifecycleError("allocation identity is invalid")
            ids.add(selected)
        elif row["identity"] is not None:
            raise LifecycleError("allocation has an unexpected resource identity")
        if state in {"created", "completed-empty"} and row["command_drained"] is not True:
            raise LifecycleError("allocation lacks a drained command outcome")
    return result


def initialize(directory: Path, request: dict[str, object], endpoint: str) -> dict[str, object]:
    """Reserve an owner before spawning any journey process."""
    binding = fields(request["binding"], BINDING)
    fixture_id = uuid.uuid7()
    value = parse(
        {
            "format": FORMAT,
            "binding_sha256": digest(binding),
            "daemon": request["daemon"],
            "endpoint": endpoint,
            "fixture_run_id": str(fixture_id),
            "owner": fixture_id.hex,
            "roles": {
                role: {
                    "state": "not-attempted",
                    "name": f"/ldp-m3-{fixture_id.hex}-{role}",
                    "image_input": None,
                    "identity": None,
                    "command_drained": False,
                }
                for role in ROLES
            },
        }
    )
    write_private(directory / "allocation.json", value)
    return value


def managed(environment: Mapping[str, str]) -> tuple[Path, dict[str, object]] | None:
    if MANAGED_ENV not in environment:
        return None
    path = Path(environment[MANAGED_ENV])
    inputs = read_private(path)
    binding = fields(inputs["binding"], BINDING)
    request = read_private(path.parent / "request.json")
    value = parse(read_private(path.parent / "allocation.json"))
    if (
        request["binding"] != binding
        or value["binding_sha256"] != digest(binding)
        or value["daemon"] != request["daemon"]
        or value["endpoint"] != environment.get("DOCKER_HOST")
        or (RUN_ENV in environment and value["owner"] != environment[RUN_ENV])
    ):
        raise LifecycleError("managed allocation belongs to different attempt inputs")
    return path.parent / "allocation.json", value


def begin(environment: Mapping[str, str], images: dict[str, str]) -> None:
    selected = managed(environment)
    if selected is None:
        return
    host_name(environment)
    path, value = selected
    require_daemon(dict(environment), value)
    roles = cast(dict[str, dict[str, object]], value["roles"])
    for role, image in images.items():
        if role not in roles or roles[role]["state"] != "not-attempted":
            raise LifecycleError("allocation cannot be submitted again")
        roles[role].update(state="begun-uncertain", image_input=image)
    replace_private(path, parse(value))


def require_daemon(environment: dict[str, str], value: dict[str, object]) -> None:
    raw = bounded_command(["docker", "info", "--format", "{{json .}}"], environment=environment)
    if raw is None:
        raise LifecycleError("allocation daemon is unavailable")
    observed = json.loads(raw)
    if {
        key: observed.get(key) for key in ("ID", "Name", "DockerRootDir", "ServerVersion")
    } != value["daemon"]:
        raise LifecycleError("allocation daemon differs from the original attempt")


def complete(environment: dict[str, str], selected_roles: tuple[str, ...]) -> None:
    """Called only after the producer command returned and its process tree drained.

    A failed or interrupted inventory leaves every pending role uncertain.
    The complete owner inventory is checked before any outcome is persisted.
    """
    selected = managed(environment)
    if selected is None:
        return
    path, value = selected
    require_daemon(environment, value)
    roles = cast(dict[str, dict[str, object]], value["roles"])
    listed = bounded_command(
        [
            "docker",
            "ps",
            "--all",
            "--filter",
            f"label={LABEL}={value['owner']}",
            "--no-trunc",
            "--format",
            "{{.ID}}",
        ],
        environment=environment,
    )
    if listed is None:
        raise LifecycleError("allocation inventory is unavailable")
    ids = listed.decode().splitlines()
    if len(ids) != len(set(ids)):
        raise LifecycleError("allocation inventory repeats an identity")
    found: dict[str, dict[str, object]] = {}
    for identifier in ids:
        fingerprint(identifier)
        raw = bounded_command(["docker", "inspect", identifier], environment=environment)
        if raw is None:
            raise LifecycleError("allocation inspection is unavailable")
        inspected = json.loads(raw)
        if not isinstance(inspected, list) or len(inspected) != 1:
            raise LifecycleError("allocation inspection is ambiguous")
        current = inspected[0]
        row = {
            "id": current["Id"],
            "name": current["Name"],
            "image": current["Image"],
            "owner": current["Config"]["Labels"].get(LABEL),
        }
        matches = [role for role in ROLES if roles[role]["name"] == row["name"]]
        if len(matches) != 1 or row["id"] != identifier or row["owner"] != value["owner"]:
            raise LifecycleError("allocation contains an unbound resource")
        role = matches[0]
        if role in found or (role not in selected_roles and roles[role]["identity"] != row):
            raise LifecycleError("allocation inventory changed outside the producer")
        found[role] = row
    for role in ROLES:
        if role not in selected_roles and roles[role]["identity"] != found.get(role):
            raise LifecycleError("allocation inventory lost or changed an earlier resource")
    for role in selected_roles:
        if role not in ROLES or roles[role]["state"] != "begun-uncertain":
            raise LifecycleError("allocation outcome lacks its original submission")
        roles[role].update(
            state="created" if role in found else "completed-empty",
            identity=found.get(role),
            command_drained=True,
        )
    replace_private(path, parse(value))


def identities(value: dict[str, object]) -> dict[str, dict[str, object]]:
    parse(value)
    result: dict[str, dict[str, object]] = {}
    for row in cast(dict[str, dict[str, object]], value["roles"]).values():
        if row["state"] == "begun-uncertain":
            raise LifecycleError("allocation outcome remains uncertain")
        if row["state"] == "created":
            observed = fields(row["identity"], IDENTITY)
            result[str(observed["id"])] = observed
    return result
