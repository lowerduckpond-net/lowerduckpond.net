"""Explicit replacement of failed genesis before any registry or credential activity."""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended import connect_action as action
from scripts.m3_11_unattended import connect_genesis as genesis
from scripts.m3_11_unattended.connect_activate import (
    INITIALIZING_FORMAT,
    Activation,
    activation_probes,
    retain,
)
from scripts.m3_11_unattended.connect_control import BACKEND, PREFIX, SETTING, GitHub
from scripts.m3_11_unattended.github_checkpoint import MAX_ARTIFACTS, MAX_STATUS_PAGES, PAGE_SIZE
from scripts.m3_11_unattended.journal import event, validate
from scripts.m3_11_unattended.model import LifecycleError, digest, identity, instant, strings
from scripts.m3_11_unattended.state import private_directory
from scripts.production_qualification_inputs import revision

FORMAT = "lowerduckpond-m3-11-connect-failed-activation-replacement-v1"


def require_unregistered(github: GitHub, approved: dict[str, object]) -> None:
    """Any registry entry, including a malformed or failed one, forbids replacement."""
    context = "m3-11/connect-checkpoint/" + identity(approved["epoch"])
    source = revision(approved["registry_revision"])
    seen: set[int] = set()
    for page in range(1, MAX_STATUS_PAGES + 1):
        rows = github.api(f"{PREFIX}/commits/{source}/statuses?per_page={PAGE_SIZE}&page={page}")
        if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
            raise LifecycleError("previous activation registry is unavailable")
        for row in rows:
            if (
                not isinstance(row, dict)
                or type(row.get("id")) is not int
                or row["id"] < 1
                or row["id"] in seen
                or not isinstance(row.get("context"), str)
            ):
                raise LifecycleError("previous activation registry is incomplete or ambiguous")
            seen.add(row["id"])
            if row["context"].lower() == context:
                raise LifecycleError("registered genesis cannot be replaced")
        if len(rows) < PAGE_SIZE:
            return
    raise LifecycleError("previous activation registry exceeds its complete scan bound")


def artifacts(github: GitHub, run_id: int) -> list[dict[str, object]]:
    """Retain metadata for all failed-run artifacts; never remove orphan uploads."""
    result: list[dict[str, object]] = []
    total: int | None = None
    for page in range(1, MAX_ARTIFACTS // PAGE_SIZE + 1):
        value = github.api(f"{PREFIX}/actions/runs/{run_id}/artifacts?per_page=100&page={page}")
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("artifacts"), list)
            or type(value.get("total_count")) is not int
            or not 0 <= value["total_count"] <= MAX_ARTIFACTS
            or (total is not None and value["total_count"] != total)
        ):
            raise LifecycleError("failed activation artifact inventory is incomplete")
        total = value["total_count"]
        rows = value["artifacts"]
        if len(rows) > PAGE_SIZE or (not rows and len(result) != total):
            raise LifecycleError("failed activation artifact inventory is incomplete")
        for row in rows:
            if (
                not isinstance(row, dict)
                or type(row.get("id")) is not int
                or row["id"] < 1
                or not isinstance(row.get("name"), str)
                or not isinstance(row.get("digest"), str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", row["digest"]) is None
                or not isinstance(row.get("workflow_run"), dict)
                or row["workflow_run"].get("id") != run_id
            ):
                raise LifecycleError("failed activation artifact metadata is invalid")
            result.append({key: row[key] for key in ("id", "name", "digest")})
        if len(result) >= total:
            if len(result) != total or len({row["id"] for row in result}) != total:
                raise LifecycleError("failed activation artifact inventory is ambiguous")
            return sorted(result, key=lambda row: cast(int, row["id"]))
    raise LifecycleError("failed activation artifact inventory exceeds its bound")


def failed_execution(github: GitHub, dispatch: dict[str, object]) -> dict[str, object]:
    selected = github.find_run(dispatch)
    if selected is None:
        raise LifecycleError("previous activation has no unambiguous execution")
    run = github.run(selected)
    attempt = run.get("run_attempt")
    if (
        run.get("status") != "completed"
        or run.get("conclusion") not in {"failure", "cancelled", "timed_out"}
        or type(attempt) is not int
        or attempt < 1
    ):
        raise LifecycleError("only a completed failed activation can be replaced")
    revision(run.get("head_sha"))
    instant(run.get("updated_at"))
    return {
        key: run[key]
        for key in ("id", "run_attempt", "head_sha", "status", "conclusion", "updated_at")
    }


def initializing(successor: Activation, approved: dict[str, object]) -> dict[str, object]:
    return {
        "format": INITIALIZING_FORMAT,
        "stage": "initializing",
        "active_helper": successor.helper,
        "request": {
            key: approved[key]
            for key in ("vaults", "anchor", "anchor_sha256", "targets_sha256", "shared_server")
        },
        "receipt": None,
    }


def replace_failed(  # noqa: PLR0912, PLR0915 - each retained transition boundary is checked before mutation
    successor: Activation, previous_directory: Path
) -> None:
    """Fence and retire only an unregistered activation, preserving all evidence."""
    private_directory(previous_directory)
    if (
        previous_directory == successor.directory
        or previous_directory.parent != successor.directory.parent
    ):
        raise LifecycleError("replacement activation requires a private sibling directory")
    path = successor.directory / "failed-activation-replacement.json"
    saved = read_private(path) if path.exists() else None
    variables = successor.github.variables()
    current = json.loads(variables.get(SETTING, "null"))
    old = saved["previous_selection"] if saved else current
    if not isinstance(old, dict):
        raise LifecycleError("failed activation has no retained protected selection")
    old_helper = revision(old.get("active_helper"))
    old = action.selection(old, helper=old_helper)
    if old["stage"] != "genesis" or old_helper == successor.helper:
        raise LifecycleError("replacement requires failed genesis at a previous helper")
    successor.bind(old)
    successor.github.merged(old_helper)
    old_inputs = read_private(previous_directory / "inputs.json")
    if old_inputs != read_private(successor.directory / "inputs.json"):
        raise LifecycleError("replacement activation changed its bootstrap inputs")
    approved = cast(dict[str, object], old["request"])
    discovery = genesis.discovery_request(
        read_private(previous_directory / "discovery-request.json")
    )
    probes = activation_probes(read_private(previous_directory / "probes.json"))
    shared = cast(dict[str, object], probes["shared"])
    if read_private(previous_directory / "journal" / (str(shared["event_id"]) + ".json")) != shared:
        raise LifecycleError("previous activation lost its shared probe creation intent")
    if (
        any(discovery[role + "_probe"] != probes[role] for role in probes)
        or any(
            discovery[key] != approved[key] for key in discovery if key not in {"format", "initial"}
        )
        or not strings(discovery["initial"]).items() <= strings(approved["initial"]).items()
    ):
        raise LifecycleError("previous activation request or probes changed")
    for stage in ("discovery", "genesis"):
        selected = old if stage == "genesis" else {**old, "stage": stage, "request": discovery}
        dispatch = read_private(previous_directory / stage / "dispatch.json")
        if (
            dispatch.get("operation") != stage
            or dispatch.get("selection_sha256") != digest(selected)
            or dispatch.get("run_sha256") != ""
            or read_private(previous_directory / stage / "submitted.json")
            != {"dispatch_sha256": digest(dispatch)}
        ):
            raise LifecycleError("previous activation dispatch or submission changed")
    if read_private(previous_directory / "shared-forgery.json") != approved["shared_forgery_probe"]:
        raise LifecycleError("previous activation forgery probe changed")
    execution = failed_execution(successor.github, dispatch)
    inventory = artifacts(successor.github, cast(int, execution["id"]))
    files = {
        str(entry.relative_to(previous_directory)): digest(read_private(entry))
        for entry in previous_directory.rglob("*.json")
    }
    records = successor.ledger.records()
    observed = {str(row["event_id"]): digest(row) for row in records}
    minimum = {
        **strings(approved["initial"]),
        **{str(validate(probe)["event_id"]): digest(probe) for probe in probes.values()},
    }
    if (
        genesis.credential_history(records, strings(approved["initial"]))
        or not minimum.items() <= observed.items()
    ):
        raise LifecycleError("failed activation replacement cannot discard credential history")
    require_unregistered(successor.github, approved)
    binding = {
        "format": FORMAT,
        "previous_directory": str(previous_directory),
        "previous_selection": old,
        "previous_files": files,
        "failed_execution": execution,
        "failed_artifacts": inventory,
        "helper_revision": successor.helper,
        "inputs_sha256": digest(old_inputs),
    }
    if saved:
        fields(saved, {*binding, "initial", "probes", "transition"})
        if any(saved.get(key) != value for key, value in binding.items()):
            raise LifecycleError("retained failed activation replacement evidence changed")
        new_probes = activation_probes(saved["probes"])
        transition = validate(saved["transition"])
        if not strings(saved["initial"]).items() <= observed.items():
            raise LifecycleError("failed activation replacement lost earlier journal history")
    else:
        if variables.get(BACKEND) != "connect-initializing" or current != old:
            raise LifecycleError("active or changed cleanup cannot be replaced")
        if any(
            entry.name not in {"inputs.json", "cleanup.lock", "journal"}
            for entry in successor.directory.iterdir()
        ) or any((successor.directory / "journal").iterdir()):
            raise LifecycleError("replacement directory already contains another activation")
        epoch = str(uuid.uuid7())
        new_probes = {
            role: event(
                "run", epoch, {"format": genesis.PROBE_FORMAT, "epoch": epoch, "actor": role}
            )
            for role in ("shared", "independent")
        }
        transition = event(
            "run",
            epoch,
            {
                "format": FORMAT,
                "previous_epoch": approved["epoch"],
                "previous_selection_sha256": digest(old),
                "replacement_binding_sha256": digest(binding),
                "helper_revision": successor.helper,
            },
        )
        saved = retain(
            path, {**binding, "initial": observed, "probes": new_probes, "transition": transition}
        )
    epoch = identity(validate(new_probes["shared"])["run_id"])
    if (
        epoch == approved["epoch"]
        or transition["kind"] != "run"
        or transition["run_id"] != epoch
        or transition["payload"]
        != {
            "format": FORMAT,
            "previous_epoch": approved["epoch"],
            "previous_selection_sha256": digest(old),
            "replacement_binding_sha256": digest(binding),
            "helper_revision": successor.helper,
        }
    ):
        raise LifecycleError("retained activation transition differs from its original binding")
    marker = {
        "format": FORMAT,
        "stage": "transition",
        "active_helper": successor.helper,
        "replacement_sha256": digest(saved),
    }
    if successor.github.variables() != variables:
        raise LifecycleError("protected activation changed before replacement fencing")
    if variables.get(BACKEND) != "connect-initializing" and not (
        saved
        and isinstance(current, dict)
        and current.get("stage") == "active"
        and variables.get(BACKEND) == "connect"
    ):
        raise LifecycleError("failed activation replacement changed cleanup backend")
    expected_variables = dict(variables)
    if current == old:
        expected_variables[SETTING] = canonical_bytes(marker).decode()
        successor.github.set_variable(SETTING, expected_variables[SETTING])
    elif current != marker and current != initializing(successor, approved):
        selected = action.selection(current, helper=successor.helper)
        request = cast(dict[str, object], selected["request"])
        if request.get("epoch") != epoch:
            raise LifecycleError("protected replacement activation changed")
        successor.bind(selected)
    successor.github.drain()
    require_unregistered(successor.github, approved)
    if failed_execution(successor.github, dispatch) != execution:
        raise LifecycleError("previous activation executed again during replacement")
    records = successor.ledger.records()
    if (
        genesis.credential_history(records, strings(approved["initial"]))
        or not strings(saved["initial"]).items()
        <= {str(row["event_id"]): digest(row) for row in records}.items()
    ):
        raise LifecycleError("failed activation history changed during replacement")
    successor.ledger.stage(transition)
    retain(successor.directory / "probes.json", new_probes)
    # Freeze discovery against the original revoke allowlist before publishing
    # initialization. Later arrivals cannot become newly approved initial history.
    successor.discovery(initial=strings(approved["initial"]))
    latest_variables = successor.github.variables()
    if latest_variables != expected_variables:
        raise LifecycleError("protected replacement changed while draining workers")
    require_unregistered(successor.github, approved)
    latest = json.loads(latest_variables.get(SETTING, "null"))
    if latest == marker:
        successor.github.set_variable(
            SETTING, canonical_bytes(initializing(successor, approved)).decode()
        )
