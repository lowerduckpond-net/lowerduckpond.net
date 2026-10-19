"""Offline consumption of an independently selected, fully bound terminal capture."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import uuid
from pathlib import Path
from typing import cast

from lowerduckpond_static_host_agent.durable import _rename_noreplace

from scripts import m3_11_frozen_github as github
from scripts.m3_11_frozen_terminal import consistent
from scripts.m3_11_frozen_transport import require_operation
from scripts.m3_11_private_inputs import read_private, read_private_bytes
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import (
    CHUNK,
    RetirementError,
    digest,
    directory,
    fingerprint,
    preserve,
    sync,
)
from scripts.m3_11_unattended.state import LeaseState

FILES = (
    {
        "invocation.json",
        "native-calls.json",
        "program.txt",
        "bundle.txt",
        "before.json",
        "after.json",
        "github/run.json",
        "github/attempt.json",
        "github/jobs.json",
        "github/artifacts.json",
        "github/cleanup.zip",
        "github/authentication.zip",
        "github/verified.json",
    }
    | {f"response-{index}.bin" for index in range(8)}
    | {f"call-{index}.json" for index in range(8)}
)


def verify(selection: object, lease: LeaseState) -> dict[str, object]:
    value = fields(selection, {"directory", "files", "github_contract", "collector_sha256"})
    root = Path(str(value["directory"]))
    directory(root)
    directory(root / "github")
    files = value["files"]
    if not isinstance(files, dict) or set(files) != FILES:
        raise RetirementError("terminal proof lacks all original native capture files")
    for name, expected in files.items():
        if fingerprint(root / name, github.MAX_ZIP) != expected:
            raise RetirementError("terminal proof capture file binding differs")
    invocation = read_private(root / "invocation.json")
    if digest(invocation) != value["collector_sha256"]:
        raise RetirementError("terminal collector invocation binding differs")
    plan = cast(dict[str, object], invocation["plan"])
    program = read_private_bytes(root / "program.txt", maximum=github.MAX_BODY).decode()
    bundle = read_private_bytes(root / "bundle.txt", maximum=github.MAX_BODY).decode()
    require_operation(program, bundle, operation="terminal-snapshot", plan_sha256=digest(plan))
    if (
        invocation.get("format") != "lowerduckpond-m3-11-terminal-native-invocation-v1"
        or invocation.get("operation") != "GET-only-terminal-capture"
        or invocation.get("program_sha256") != hashlib.sha256(program.encode()).hexdigest()
        or invocation.get("bundle_sha256") != hashlib.sha256(bundle.encode()).hexdigest()
        or plan.get("lease_id") != lease.manifest().lease_id
        or plan.get("manifest_sha256") != lease.manifest().sha256
        or cast(dict[str, object], plan.get("controller_identity", {})).get("id")
        != invocation.get("controller")
    ):
        raise RetirementError("terminal collector source or original lease differs")
    before, after = (
        read_private(root / name, maximum=github.MAX_BODY) for name in ("before.json", "after.json")
    )
    facts = consistent(before, after, lease)
    native = github.verify(root / "github", value["github_contract"], lease.manifest())
    calls = read_private(root / "native-calls.json").get("calls")
    if (
        not isinstance(calls, list)
        or len(calls) != 8  # noqa: PLR2004 - two native snapshots and six GETs
        or calls[0].get("operation") != "terminal-snapshot"
        or calls[-1].get("operation") != "terminal-snapshot"
        or any(row.get("operation") != "github-get" for row in calls[1:-1])
    ):
        raise RetirementError("terminal collector native invocation inventory differs")
    verify_calls(root, calls, invocation, native)
    if read_private(root / "github/verified.json") != native:
        raise RetirementError("terminal independent selection differs from full verification")
    return {
        "format": "lowerduckpond-m3-11-terminal-proof-selection-v1",
        "selection_sha256": digest(value),
        "native": native,
        "facts_sha256": digest(facts),
        "manifest_sha256": lease.manifest().sha256,
        "credential_cleanup": "verified-seven-exact-denials",
    }


def verify_calls(
    root: Path,
    calls: list[dict[str, object]],
    invocation: dict[str, object],
    native: dict[str, object],
) -> None:
    artifacts = cast(dict[str, dict[str, object]], native["artifacts"])
    run = native["run_id"]
    endpoints = [
        None,
        f"runs/{run}",
        f"runs/{run}/attempts/1",
        f"runs/{run}/attempts/1/jobs?per_page=100",
        f"runs/{run}/artifacts?per_page=100",
        f"artifacts/{artifacts['cleanup']['artifact_id']}/zip",
        f"artifacts/{artifacts['authentication']['artifact_id']}/zip",
        None,
    ]
    members = [
        "before.json",
        "github/run.json",
        "github/attempt.json",
        "github/jobs.json",
        "github/artifacts.json",
        "github/cleanup.zip",
        "github/authentication.zip",
        "after.json",
    ]
    for index, (endpoint, member) in enumerate(zip(endpoints, members, strict=True)):
        row = fields(
            calls[index],
            {"operation", "response_sha256", "response_file", "elapsed_seconds", "attempt_count"}
            | ({"endpoint"} if endpoint else set()),
        )
        if read_private(root / f"call-{index}.json") != row:
            raise RetirementError("terminal original per-call receipt differs")
        raw = read_private_bytes(root / f"response-{index}.bin", maximum=github.MAX_ZIP)
        if (
            type(row["attempt_count"]) is not int
            or row["attempt_count"] != 1
            or type(row["elapsed_seconds"]) not in {float, int}
            or not 0 <= cast(float, row["elapsed_seconds"]) <= (3900 if endpoint is None else 900)
            or not math.isfinite(cast(float, row["elapsed_seconds"]))
        ):
            raise RetirementError("terminal native elapsed/attempt evidence differs")
        if (
            row["response_file"] != f"response-{index}.bin"
            or row["response_sha256"] != hashlib.sha256(raw).hexdigest()
        ):
            raise RetirementError("terminal original native response binding differs")
        if endpoint:
            if (
                row["operation"] != "github-get"
                or row["endpoint"]
                != "repos/lowerduckpond-net/lowerduckpond.net/actions/" + endpoint
            ):
                raise RetirementError("terminal original native GET endpoint differs")
            if member.endswith(".zip"):
                matches = raw == read_private_bytes(root / member, maximum=github.MAX_ZIP)
            else:
                matches = json.loads(raw) == read_private(root / member, maximum=github.MAX_BODY)
        else:
            value = fields(
                json.loads(raw),
                {"status", "snapshot", "plan_sha256", "bundle_sha256", "provenance"},
            )
            plan = cast(dict[str, object], invocation["plan"])
            matches = (
                value["status"] == "observed-terminal-facts"
                and value["plan_sha256"] == digest(invocation["plan"])
                and value["bundle_sha256"] == invocation["bundle_sha256"]
                and value["snapshot"] == read_private(root / member, maximum=github.MAX_BODY)
                and value["provenance"]
                == {
                    key: plan[key]
                    for key in ("controller_identity", "request_sha256", "consumer_binding")
                }
            )
        if not matches:
            raise RetirementError(
                "terminal native response differs from retained full verification input"
            )


def pack(selection: object) -> dict[str, str]:
    """Read fixed original capture members for the separately sealed local plan."""
    value = cast(dict[str, object], selection)
    root = Path(str(value["directory"]))
    return {
        name: base64.b85encode(read_private_bytes(root / name, maximum=github.MAX_ZIP)).decode()
        for name in FILES
    }


def install(selection: object, encoded: object, *, registry: Path) -> None:
    """Publish only exact approved proof bytes outside all fixture deletion scopes."""
    chosen = cast(dict[str, object], selection)
    output = Path(str(chosen["directory"]))
    if (
        output.parent != registry
        or not output.name.startswith("terminal-")
        or not isinstance(encoded, dict)
        or set(encoded) != FILES
    ):
        raise RetirementError("terminal capture materialization escaped its fixed scope")
    files = cast(dict[str, dict[str, object]], chosen["files"])
    decoded = {}
    for name, data in encoded.items():
        if not isinstance(data, str) or len(data) > 2 * github.MAX_ZIP:
            raise RetirementError("terminal capture encoded member exceeds bound")
        raw = base64.b85decode(data)
        if files.get(name) != {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}:
            raise RetirementError("terminal capture transfer bytes differ")
        decoded[name] = raw
    if output.exists() or output.is_symlink():
        for name in FILES:
            if fingerprint(output / name, github.MAX_ZIP) != files[name]:
                raise RetirementError("terminal capture existing publication differs")
        return
    directory(registry)
    temporary = registry / (output.name + ".unpublished-" + uuid.uuid7().hex)
    temporary.mkdir(mode=0o700)
    (temporary / "github").mkdir(mode=0o700)
    sync(registry)
    for name, raw in decoded.items():
        preserve(
            temporary / name,
            (raw[i : i + CHUNK] for i in range(0, len(raw), CHUNK)),
            len(raw),
            str(files[name]["sha256"]),
        )
    for name in FILES:
        if fingerprint(temporary / name, github.MAX_ZIP) != files[name]:
            raise RetirementError("terminal capture publication reread differs")
    sync(temporary / "github")
    sync(temporary)
    parent = os.open(registry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _rename_noreplace(parent, temporary.name, output.name)
        os.fsync(parent)
    finally:
        os.close(parent)
