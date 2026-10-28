"""Scheduled custody selection over complete authenticated native bytes.

This verifier fetches nothing and mutates only a new private scratch directory.
The sealed collector establishes Docker/GitHub origin before selection. Every
nonce reply revalidates captured bytes, host domain and native provider/legacy
outcomes; preservation and original proof clocks are never replaced by labels.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

from scripts import m3_11_custody_github as github
from scripts import m3_11_custody_host as host
from scripts import m3_11_frozen_github as native
from scripts.m3_11_custody_plan import require
from scripts.m3_11_frozen_local import bound_file
from scripts.m3_11_private_inputs import read_private_bytes
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import CHUNK, digest, directory, preserve
from scripts.m3_11_unattended.docker import EVIDENCE_VOLUME
from scripts.m3_11_unattended.model import LeaseManifest, fingerprint, instant

MANUAL_PROPOSAL_FORMAT = "lowerduckpond-m3-11-custody-cleanup-contract-v1"
FORMAT = "lowerduckpond-m3-11-custody-scheduled-cleanup-contract-v1"
SCHEDULED_FORMAT = FORMAT
SELECTION = "lowerduckpond-m3-11-custody-scheduled-cleanup-selection-v1"
SCHEDULED_SELECTION = SELECTION
FILES = {
    "run.json",
    "attempt.json",
    "jobs.json",
    "artifacts.json",
    "cleanup.zip",
    "authentication.zip",
}


def contract(raw: object) -> tuple[dict[str, object], LeaseManifest]:
    value = fields(
        raw,
        {
            "format",
            "current_manifest",
            "active_lease",
            "host_id",
            "host_started_at",
            "host_helper",
            "independent_helper",
            "native_workflow",
            "collector_sha256",
            "cleanup_configuration_sha256",
            "runtime",
            "daemon_socket",
            "github",
        },
    )
    require(
        value["format"] == FORMAT,
        "unknown custody cleanup protocol",
    )
    manifest = LeaseManifest.parse(value["current_manifest"])
    for key in ("host_id", "collector_sha256", "cleanup_configuration_sha256"):
        fingerprint(value[key])
    runtime = fields(
        value["runtime"], {"workspace_id", "daemon_id", "evidence_volume_created_at", "image"}
    )
    require(
        isinstance(value["daemon_socket"], str) and value["daemon_socket"].startswith("/"),
        "custody cleanup socket is not absolute",
    )
    require(
        value["host_helper"]
        == value["independent_helper"]
        == value["native_workflow"]
        == manifest.helper_revision
        == manifest.source_revision
        and isinstance(runtime["image"], str)
        and runtime["image"].startswith("sha256:"),
        "custody cleanup helper or image differs",
    )
    github.active(value["active_lease"], manifest)
    base = cast(dict[str, object], value["github"])
    require(
        base.get("native_workflow_revision") == value["native_workflow"]
        and base.get("installed_helper_revision") == value["independent_helper"],
        "custody independent verifier binding differs",
    )
    return value, manifest


def _host(
    raw: object, selected: dict[str, object], manifest: LeaseManifest, *, now: datetime
) -> datetime:
    value = fields(
        raw,
        {
            "format",
            "before",
            "after",
            "configuration",
            "daemon",
            "volume",
            "receipt",
            "receipt_emitted_at",
            "captured_at",
            "provider_calls",
            "new_dispatches",
            "live_mutations",
        },
    )
    require(
        value["format"] == host.FORMAT
        and all(
            type(value[k]) is int and value[k] == 0
            for k in ("provider_calls", "new_dispatches", "live_mutations")
        ),
        "custody host collection is not read-only",
    )
    before = host.projection(value["before"], selected)
    require(
        before == value["before"] == value["after"] == host.projection(value["after"], selected),
        "custody host native snapshots differ",
    )
    runtime = cast(dict[str, object], selected["runtime"])
    require(
        value["daemon"]
        == {"ID": runtime["daemon_id"], "endpoint": "unix://" + str(selected["daemon_socket"])},
        "custody host daemon binding differs",
    )
    volume = fields(value["volume"], {"Name", "CreatedAt", "Mountpoint"})
    mount = next(
        row
        for row in cast(list[dict[str, object]], before["Mounts"])
        if row["Destination"] == "/evidence"
    )
    require(
        volume["Name"] == EVIDENCE_VOLUME
        and volume["CreatedAt"] == runtime["evidence_volume_created_at"]
        and mount["Source"] == volume["Mountpoint"],
        "custody host evidence domain differs",
    )
    require(
        value["configuration"]
        == {
            "mode": "cleanup-only",
            "helper_revision": selected["host_helper"],
            "configuration_sha256": selected["cleanup_configuration_sha256"],
        },
        "custody host private configuration readback differs",
    )
    receipt = fields(
        value["receipt"],
        {"format", "helper_revision", "actor", "observed_at", "leases", "legacy", "status"},
    )
    require(
        receipt["format"] == "lowerduckpond-m3-11-lease-cleanup-v1"
        and receipt["actor"] == "watchdog"
        and receipt["status"] == "ready"
        and receipt["helper_revision"] == selected["host_helper"],
        "custody host native receipt differs",
    )
    base = cast(dict[str, object], selected["github"])
    native.legacy_baseline(receipt["legacy"], base["legacy"])
    require(
        github._leases(receipt["leases"], base, manifest) == selected["active_lease"],
        "custody host active results differ",
    )
    observed = instant(receipt["observed_at"])
    require(
        instant(selected["host_started_at"])
        <= observed
        <= instant(value["receipt_emitted_at"])
        <= instant(value["captured_at"])
        <= now,
        "custody host native chronology differs",
    )
    valid_until = observed + timedelta(seconds=github.PROOF_SECONDS)
    require(now < valid_until, "custody host native proof is stale")
    return valid_until


def _github(selection: object, *, scratch: Path) -> Path:
    chosen = fields(selection, {"directory", "files"})
    root = Path(str(chosen["directory"]))
    directory(root)
    files = chosen["files"]
    require(
        isinstance(files, dict) and set(files) == FILES, "custody native capture file set differs"
    )
    directory(scratch.parent)
    scratch.mkdir(mode=0o700)
    for name, binding in cast(dict[str, object], files).items():
        descriptor = fields(binding, {"size", "sha256"})
        limit = native.MAX_ZIP if name.endswith(".zip") else native.MAX_BODY
        raw = read_private_bytes(root / name, maximum=limit)
        require(
            type(descriptor["size"]) is int
            and len(raw) == descriptor["size"]
            and hashlib.sha256(raw).hexdigest() == fingerprint(descriptor["sha256"]),
            "custody native capture bytes changed",
        )
        preserve(
            scratch / name,
            (raw[i : i + CHUNK] for i in range(0, len(raw), CHUNK)),
            len(raw),
            str(descriptor["sha256"]),
        )
    return scratch


def verify_scheduled(
    selection: object, raw_contract: object, *, now: datetime, scratch: Path
) -> datetime:
    selected, manifest = contract(raw_contract)
    chosen = fields(selection, {"format", "host", "github", "collection"})
    require(
        chosen["format"] == SELECTION,
        "custody cleanup selection protocol differs",
    )
    collected = bound_file(chosen["collection"])
    github_selection = fields(chosen["github"], {"directory", "files"})
    require(
        all(
            type(collected.get(k)) is int
            for k in ("provider_calls", "new_dispatches", "live_mutations")
        ),
        "custody collection counters must be native integers",
    )
    require(
        collected
        == {
            "format": "lowerduckpond-m3-11-custody-read-collection-v1",
            "status": "passed",
            "collector_sha256": selected["collector_sha256"],
            "host_sha256": cast(dict[str, object], chosen["host"])["sha256"],
            "github_files_sha256": digest(github_selection["files"]),
            "provider_calls": 0,
            "new_dispatches": 0,
            "live_mutations": 0,
        },
        "custody collector invocation or read-only result differs",
    )
    directory(scratch.parent)
    scratch.mkdir(mode=0o700)
    valid_host = _host(bound_file(chosen["host"]), selected, manifest, now=now)
    directory_copy = _github(chosen["github"], scratch=scratch / "github")
    independent = github.verify_scheduled(directory_copy, selected["github"], manifest, now=now)
    require(
        independent["active_lease"] == selected["active_lease"],
        "custody independent active results differ",
    )
    return min(
        valid_host,
        instant(independent["native_created_at"]) + timedelta(seconds=github.PROOF_SECONDS),
    )
