"""Offline local half of the locked retirement proof exchange.

Cleanup selections must be outputs of the separately reviewed complete native
verifiers. Selecting newer outputs does not renew their original native clocks.
This module never fetches, copies, repairs, mounts or modifies retained evidence.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import decode_json_object

from scripts.m3_11_frozen_context import require
from scripts.m3_11_frozen_evidence import verify
from scripts.m3_11_private_inputs import read_private_bytes
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import digest, directory
from scripts.m3_11_unattended.model import instant, stamp

PROOF_AGE_SECONDS = 5400


def bound_file(value: object) -> dict[str, object]:
    binding = fields(value, {"path", "size", "sha256"})
    path = Path(str(binding["path"]))
    directory(path.parent)
    raw = read_private_bytes(path, maximum=2 * 1024 * 1024)
    require(
        path.is_absolute()
        and len(raw) == binding["size"]
        and hashlib.sha256(raw).hexdigest() == binding["sha256"],
        "retirement local receipt bytes differ",
    )
    return decode_json_object(raw, maximum_bytes=2 * 1024 * 1024)


def cleanup(selection: object, contract: dict[str, object], *, now: datetime) -> datetime:
    chosen = fields(selection, {"host", "independent", "collection"})
    # Do not rely on dictionary insertion order supplied by a caller.
    host = bound_file(chosen["host"])
    independent = bound_file(chosen["independent"])
    collection = bound_file(chosen["collection"])
    wanted = contract["active_lease"]
    active = fields(wanted, {"lease_id", "manifest_sha256", "status", "overdue", "results"})
    require(
        active["status"] == "active"
        and active["overdue"] is False
        and isinstance(active["results"], list)
        and len(active["results"]) == 7,  # noqa: PLR2004 - original seven obligations
        "retirement requires its original seven retained obligations",
    )
    receipt = cast(dict[str, object], host.get("receipt"))
    leases = cast(list[dict[str, object]], receipt.get("leases", []))
    require(
        host.get("status") == "verified-new-host-cleanup"
        and host.get("container_id") == contract["host_id"]
        and host.get("started_at") == contract["host_started_at"]
        and host.get("active_obligations") == 7  # noqa: PLR2004
        and host.get("old_cleanup_preserved") is True
        and receipt.get("actor") == "watchdog"
        and receipt.get("status") == "ready"
        and receipt.get("helper_revision") == contract["host_helper"]
        and [row for row in leases if row.get("lease_id") == active["lease_id"]] == [active],
        "retirement host cleanup proof differs",
    )
    require(
        independent.get("status") == "verified-scheduled-cleanup-separate-native-helper-binding"
        and independent.get("event") == "schedule"
        and independent.get("run_attempt") == 1
        and independent.get("managed_run_id") == active["lease_id"]
        and independent.get("manifest_sha256") == active["manifest_sha256"]
        and independent.get("active_lease") == active
        and independent.get("native_workflow_revision") == contract["native_workflow"]
        and independent.get("installed_cleanup_helper_revision") == contract["independent_helper"]
        and independent.get("collector_sha256") == contract["collector_sha256"]
        and collection.get("status") == "passed"
        and collection.get("verified_sha256")
        == cast(dict[str, object], chosen["independent"])["sha256"]
        and all(
            collection.get(key) == 0
            for key in ("provider_calls", "new_dispatches", "live_mutations")
        ),
        "retirement independent cleanup verification differs",
    )
    for proof in (host, independent):
        require(
            proof.get("overdue") == 0
            and proof.get("legacy_verified") == 50  # noqa: PLR2004 - retained baseline
            and proof.get("accepted_uncertainty") == 1
            and proof.get("cleanup_complete") is False
            and proof.get("current_lease_closed") is False,
            "retirement cleanup obligations or historical uncertainty changed",
        )
    stamps = [instant(receipt["observed_at"]), instant(independent["native_created_at"])]
    require(
        all(timedelta() <= now - stamp < timedelta(seconds=PROOF_AGE_SECONDS) for stamp in stamps),
        "retirement cleanup proof is stale or future dated",
    )
    return min(stamps) + timedelta(seconds=PROOF_AGE_SECONDS)


def verify_local(evidence: object, selection: object, *, scratch: Path) -> dict[str, object]:
    value = fields(
        evidence,
        {
            "archive",
            "archive_path",
            "image",
            "image_path",
            "original_result",
            "files",
            "cleanup_contract",
        },
    )
    contract = cast(dict[str, object], value["cleanup_contract"])
    cleanup(selection, contract, now=datetime.now(UTC))
    for item in cast(list[dict[str, object]], value["files"]):
        bound_file(item)
    result = verify(
        cast(dict[str, object], value["archive"]),
        archive=Path(str(value["archive_path"])),
        state_image=Path(str(value["image_path"])),
        image_binding=cast(dict[str, object], value["image"]),
        scratch=scratch,
    )
    require(
        result["result"] == bound_file(value["original_result"]),
        "retirement original result differs from the preserved native state",
    )
    now = datetime.now(UTC)
    valid_until = cleanup(selection, contract, now=now)
    return {
        "evidence_sha256": digest(value),
        "status": "native-files-and-cleanup-verified",
        "proof_valid_until": stamp(valid_until),
        "observed_at": stamp(now),
    }
