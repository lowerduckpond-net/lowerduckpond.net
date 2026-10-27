"""Allow the first runtime use of the same native lease after proven retirement.

This is not a synthetic qualification consumer/release. It only removes the
prior-consumer prerequisite for a completed, externally excluded custody
retirement. The existing full storage, seven-role, approval and reservation
checks still run and make the real first consumer claim.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scripts.m3_11_custody_domain import admission_domain
from scripts.m3_11_custody_plan import FORMAT, authorization, local_root, plan, require
from scripts.m3_11_custody_registry import Registry
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import digest, directory
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.docker import Docker
from scripts.m3_11_unattended.model import identity
from scripts.m3_11_unattended.state import LeaseState


def require_completed(
    config: LeaseConfiguration, lease: LeaseState, *, evidence_root: Path, docker: Docker
) -> None:
    index = fields(
        read_private(lease.directory / "custody-retirement.json"),
        {"fixture_id", "retirement_sha256"},
    )
    root = local_root(evidence_root, {"fixture_id": identity(index["fixture_id"])})
    directory(root.parent)
    directory(root)
    approved = plan(read_private(root / "plan.json"))
    admission_domain(docker, approved["runtime"], evidence_root=evidence_root)
    auth = authorization(read_private(root / "authorization.json"), approved, now=datetime.now(UTC))
    result, absence = read_private(root / "retired.json"), read_private(root / "absence.json")
    manifest = lease.manifest()
    require(
        approved["current_lease_id"] == manifest.lease_id
        and approved["current_manifest_sha256"] == manifest.sha256
        and approved["implementation_revision"] == config.helper_revision
        and result["format"] == FORMAT
        and result["outcome"] == "exact-version-retired-custody-retained"
        and result["plan_sha256"] == absence["plan_sha256"] == digest(approved)
        and result["authorization_sha256"] == absence["authorization_sha256"] == digest(auth)
        and result["absence_sha256"] == digest(absence)
        and result["fixture_id"] == index["fixture_id"]
        and result["versions_retired"] == 1
        and result["fixture_execution"] == "permanently-excluded"
        and result["historical_lease_closed"] is True
        and result["current_lease_cleanup_complete"] is False
        and absence["whole_bucket_empty"] is True
        and digest(result) == index["retirement_sha256"],
        "unused native lease lacks its exact completed custody retirement",
    )
    roles = config.generations[config.active_generation]
    records = [
        Registry(roles[role].reader(), config.journal_vault).selected(str(index["fixture_id"]))
        for role in ("provision", "cleanup")
    ]
    require(
        records[0] is not None
        and records[0] == records[1]
        and records[0]["plan"] == approved
        and records[0]["authorization"] == auth
        and digest(records[0]) == absence["exclusion_sha256"]
        and read_private(root / "delete-submitted.json") == records[0],
        "unused native lease retirement exclusion is not currently visible",
    )
