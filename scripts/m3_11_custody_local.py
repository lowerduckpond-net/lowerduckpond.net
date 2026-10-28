"""New local custody index over unchanged original files, never secret activation.

The reviewed caller authenticates newly collected native cleanup selections just
as for the existing frozen route. This is their complete offline verifier, not
an authentication shortcut for arbitrary supplied JSON.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts import m3_11_custody_cleanup
from scripts.m3_11_combined_inputs import FORMAT as FIXTURE_FORMAT
from scripts.m3_11_combined_inputs import _environment
from scripts.m3_11_custody_plan import require
from scripts.m3_11_frozen_local import bound_file, cleanup, verify_preserved
from scripts.m3_11_frozen_retirement import plan as historical_plan
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import digest, directory
from scripts.m3_11_unattended.model import LeaseManifest, stamp

FORMAT = "lowerduckpond-m3-11-migrated-custody-index-v1"
MAX_PROVENANCE_FILES = 32


def verify(
    value: object,
    approved: dict[str, object],
    *,
    selection: object,
    cleanup_contract: dict[str, object],
    scratch: Path,
) -> dict[str, object]:
    index = fields(
        value,
        {
            "format",
            "source_workspace_id",
            "fixture_id",
            "historical",
            "original_fixture",
            "original_plan",
            "migration_records",
            "evidence",
        },
    )
    require(
        index["format"] == FORMAT
        and digest(index) == approved["custody_sha256"]
        and index["source_workspace_id"] == approved["source_workspace_id"]
        and index["fixture_id"] == approved["fixture_id"]
        and digest(index["evidence"]) == approved["evidence_sha256"]
        and digest(cleanup_contract) == approved["cleanup_contract_sha256"],
        "migrated custody index or current cleanup binding differs",
    )
    native_fixture = fields(
        bound_file(index["original_fixture"]), {"format", "run_id", "environment"}
    )
    original = historical_plan(bound_file(index["original_plan"]))
    environment = native_fixture["environment"]
    require(
        isinstance(environment, dict) and isinstance(environment.get("DOCKER_HOST"), str),
        "preserved native fixture environment is unavailable",
    )
    endpoint = str(cast(dict[str, object], environment)["DOCKER_HOST"])
    require(
        native_fixture["format"] == FIXTURE_FORMAT
        and environment
        == _environment(
            Path(str(original["original_run"])), str(native_fixture["run_id"]), endpoint
        ),
        "preserved native fixture differs from its original path and immutable identity",
    )
    history = fields(index["historical"], {"manifest", "issuer", "created"})
    manifest = LeaseManifest.parse(history["manifest"])
    evidence = cast(dict[str, object], index["evidence"])
    require(
        native_fixture.get("run_id") == index["fixture_id"]
        and manifest.lease_id == approved["historical_lease_id"] == original["lease_id"]
        and manifest.sha256 == approved["historical_manifest_sha256"] == original["manifest_sha256"]
        and evidence["archive"] == approved["archive"] == original["archive"],
        "preserved original fixture, lease or version identity differs",
    )
    records = index["migration_records"]
    require(
        isinstance(records, list) and 1 <= len(records) <= MAX_PROVENANCE_FILES,
        "migrated custody requires its bounded reviewed provenance files",
    )
    for binding in cast(list[dict[str, object]], records):
        bound_file(binding)
    active = fields(
        cleanup_contract["active_lease"],
        {"lease_id", "manifest_sha256", "status", "overdue", "results"},
    )
    require(
        active["lease_id"] == approved["current_lease_id"]
        and active["manifest_sha256"] == approved["current_manifest_sha256"]
        and cleanup_contract["host_helper"]
        == cleanup_contract["independent_helper"]
        == approved["implementation_revision"],
        "current cleanup proof covers another lease or helper",
    )
    require(
        cleanup_contract.get("format") != m3_11_custody_cleanup.MANUAL_PROPOSAL_FORMAT,
        "manual confirmation is not enabled as custody retirement eligibility",
    )
    if cleanup_contract.get("format") == m3_11_custody_cleanup.SCHEDULED_FORMAT:
        current_contract, current_manifest = m3_11_custody_cleanup.contract(cleanup_contract)
        require(
            current_manifest.lease_id == approved["current_lease_id"]
            and current_manifest.sha256 == approved["current_manifest_sha256"]
            and current_manifest.targets == manifest.targets
            and current_contract["runtime"] == approved["runtime"],
            "scheduled cleanup proof covers another current runtime or manifest",
        )
        directory(scratch.parent)
        scratch.mkdir(mode=0o700)
        m3_11_custody_cleanup.verify_scheduled(
            selection, cleanup_contract, now=datetime.now(UTC), scratch=scratch / "cleanup-before"
        )
        preserved = scratch / "preserved"
        preserved.mkdir(mode=0o700)
        directory(preserved)
        verify_preserved(evidence, scratch=preserved)
        valid_until = m3_11_custody_cleanup.verify_scheduled(
            selection, cleanup_contract, now=datetime.now(UTC), scratch=scratch / "cleanup-after"
        )
    else:
        cleanup(selection, cleanup_contract, now=datetime.now(UTC))
        verify_preserved(evidence, scratch=scratch)
        valid_until = cleanup(selection, cleanup_contract, now=datetime.now(UTC))
    return {
        "status": "native-custody-and-cleanup-verified",
        "custody_sha256": digest(index),
        "evidence_sha256": approved["evidence_sha256"],
        "cleanup_contract_sha256": digest(cleanup_contract),
        "proof_valid_until": stamp(valid_until),
        "observed_at": stamp(datetime.now(UTC)),
    }
