"""Native, read-only revalidation of a preserved archive and clean state image.

Only the caller's new private scratch directory is written. The archived tenant,
its immutable admission correlation, final job/result and audit remain history;
no tenant deletion intent or replacement archive authority is manufactured.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import manifest_digest, result_digest
from lowerduckpond_static_host_agent.archive_bundle import require_archive_inspection
from lowerduckpond_static_host_agent.audit import inspect_audit_correlation, inspect_audit_readonly
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.execution import (
    _require_same_authority,
    _validate_request_integrity,
    _validate_result_binding,
)
from lowerduckpond_static_host_agent.parser_budget import parser_work_budget
from lowerduckpond_static_host_agent.portable_bundle import inspect_portable_bundle
from lowerduckpond_static_host_agent.repository import StateRecordPath

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_ext4 import Ext4
from scripts.m3_11_retirement_files import RetirementError, directory, fingerprint, preserve
from scripts.m3_11_retirement_state import contract, inventory


def verify(  # noqa: PLR0915 - one unchanged native evidence chain
    selected: dict[str, object],
    *,
    archive: Path,
    state_image: Path,
    image_binding: dict[str, object],
    scratch: Path,
) -> dict[str, object]:
    """Full byte rereads plus native bundle/state/correlation/audit contracts."""
    image = fields(image_binding, {"size", "sha256"})
    if type(image["size"]) is not int or image["size"] != 8 * 1024**3:
        raise RetirementError("frozen retirement requires its exact clean state image")
    if fingerprint(state_image, image["size"]) != image:
        raise RetirementError("frozen state image differs from preserved evidence")
    expected = {key: selected[key] for key in ("size", "sha256")}
    if fingerprint(archive, cast(int, expected["size"])) != expected:
        raise RetirementError("preserved archive bytes differ from exact version")
    reader = Ext4(state_image)
    rows = inventory(reader, "/static")
    if len(rows) != 1:
        raise RetirementError("frozen retirement requires exactly one bound archive")
    row = rows[0]
    record = row["archive"]
    mapped = {
        key: record[field]
        for key, field in {
            "bucket": "bucket",
            "key": "key",
            "version": "versionId",
            "size": "bundleSize",
        }.items()
    }
    mapped["sha256"] = cast(dict[str, object], record["bundleDigest"])["value"]
    if mapped != selected:
        raise RetirementError("state authority differs from exact approved version")
    observed = contract(reader, "/static", StateRecordPath.tenant_observed(str(record["tenantId"])))
    correlation = contract(
        reader, "/static", StateRecordPath.authorization_correlation(str(record["correlationId"]))
    )
    job = contract(reader, "/static", StateRecordPath.authorization_job(str(correlation["jobId"])))
    result = contract(reader, "/static", StateRecordPath.authorization_result(str(job["jobId"])))
    _validate_request_integrity(job)
    _validate_request_integrity(correlation)
    _require_same_authority(job, correlation)
    _validate_result_binding(job, result)
    if (
        observed["observedState"] != "archived"
        or observed["desiredManifestDigest"] != manifest_digest(row["desired"]).to_dict()
        or observed["activeDeploymentId"] is not None
        or observed["runtimeGenerationId"] is not None
        or job["phase"] != "completed"
        or job["executionValidated"] is not True
        or result["status"] != "succeeded"
        or result["operation"] != "archive"
        or result["archiveRecord"] != record
        or result["manifest"] != row["desired"]
    ):
        raise RetirementError("frozen fixture lacks its completed archived authority")
    for path in ("/static/intents", "/static/exports", "/static/intake"):
        if reader.names(path):
            raise RetirementError("frozen fixture has unresolved intent, export or intake state")
    if reader.names("/static/platform") != {"namespace.json": "regular"}:
        raise RetirementError("frozen fixture platform has quarantine or unknown state")
    contract(reader, "/static", StateRecordPath.platform_namespace())
    segments = reader.names("/static/audit")
    if segments != {"segment-00000000000000000000.jsonl": "regular"}:
        raise RetirementError("frozen fixture audit inventory exceeds this narrow transition")
    directory(scratch)
    (scratch / "audit").mkdir(mode=0o700)
    segment = reader.read("/static/audit/segment-00000000000000000000.jsonl")
    preserve(scratch / "audit/segment-00000000000000000000.jsonl", iter((segment,)), len(segment))
    with DurableDirectory.open(
        scratch, expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as root:
        audit = inspect_audit_readonly(
            root,
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
            expected_record_mode=0o600,
        )
        lookup = inspect_audit_correlation(
            root,
            str(record["correlationId"]),
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
            expected_record_mode=0o600,
            read_only=True,
        )
    if (
        lookup.state != audit
        or lookup.entry is None
        or lookup.has_later_tenant_state_transition
        or lookup.entry["resultDigest"] != result_digest(result).to_dict()
        or lookup.entry["tenantId"] != record["tenantId"]
        or lookup.entry["operation"] != "archive"
        or lookup.entry["resultStatus"] != "succeeded"
        or lookup.entry["operatorPrincipal"] != job["operatorPrincipal"]
    ):
        raise RetirementError("frozen fixture audit does not bind the final archive result")
    with parser_work_budget():
        inspection = inspect_portable_bundle(archive, expected_owner=os.geteuid())
        require_archive_inspection(inspection, record, row["desired"])
    if (
        fingerprint(state_image, image["size"]) != image
        or fingerprint(archive, cast(int, expected["size"])) != expected
    ):
        raise RetirementError("preserved archive or state changed during native validation")
    return {
        "archive": selected,
        "image": image,
        "result": result,
        "tenant_job_audit_unchanged": True,
        "qualification_authority": "none",
    }
