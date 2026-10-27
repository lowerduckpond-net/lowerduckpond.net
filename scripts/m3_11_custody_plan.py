"""Exact new authority over preserved history; never rebind a historical lease."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from pathlib import Path

from scripts.m3_11_frozen_retirement import fingerprint
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_archive import records
from scripts.m3_11_retirement_files import RetirementError, digest
from scripts.m3_11_unattended.model import identity, instant
from scripts.production_qualification_inputs import revision

FORMAT = "lowerduckpond-m3-11-custody-retirement-v1"
AUTHORIZATION = "lowerduckpond-m3-11-custody-retirement-authorization-v1"
RETAINED = ["original-failure", "sealed-custody", "state", "backup-prefix", "private-copies"]


def require(value: object, explanation: str) -> None:
    if not value:
        raise RetirementError(explanation)


def plan(raw: object) -> dict[str, object]:
    value = fields(
        raw,
        {
            "format",
            "fixture_id",
            "source_workspace_id",
            "historical_lease_id",
            "historical_manifest_sha256",
            "custody_sha256",
            "evidence_sha256",
            "cleanup_contract_sha256",
            "current_lease_id",
            "current_manifest_sha256",
            "implementation_revision",
            "runtime",
            "archive",
            "retained",
        },
    )
    require(
        value["format"] == FORMAT and value["retained"] == RETAINED,
        "custody retirement plan format differs",
    )
    for key in ("fixture_id", "historical_lease_id", "current_lease_id"):
        identity(value[key])
    workspace_id(value["source_workspace_id"])
    require(
        value["historical_lease_id"] != value["current_lease_id"],
        "historical credentials cannot supply current retirement authority",
    )
    for key in (
        "historical_manifest_sha256",
        "custody_sha256",
        "evidence_sha256",
        "cleanup_contract_sha256",
        "current_manifest_sha256",
    ):
        fingerprint(value[key])
    revision(value["implementation_revision"])
    runtime = fields(
        value["runtime"], {"workspace_id", "daemon_id", "evidence_volume_created_at", "image"}
    )
    workspace_id(runtime["workspace_id"])
    require(
        runtime["workspace_id"] != value["source_workspace_id"],
        "migrated retirement must not execute on the source workspace",
    )
    require(
        isinstance(runtime["daemon_id"], str)
        and re.fullmatch(r"[A-Za-z0-9:-]{8,128}", runtime["daemon_id"]) is not None,
        "custody retirement daemon identity is invalid",
    )
    instant(runtime["evidence_volume_created_at"])
    require(
        isinstance(runtime["image"], str)
        and re.fullmatch(r"sha256:[a-f0-9]{64}", runtime["image"]) is not None,
        "custody retirement image is invalid",
    )
    archive = fields(value["archive"], {"bucket", "key", "version", "size", "sha256"})
    require(
        isinstance(archive["bucket"], str)
        and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", archive["bucket"]) is not None,
        "custody retirement bucket is invalid",
    )
    records([{key: archive[key] for key in ("key", "version", "size", "sha256")}])
    return value


def workspace_id(value: object) -> str:
    require(
        isinstance(value, str) and str(uuid.UUID(value)) == value,
        "custody retirement workspace identity is invalid",
    )
    return str(value)


def authorization(raw: object, approved: dict[str, object], *, now: datetime) -> dict[str, object]:
    value = fields(
        raw,
        {
            "format",
            "plan_sha256",
            "approved_at",
            "approval_reference_sha256",
            "acknowledge_exact_version_loss",
            "acknowledge_permanent_fixture_retirement",
            "acknowledge_current_lease_cleanup_owed",
            "acknowledge_exclusive_archive_writers",
        },
    )
    require(
        value["format"] == AUTHORIZATION
        and value["plan_sha256"] == digest(approved)
        and all(
            value[key] is True
            for key in (
                "acknowledge_exact_version_loss",
                "acknowledge_permanent_fixture_retirement",
                "acknowledge_current_lease_cleanup_owed",
                "acknowledge_exclusive_archive_writers",
            )
        ),
        "exact migrated retirement approval is missing",
    )
    fingerprint(value["approval_reference_sha256"])
    require(instant(value["approved_at"]) <= now, "retirement approval is future dated")
    return value


def local_root(evidence_root: Path, approved: dict[str, object]) -> Path:
    return evidence_root / "custody-retirements" / identity(approved["fixture_id"])
