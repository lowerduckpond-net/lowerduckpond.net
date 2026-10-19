"""Exact reviewable authorization, distinct from private bootstrap configuration."""

from __future__ import annotations

from datetime import datetime, timedelta

from scripts.m3_11_qualification_evidence import digest as sha256
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import standing_authority
from scripts.m3_11_unattended.model import LifecycleError, Targets, identity, instant
from scripts.production_qualification_inputs import revision

FORMAT = "lowerduckpond-m3-11-live-approval-v2"
PREPARED = {"source_revision", "helper_revision", "controller_image", "artifact_sha256", "daemon"}


def preparation(value: object) -> dict[str, object]:
    prepared = fields(value, PREPARED)
    revision(prepared["source_revision"])
    revision(prepared["helper_revision"])
    sha256(prepared["artifact_sha256"])
    image = prepared["controller_image"]
    if not isinstance(image, str) or not image.startswith("sha256:"):
        raise LifecycleError("approval controller image is invalid")
    sha256(image.removeprefix("sha256:"))
    daemon = fields(prepared["daemon"], {"ID", "Name", "DockerRootDir", "ServerVersion"})
    if any(not isinstance(item, str) or not item for item in daemon.values()):
        raise LifecycleError("approval Docker host identity is incomplete")
    return prepared


def validate(value: object, *, mode: str, now: datetime) -> dict[str, object]:
    if isinstance(value, dict) and value.get("format") == standing_authority.EXECUTION_FORMAT:
        checked = standing_authority.validate(value, mode=mode, now=now)
        preparation(checked["prepared"])
        sha256(checked["qualification_inputs_sha256"])
        return checked
    approved = fields(
        value,
        {
            "format",
            "prepared",
            "targets",
            "qualification_inputs_sha256",
            "modes",
            "approved_at",
            "expires_at",
            "policy_sha256",
            "lease_id",
            "approval_reference",
        },
    )
    sha256(approved["policy_sha256"])
    if approved["lease_id"] is not None:
        identity(approved["lease_id"])
    preparation(approved["prepared"])
    sha256(approved["qualification_inputs_sha256"])
    Targets.parse(approved["targets"])
    modes = approved["modes"]
    reference = approved["approval_reference"]
    if (
        approved["format"] != FORMAT
        or not isinstance(modes, list)
        or not modes
        or len(modes) != len(set(modes))
        or any(item not in {"rehearsal", "qualification"} for item in modes)
        or mode not in modes
        or not instant(approved["approved_at"]) <= now < instant(approved["expires_at"])
        or instant(approved["expires_at"]) - instant(approved["approved_at"]) > timedelta(days=1)
        or not isinstance(reference, str)
        or not reference
        or len(reference) > 256  # noqa: PLR2004 - bounded human approval reference
        or any(ord(char) < 32 for char in reference)  # noqa: PLR2004 - control characters
    ):
        raise LifecycleError("live approval is absent, expired or does not authorize this attempt")
    return approved
