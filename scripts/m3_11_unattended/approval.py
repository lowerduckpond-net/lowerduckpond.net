"""Exact reviewable authorization, distinct from private bootstrap configuration."""

from __future__ import annotations

from datetime import datetime, timedelta

from scripts.m3_11_qualification_evidence import digest as sha256
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.model import LifecycleError, Targets, instant
from scripts.production_qualification_inputs import revision

FORMAT = "lowerduckpond-m3-11-live-approval-v1"
PREPARED = {"source_revision", "helper_revision", "controller_image", "artifact_sha256", "daemon"}


def validate(value: object, *, mode: str, now: datetime) -> dict[str, object]:
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
            "credential_lifetime_hours",
            "approval_reference",
        },
    )
    prepared = fields(approved["prepared"], PREPARED)
    revision(prepared["source_revision"])
    revision(prepared["helper_revision"])
    sha256(prepared["artifact_sha256"])
    sha256(approved["qualification_inputs_sha256"])
    image = prepared["controller_image"]
    if not isinstance(image, str) or not image.startswith("sha256:"):
        raise LifecycleError("approval controller image is invalid")
    sha256(image.removeprefix("sha256:"))
    daemon = fields(prepared["daemon"], {"ID", "Name", "DockerRootDir", "ServerVersion"})
    if any(not isinstance(item, str) or not item for item in daemon.values()):
        raise LifecycleError("approval Docker host identity is incomplete")
    Targets.parse(approved["targets"])
    modes = approved["modes"]
    reference = approved["approval_reference"]
    if (
        approved["format"] != FORMAT
        or approved["credential_lifetime_hours"] != 14  # noqa: PLR2004 - approved native expiry
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
