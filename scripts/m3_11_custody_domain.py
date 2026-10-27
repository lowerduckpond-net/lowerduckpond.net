"""Prove a single native lock domain, rather than trusting copied path strings."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import cast

from scripts.m3_11_custody_plan import require
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.docker import (
    ADMISSION,
    CONFIG_VOLUME,
    EVIDENCE_VOLUME,
    LEASE_DIRECTORY,
    LEASE_VOLUME,
    Docker,
    helper_volume,
)
from scripts.m3_11_unattended.storage_admission import ReadOnlyDocker, require_remaining


class DomainDocker(ReadOnlyDocker):
    def native_volume(self, name: str) -> dict[str, object]:
        require(name in {EVIDENCE_VOLUME, LEASE_VOLUME}, "unapproved retirement volume read")
        require_remaining(120)
        raw = Docker.command(self, "volume", "inspect", name, timeout=120)
        values = json.loads(raw)
        require(
            isinstance(values, list) and len(values) == 1 and isinstance(values[0], dict),
            "native retirement volume identity is unavailable",
        )
        return cast(dict[str, object], values[0])


def verify(docker: DomainDocker, runtime: object, invocation: object, *, helper: str) -> None:
    expected = fields(runtime, {"workspace_id", "daemon_id", "evidence_volume_created_at", "image"})
    call = fields(invocation, {"container_id", "admission_id", "workspace_id", "image"})
    require(
        all(
            isinstance(call[key], str) and re.fullmatch(r"[a-f0-9]{64}", cast(str, call[key]))
            for key in ("container_id", "admission_id")
        ),
        "retirement container identity is not exact",
    )
    require(
        call["workspace_id"] == expected["workspace_id"]
        and docker.info()["ID"] == expected["daemon_id"],
        "retirement is outside the approved crow runtime",
    )
    actor, admission = docker.owned(str(call["container_id"])), docker.owned(ADMISSION)
    actor_state, reservation = actor.get("State"), admission.get("State")
    require(
        isinstance(actor_state, dict)
        and actor_state.get("Running") is True
        and isinstance(reservation, dict)
        and reservation.get("Status") == "created"
        and admission.get("Id") == call["admission_id"]
        and actor.get("Id") == call["container_id"]
        and actor.get("Image") == admission.get("Image") == call["image"] == expected["image"],
        "retirement lacks its held native daemon admission reservation",
    )
    mounts = actor.get("Mounts")
    require(
        isinstance(mounts, list) and all(isinstance(row, dict) for row in mounts),
        "retirement native mounts are unavailable",
    )
    protected = {
        "/evidence": (EVIDENCE_VOLUME, True),
        LEASE_DIRECTORY: (LEASE_VOLUME, True),
        "/configuration": (CONFIG_VOLUME, False),
        "/opt/lifecycle": (helper_volume(helper), False),
    }
    for destination, (name, writable) in protected.items():
        selected = [
            row
            for row in cast(list[dict[str, object]], mounts)
            if row.get("Destination") == destination
        ]
        require(
            len(selected) == 1
            and selected[0].get("Type") == "volume"
            and selected[0].get("Name") == name
            and selected[0].get("RW") is writable,
            "retirement requires actual shared native volumes",
        )
        require(
            not any(
                str(row.get("Destination", "")).startswith(destination + "/")
                for row in cast(list[dict[str, object]], mounts)
            ),
            "retirement native lock mount is shadowed",
        )
        if name in {EVIDENCE_VOLUME, LEASE_VOLUME}:
            volume = docker.native_volume(name)
            require(
                volume.get("Name") == name
                and selected[0].get("Source") == volume.get("Mountpoint"),
                "retirement lock mount differs from the native volume",
            )
            if name == EVIDENCE_VOLUME:
                require(
                    volume.get("CreatedAt") == expected["evidence_volume_created_at"],
                    "retirement evidence volume was replaced",
                )


def admission_domain(docker: Docker, runtime: object, *, evidence_root: Path) -> None:
    expected = fields(runtime, {"workspace_id", "daemon_id", "evidence_volume_created_at", "image"})
    require(
        evidence_root == Path("/evidence") and docker.info()["ID"] == expected["daemon_id"],
        "first custody lease use belongs to another daemon or evidence root",
    )
    values = json.loads(docker.command("volume", "inspect", EVIDENCE_VOLUME))
    require(
        isinstance(values, list) and len(values) == 1 and isinstance(values[0], dict),
        "first custody lease use lacks the native evidence volume",
    )
    volume = values[0]
    actor = docker.owned(Path("/etc/hostname").read_text().strip())
    mounts = actor.get("Mounts")
    require(isinstance(mounts, list), "first custody lease use lacks native mounts")
    selected = [
        row
        for row in cast(list[dict[str, object]], mounts)
        if isinstance(row, dict) and row.get("Destination") == "/evidence"
    ]
    require(
        volume.get("Name") == EVIDENCE_VOLUME
        and volume.get("CreatedAt") == expected["evidence_volume_created_at"]
        and actor.get("Image") == expected["image"]
        and len(selected) == 1
        and selected[0].get("Type") == "volume"
        and selected[0].get("Name") == EVIDENCE_VOLUME
        and selected[0].get("Source") == volume.get("Mountpoint")
        and not any(
            not isinstance(row, dict) or str(row.get("Destination", "")).startswith("/evidence/")
            for row in cast(list[object], mounts)
        ),
        "first custody lease use lost its original native evidence domain",
    )
