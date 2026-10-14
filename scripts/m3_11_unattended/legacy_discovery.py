"""Non-authorizing historical discovery followed by a fresh, fenced import.

Discovery permits running legacy actors. It freezes originals and actor identity,
not a future stopped state. Later cleanup facts may extend that inventory.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import legacy_actors
from scripts.m3_11_unattended import legacy_bridge_contract as bridge_contract
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.docker import Docker
from scripts.m3_11_unattended.journal import LegacyRecords, validate
from scripts.m3_11_unattended.legacy_terminal import retained_bytes
from scripts.m3_11_unattended.lifecycle import _intents
from scripts.m3_11_unattended.model import (
    LifecycleError,
    digest,
    fingerprint,
    instant,
    stamp,
    strings,
)

DECLARATIONS = "lowerduckpond-m3-11-migration-declarations-v2"
DISCOVERY = "lowerduckpond-m3-11-migration-discovery-v1"
EVIDENCE = "lowerduckpond-m3-11-migration-evidence-v2"
MIGRATION = "lowerduckpond-m3-11-legacy-import-v2"


def extends(original: list[dict[str, object]], current: list[dict[str, object]]) -> None:
    before = {str(row["event_id"]): validate(row) for row in original}
    after = {str(row["event_id"]): validate(row) for row in current}
    if (
        len(before) != len(original)
        or len(after) != len(current)
        or any(after.get(key) != row for key, row in before.items())
    ):
        raise LifecycleError("discovered original evidence disappeared or changed")
    if any(
        row["kind"] in {"run", "intent", "created"} and key not in before
        for key, row in after.items()
    ):
        raise LifecycleError("new legacy issuance requires discovery and review")


def collect(
    reader: Connect, *, vault: str, declarations: object, docker: Docker
) -> dict[str, object]:
    from scripts.m3_11_unattended.connect_activate import local_events  # noqa: PLC0415
    from scripts.m3_11_unattended.operator_records import migration_body  # noqa: PLC0415

    declared = fields(
        declarations, {"format", "retained_files", "obligations", "expiry_updates", "actors"}
    )
    filenames, raw_actors = declared["retained_files"], declared["actors"]
    if (
        declared["format"] != DECLARATIONS
        or not isinstance(filenames, list)
        or not isinstance(raw_actors, list)
    ):
        raise LifecycleError("historical discovery declarations are invalid")
    if any(not isinstance(name, str) or not Path(name).is_absolute() for name in filenames) or len(
        set(filenames)
    ) != len(filenames):
        raise LifecycleError("historical discovery requires unique original paths")
    journal = LegacyRecords(reader, vault)

    def snapshot() -> dict[str, object]:
        retained = {
            name: hashlib.sha256(retained_bytes(declared, Path(name))).hexdigest()
            for name in filenames
        }
        records = journal.originals()
        by_id = {str(row["event_id"]): row for row in records}
        for row in local_events(
            {"retained_files": retained, "expiry_updates": declared["expiry_updates"]}
        ):
            key = str(row["event_id"])
            if key in by_id and by_id[key] != row:
                raise LifecycleError("local and external original evidence conflict")
            by_id[key] = row
        records = [by_id[key] for key in sorted(by_id)]
        actors = [legacy_actors.observe(docker, row, records, retained) for row in raw_actors]
        ids, runs = (
            {str(row["container_id"]) for row in actors},
            {str(row["run_id"]) for row in actors if row["run_id"] is not None},
        )
        if (
            len(ids) != len(actors)
            or len(runs) != sum(row["run_id"] is not None for row in actors)
            or ids != legacy_actors.inventory(docker, reader_images=bridge_contract.images(actors))
            or not {item.run_id for item in _intents(records)} <= runs
        ):
            raise LifecycleError("historical discovery lacks complete original actor coverage")
        # No consent or fence is made here. The pure proposal body validator
        # checks declaration coverage/claims, without producing an approved import.
        migration_body(
            {
                "format": EVIDENCE,
                "records": records,
                "retained_files": retained,
                "obligations": declared["obligations"],
                "expiry_updates": declared["expiry_updates"],
                "issuers": [],
            }
        )
        return {
            "format": DISCOVERY,
            "records": records,
            "retained_files": retained,
            "obligations": declared["obligations"],
            "expiry_updates": declared["expiry_updates"],
            "actors": actors,
            "daemon": docker.info(),
        }

    before, after = snapshot(), snapshot()
    compare(before, after)
    return after


def compare(before: dict[str, object], after: dict[str, object]) -> None:
    required = {
        "format",
        "records",
        "retained_files",
        "obligations",
        "expiry_updates",
        "actors",
        "daemon",
    }
    fields(before, required)
    fields(after, required)
    if (
        before["format"] != DISCOVERY
        or after["format"] != DISCOVERY
        or any(before[key] != after[key] for key in required - {"records"})
    ):
        raise LifecycleError("historical actor identity, originals or declarations changed")
    extends(
        cast(list[dict[str, object]], before["records"]),
        cast(list[dict[str, object]], after["records"]),
    )


def finalize(
    reader: Connect, *, vault: str, declarations: object, docker: Docker
) -> dict[str, object]:
    value = fields(declarations, {"format", "discovery", "fences"})
    if (
        value["format"] != "lowerduckpond-m3-11-migration-fences-v2"
        or not isinstance(value["discovery"], dict)
        or not isinstance(value["fences"], list)
    ):
        raise LifecycleError("final migration needs original discovery and explicit fences")
    original = value["discovery"]
    if not isinstance(original.get("actors"), list):
        raise LifecycleError("original actor discovery is unavailable")
    fresh = collect(
        reader,
        vault=vault,
        docker=docker,
        declarations={
            "format": DECLARATIONS,
            "retained_files": list(strings(original["retained_files"])),
            "obligations": original["obligations"],
            "expiry_updates": original["expiry_updates"],
            "actors": [
                {key: row[key] for key in legacy_actors.DESCRIPTOR} for row in original["actors"]
            ],
        },
    )
    compare(original, fresh)
    actors = {
        str(row["container_id"]): row for row in cast(list[dict[str, object]], fresh["actors"])
    }
    issuers = []
    used = set()
    for raw in value["fences"]:
        fence = fields(raw, {"container_id", "stopped_at", "issuance_disabled"})
        selected = fingerprint(fence["container_id"])
        if (
            selected not in actors
            or selected in used
            or fence["issuance_disabled"] is not True
            or instant(fence["stopped_at"]) > datetime.now(UTC)
        ):
            raise LifecycleError("final issuer fence is incomplete or invalid")
        state = legacy_actors.fenced(docker, actors[selected])
        used.add(selected)
        issuers.append(
            {
                **fence,
                # A historical operator timestamp cannot make a pre-fence
                # restoration look newer than this actual fence observation.
                "stopped_at": stamp(datetime.now(UTC)),
                "fence_state": state,
                "daemon_sha256": digest(docker.info()),
                "running": False,
                "restart_policy": "no",
                "actor": actors[selected],
            }
        )
    if (
        used != set(actors)
        or legacy_actors.inventory(
            docker, reader_images=bridge_contract.images(list(actors.values()))
        )
        != used
    ):
        raise LifecycleError("final fences do not cover every discovered issuer")
    return {
        "format": EVIDENCE,
        "records": fresh["records"],
        "retained_files": fresh["retained_files"],
        "obligations": fresh["obligations"],
        "expiry_updates": fresh["expiry_updates"],
        "issuers": issuers,
    }
