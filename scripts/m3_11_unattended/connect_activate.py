"""Reviewable legacy import and explicit preflight for versioned lease configuration.

No old issuer is stopped here. The operator must establish its exact stopped,
non-restarting state before this import can be published. Import preserves files
and original outcomes; cleanup performs fresh provider verification afterwards.
"""

from __future__ import annotations

import argparse
import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, read_private_bytes, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended.cleanup import sweep_legacy
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_delivery import bundles
from scripts.m3_11_unattended.docker import OWNER, Docker
from scripts.m3_11_unattended.inventory import ConnectInventory
from scripts.m3_11_unattended.journal import (
    MIGRATION_TAG,
    TAG,
    ConnectObligations,
    migration,
    record_title,
)
from scripts.m3_11_unattended.journal import validate as validate_record
from scripts.m3_11_unattended.lifecycle import LeaseLifecycle, _intents, _known_id
from scripts.m3_11_unattended.model import LeaseManifest, LifecycleError, digest, stamp, strings
from scripts.m3_11_unattended.setup import validate
from scripts.m3_11_unattended.state import LeaseState

FORMAT = "lowerduckpond-m3-11-lease-activation-v1"


def retain(path: Path, value: dict[str, object]) -> dict[str, object]:
    if not path.exists():
        write_private(path, value)
    if read_private(path) != value:
        raise LifecycleError("retained activation input differs from the original")
    return value


def local_events(mapping: dict[str, object]) -> list[dict[str, object]]:
    """Recover exact original events from the reviewed private-file inventory."""
    from scripts.m3_11_qualification_evidence import fields  # noqa: PLC0415
    from scripts.m3_11_unattended.creation_outcome import RETAINED_FORMAT  # noqa: PLC0415

    records = []
    for filename, expected in strings(mapping["retained_files"]).items():
        path = Path(filename)
        if hashlib.sha256(read_private_bytes(path)).hexdigest() != expected:
            raise LifecycleError("retained legacy evidence differs from the reviewed import")
        if path.parent.name == "credential-created":
            record = validate_record(read_private(path))
            payload = fields(record["payload"], {"intent_sha256", "credential_id"})
            if (
                record["kind"] != "created"
                or payload["intent_sha256"] != path.stem
                or record["run_id"] != path.parent.parent.name
            ):
                raise LifecycleError("retained legacy creation identity differs")
            records.append(record)
        elif path.parent.name == "credential-aborted":
            envelope = fields(read_private(path), {"format", "intent", "abort"})
            if envelope["format"] != RETAINED_FORMAT:
                raise LifecycleError("retained legacy abort format differs")
            records.extend(
                [validate_record(envelope["intent"]), validate_record(envelope["abort"])]
            )
    return records


def publish_original(journal: ConnectObligations, record: dict[str, object]) -> None:
    """An imported original keeps its exact ID; a lost POST is never repeated."""
    title = record_title(record)
    existing = [row for row in journal._items() if row.get("title") == title]
    if existing:
        if any(journal._read(row, tag=TAG) != record for row in existing):
            raise LifecycleError("original migration event conflicts")
        return
    pending = journal.spool / ("original-" + str(record["event_id"]) + ".json")
    if pending.exists():
        raise LifecycleError("original event publication is uncertain; preserve its identity")
    retain(pending, record)
    journal.client.request(
        "POST",
        f"/v1/vaults/{journal.vault}/items",
        {
            "title": title,
            "category": "SECURE_NOTE",
            "vault": {"id": journal.vault},
            "tags": [TAG],
            "fields": [
                {
                    "id": "notesPlain",
                    "type": "STRING",
                    "purpose": "NOTES",
                    "label": "notesPlain",
                    "value": canonical_bytes(record).decode(),
                }
            ],
        },
    )
    existing = [row for row in journal._items() if row.get("title") == title]
    if not existing or any(journal._read(row, tag=TAG) != record for row in existing):
        raise LifecycleError("original migration event lacks exact readback")


def publish_import(  # noqa: PLR0912 - reviewed originals, files and issuer fencing
    client: Connect, *, vault: str, approved: object, spool: Path, docker: Docker
) -> str:
    mapping = migration(approved)
    expected = digest(mapping)
    journal = ConnectObligations(client, vault, spool=spool, expected=expected)
    items = journal._items()
    if any(item.get("title") == "m3-11-import-" + expected for item in items):
        journal.records()
        return expected
    originals = [
        journal._read(item, tag=TAG)
        for item in items
        if TAG in cast(list[str], item.get("tags", []))
        or re.fullmatch(r"m3-11-[0-9a-f-]{36}-[0-9a-f]{64}", str(item.get("title"))) is not None
    ]
    imported = local_events(mapping)
    by_id = {str(row["event_id"]): row for row in originals}
    for row in imported:
        key = str(row["event_id"])
        if key in by_id and by_id[key] != row:
            raise LifecycleError("local and external legacy events conflict")
        by_id[key] = row
    originals = list(by_id.values())
    from scripts.m3_11_unattended.creation_outcome import is_abort, validate_abort  # noqa: PLC0415

    for record in imported:
        if is_abort(record):
            matches = [
                item
                for item in _intents(originals)
                if isinstance(record["payload"], dict)
                and item.sha256 == record["payload"]["intent_sha256"]
            ]
            if len(matches) != 1:
                raise LifecycleError("imported abort has no original intent")
            validate_abort(record, matches[0], originals)
    if {str(row["event_id"]): digest(row) for row in originals} != mapping["records"]:
        raise LifecycleError("reviewed legacy inventory differs from current original records")
    obligations = cast(dict[str, dict[str, object]], mapping["obligations"])
    owned = _intents(originals)
    if set(obligations) != {item.sha256 for item in owned} or any(
        obligations[item.sha256]["provider_id"] != _known_id(originals, item) for item in owned
    ):
        raise LifecycleError("reviewed import omits or changes an original obligation")
    for filename, expected_file in strings(mapping["retained_files"]).items():
        if hashlib.sha256(read_private_bytes(Path(filename))).hexdigest() != expected_file:
            raise LifecycleError("retained legacy evidence differs from the reviewed import")
    issuers = cast(list[dict[str, object]], mapping["issuers"])
    current_ids = (
        docker.command(
            "ps",
            "--all",
            "--filter",
            "label=" + OWNER + "=true",
            "--filter",
            "name=ldp-m311-controller-",
            "--no-trunc",
            "--format",
            "{{.ID}}",
        )
        .decode()
        .splitlines()
    )
    if set(current_ids) != {row["container_id"] for row in issuers}:
        raise LifecycleError("legacy issuer inventory differs from the reviewed import")
    for row in issuers:
        actual = docker.owned(str(row["container_id"]))
        if (
            actual.get("Id") != row["container_id"]
            or digest(docker.info()) != row["daemon_sha256"]
            or cast(dict[str, object], actual.get("State", {})).get("Running") is not False
            or cast(dict[str, object], actual.get("HostConfig", {})).get("RestartPolicy")
            != {"Name": "no", "MaximumRetryCount": 0}
        ):
            raise LifecycleError("an original issuer may still execute or restart")
    for record in imported:
        publish_original(journal, record)
    pending = spool / ("import-" + expected + ".json")
    if pending.exists():
        raise LifecycleError("legacy import POST is uncertain; reconcile its original identity")
    retain(pending, mapping)
    client.request(
        "POST",
        f"/v1/vaults/{vault}/items",
        {
            "title": "m3-11-import-" + expected,
            "category": "SECURE_NOTE",
            "vault": {"id": vault},
            "tags": [MIGRATION_TAG],
            "fields": [
                {
                    "id": "notesPlain",
                    "type": "STRING",
                    "purpose": "NOTES",
                    "label": "notesPlain",
                    "value": canonical_bytes(mapping).decode(),
                }
            ],
        },
    )
    journal.records()
    return expected


def activate(output: Path) -> dict[str, object]:
    controller, independent = bundles(output)
    config = LeaseConfiguration.load(output / "controller-connect.json")
    validate(config, now=datetime.now(UTC))
    client = config.generations[config.active_generation]["cleanup"].reader()
    legacy = sweep_legacy(config, client, root=output)
    if legacy["status"] != "ready":
        raise LifecycleError("legacy cleanup is unresolved; cutover remains blocked")
    inventory = ConnectInventory(client, config.journal_vault, spool=output / "pending")
    records = inventory.records()
    manifests = {
        row["lease_id"]: LeaseManifest.parse(row["payload"])
        for row in records
        if row["slot"] == "manifest"
    }
    if any(row["lease_id"] not in manifests for row in records):
        raise LifecycleError("activation inventory has outcomes without their manifest")
    for lease_id, manifest in manifests.items():
        if any(row["lease_id"] == lease_id and row["slot"] == "closed" for row in records):
            continue
        lifecycle = LeaseLifecycle(
            manifest, inventory, LeaseState(output / "leases" / str(lease_id)), providers={}
        )
        observed = lifecycle.records()
        for intent in manifest.intents:
            generation = lifecycle.cleanup_generation(intent, observed)
            available = config.generations.get(generation.generation_id, {}).get("cleanup")
            if available is None or available.generation != generation:
                raise LifecycleError("activation removed required cleanup authority")
    receipt: dict[str, object] = {
        "format": FORMAT,
        "controller_sha256": hashlib.sha256(controller).hexdigest(),
        "independent_sha256": hashlib.sha256(independent).hexdigest(),
        "migration_sha256": config.migration_sha256,
        "legacy": legacy,
        "observed_at": stamp(datetime.now(UTC)),
        "status": "ready",
    }
    path = output / "activation.json"
    if path.exists():
        receipt["observed_at"] = read_private(path)["observed_at"]
    return retain(path, receipt)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    check = sub.add_parser("preflight")
    check.add_argument("--output", type=Path, required=True)
    imported = sub.add_parser("import")
    imported.add_argument("--configuration", type=Path, required=True)
    imported.add_argument("--approved-import", type=Path, required=True)
    imported.add_argument("--spool", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.operation == "preflight":
            activate(args.output)
        else:
            config = LeaseConfiguration.load(args.configuration)
            mapping = read_private(args.approved_import)
            if digest(migration(mapping)) != config.migration_sha256:
                raise LifecycleError("configuration does not approve this import")
            publish_import(
                config.generations[config.active_generation]["cleanup"].reader(),
                vault=config.journal_vault,
                approved=mapping,
                spool=args.spool,
                docker=Docker(),
            )
    except RuntimeError, OSError, ValueError, KeyError, TypeError:
        parser.exit(1, "Migration or activation is unresolved; preserve original access.\n")
    print("Verified local activation evidence retained; no qualification started.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
