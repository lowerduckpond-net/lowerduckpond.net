"""Reviewable legacy import and explicit preflight for versioned lease configuration.

No old issuer is stopped here. The operator must establish its exact stopped,
non-restarting state before this import can be published. Import preserves files
and original outcomes; outstanding cleanup still requires provider verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, read_private_bytes, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended import legacy_bridge_contract as bridge_contract
from scripts.m3_11_unattended.cleanup import sweep_legacy
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_delivery import bundles
from scripts.m3_11_unattended.docker import OWNER, ROOT, Docker, controller_name
from scripts.m3_11_unattended.inventory import ConnectInventory
from scripts.m3_11_unattended.journal import (
    MAX_OUTPUT,
    MIGRATION_FORMAT_V2,
    MIGRATION_TAG,
    TAG,
    ConnectObligations,
    LegacyRecords,
    migration,
    record_title,
)
from scripts.m3_11_unattended.journal import validate as validate_record
from scripts.m3_11_unattended.legacy_terminal import (
    original_run,
    require_terminal_run,
    validate_claims,
)
from scripts.m3_11_unattended.lifecycle import LeaseLifecycle, _intents, _known_id
from scripts.m3_11_unattended.model import (
    LeaseManifest,
    LifecycleError,
    digest,
    fingerprint,
    identity,
    instant,
    stamp,
    strings,
)
from scripts.m3_11_unattended.setup import validate
from scripts.m3_11_unattended.state import LeaseState

FORMAT = "lowerduckpond-m3-11-lease-activation-v1"
UTILITY_FORMAT = "lowerduckpond-m3-11-daemon-utility-v1"
DECLARATIONS_FORMAT = "lowerduckpond-m3-11-migration-declarations-v1"
MAX_UTILITY_BYTES = MAX_OUTPUT


def issuer_bound(
    docker: Docker, issuer: dict[str, object], request: dict[str, object]
) -> dict[str, object]:
    selected = fingerprint(issuer["container_id"])
    actual = docker.owned(selected)
    binding = fields(
        request["binding"],
        {
            "managed_run_id",
            "source_revision",
            "helper_revision",
            "qualification_inputs_sha256",
            "storage_target_sha256",
            "artifact_sha256",
        },
    )
    if (
        actual.get("Id") != selected
        or actual.get("Name") != "/" + controller_name(identity(binding["managed_run_id"]))
        or actual.get("Image") != request["controller_image"]
        or cast(dict[str, dict[str, object]], actual.get("Config", {}))
        .get("Labels", {})
        .get(OWNER + ".source")
        != binding["helper_revision"]
        or docker.info() != request["daemon"]
        or digest(docker.info()) != issuer["daemon_sha256"]
        or cast(dict[str, object], actual.get("State", {})).get("Running") is not False
        or cast(dict[str, object], actual.get("HostConfig", {})).get("RestartPolicy")
        != {"Name": "no", "MaximumRetryCount": 0}
        or issuer["issuance_disabled"] is not True
        or instant(issuer["stopped_at"]) > datetime.now(UTC)
    ):
        raise LifecycleError("legacy issuer fence differs from its original run")
    return {
        "container_id": selected,
        "request_sha256": digest(request),
        "binding_sha256": digest(binding),
        "issuer_sha256": digest(issuer),
    }


def inspect_import(
    reader: Connect, *, vault: str, declarations: object, docker: Docker
) -> dict[str, object]:
    """Collect original evidence before assembly; no import or provider mutation."""
    if (
        isinstance(declarations, dict)
        and declarations.get("format") == "lowerduckpond-m3-11-migration-fences-v2"
    ):
        from scripts.m3_11_unattended.legacy_discovery import finalize  # noqa: PLC0415

        return finalize(reader, vault=vault, declarations=declarations, docker=docker)
    from scripts.m3_11_unattended.operator_records import (  # noqa: PLC0415
        EVIDENCE_FORMAT,
        migration_body,
    )

    declared = fields(
        declarations, {"format", "retained_files", "obligations", "expiry_updates", "issuers"}
    )
    if (
        declared["format"] != DECLARATIONS_FORMAT
        or not isinstance(declared["retained_files"], list)
        or not isinstance(declared["issuers"], list)
    ):
        raise LifecycleError("migration collection declarations are invalid")
    filenames = declared["retained_files"]
    if any(not isinstance(name, str) or not Path(name).is_absolute() for name in filenames) or len(
        filenames
    ) != len(set(filenames)):
        raise LifecycleError("migration collection needs unique canonical original paths")
    journal = LegacyRecords(reader, vault)

    def snapshot() -> dict[str, object]:
        retained = {
            name: hashlib.sha256(read_private_bytes(Path(name))).hexdigest() for name in filenames
        }
        records = journal.originals()
        by_id = {str(row["event_id"]): row for row in records}
        for row in local_events({"retained_files": retained}):
            key = str(row["event_id"])
            if key in by_id and by_id[key] != row:
                raise LifecycleError("local and external original evidence conflict")
            by_id[key] = row
        records = [by_id[key] for key in sorted(by_id)]
        issuers = []
        runs = set()
        for raw in cast(list[object], declared["issuers"]):
            declaration = fields(raw, {"container_id", "stopped_at", "issuance_disabled"})
            selected = fingerprint(declaration["container_id"])
            actual = docker.owned(selected)
            name = str(actual.get("Name", ""))
            if not name.startswith("/ldp-m311-controller-"):
                raise LifecycleError("legacy controller name is invalid")
            import uuid  # noqa: PLC0415

            run_id = identity(str(uuid.UUID(name.removeprefix("/ldp-m311-controller-"))))
            matches = [
                Path(name).parent
                for name in retained
                if Path(name).name == "request.json" and Path(name).parent.name == run_id
            ]
            if len(matches) != 1 or run_id in runs:
                raise LifecycleError("legacy issuer lacks its unique original request")
            runs.add(run_id)
            request = original_run(matches[0], records, retained)
            issuer = {
                **declaration,
                "daemon_sha256": digest(docker.info()),
                "running": False,
                "restart_policy": "no",
            }
            issuer_bound(docker, issuer, request)
            issuers.append(issuer)
        current = (
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
        if (
            len(current) != len(set(current))
            or set(current) != {row["container_id"] for row in issuers}
            or {intent.run_id for intent in _intents(records)} != runs
        ):
            raise LifecycleError("migration collection lacks complete original issuer coverage")
        result = {
            "format": EVIDENCE_FORMAT,
            "records": records,
            "retained_files": retained,
            "obligations": declared["obligations"],
            "expiry_updates": declared["expiry_updates"],
            "issuers": issuers,
        }
        migration_body(result)
        return result

    observed = snapshot()
    if snapshot() != observed:
        raise LifecycleError("migration evidence changed during collection")
    return observed


def admission_projection(
    config: LeaseConfiguration, *, run_id: str, container_id: str, directory: Path, docker: Docker
) -> dict[str, object]:
    if config.mode != "cleanup-only" or directory.name != identity(run_id):
        raise LifecycleError("legacy admission requires its cleanup-only run binding")
    # Scratch is private and ephemeral. This operation never opens the import
    # publisher's durable spool and never calls any provider or journal writer.
    with tempfile.TemporaryDirectory(prefix="ldp-legacy-read-") as temporary:
        journal = ConnectObligations(
            config.generations[config.active_generation]["cleanup"].reader(),
            config.journal_vault,
            spool=Path(temporary),
            expected=config.migration_sha256,
        )
        records = journal.records()
        mapping = journal.mapping
        if mapping is None:
            raise LifecycleError("approved legacy mapping is unavailable")
        request = require_terminal_run(directory, mapping, records, targets=config.targets)
        issuers = [
            row
            for row in cast(list[dict[str, object]], mapping["issuers"])
            if row["container_id"] == fingerprint(container_id)
        ]
        if len(issuers) != 1:
            raise LifecycleError("legacy admission lacks its exact approved issuer fence")
        if mapping["format"] == MIGRATION_FORMAT_V2:
            from scripts.m3_11_unattended import legacy_actors  # noqa: PLC0415

            recheck_import(mapping, docker)
            actor = cast(dict[str, object], issuers[0]["actor"])
            observed = legacy_actors.observe(
                docker,
                {k: actor[k] for k in legacy_actors.DESCRIPTOR},
                records,
                strings(mapping["retained_files"]),
            )
            if observed != actor:
                raise LifecycleError("legacy admission actor differs from discovery")
            bound: dict[str, object] = {
                "container_id": container_id,
                "request_sha256": digest(request),
                "binding_sha256": digest(request["binding"]),
                "issuer_sha256": digest(issuers[0]),
            }
        else:
            bound = issuer_bound(docker, issuers[0], request)
        for intent in _intents(records):
            if intent.run_id == run_id and intent.targets != config.targets:
                raise LifecycleError(
                    "legacy admission targets differ from the approved configuration"
                )
            obligation = cast(dict[str, dict[str, object]], mapping["obligations"])[intent.sha256]
            bootstrap = config.generations.get(str(obligation["generation_id"]), {}).get("cleanup")
            if (
                bootstrap is not None
                and bootstrap.generation.fingerprints[intent.provider]
                != intent.cleanup_authority_sha256
            ):
                raise LifecycleError("legacy admission authority differs from its original intent")
        return {
            "format": "lowerduckpond-m3-11-legacy-admission-v1",
            "run_id": run_id,
            "mapping_sha256": config.migration_sha256,
            "helper_revision": config.helper_revision,
            "records_sha256": digest(sorted(records, key=lambda row: str(row["event_id"]))),
            **bound,
        }


def daemon_utility(
    envelope: object,
    *,
    evidence_root: Path = Path("/evidence"),
    import_root: Path = Path("/cleanup/legacy-import"),
) -> dict[str, object]:
    """Private-stdin entry on the exact prepared daemon helper."""
    from scripts.m3_11_unattended import approval  # noqa: PLC0415
    from scripts.m3_11_unattended.connect_configuration import reader  # noqa: PLC0415
    from scripts.m3_11_unattended.state import private_directory  # noqa: PLC0415
    from scripts.production_qualification_inputs import current_candidate, revision  # noqa: PLC0415

    value = fields(envelope, {"format", "operation", "prepared", "payload"})
    prepared = fields(value["prepared"], approval.PREPARED)
    source = revision(prepared["source_revision"])
    docker = Docker()
    current_candidate(ROOT, source)
    artifact = evidence_root / "prepared" / source / "static-host-agent.tar"
    with artifact.open("rb") as stream:
        actual_artifact = hashlib.file_digest(stream, "sha256").hexdigest()
    if (
        value["format"] != UTILITY_FORMAT
        or prepared["helper_revision"] != source
        or prepared["daemon"] != docker.info()
        or prepared["artifact_sha256"] != actual_artifact
    ):
        raise LifecycleError("daemon utility differs from the exact prepared inputs")
    operation = value["operation"]
    if operation in {"discover-import", "inspect-import"}:
        payload = fields(value["payload"], {"historical_reader", "journal_vault", "declarations"})
        from scripts.m3_11_unattended.legacy_discovery import collect  # noqa: PLC0415

        operation_reader = collect if operation == "discover-import" else inspect_import
        return operation_reader(
            reader(payload["historical_reader"]),
            vault=str(payload["journal_vault"]),
            declarations=payload["declarations"],
            docker=docker,
        )
    payload = fields(
        value["payload"],
        {"configuration", "mapping"}
        if operation == "import"
        else {"configuration", "run_id", "container_id"},
    )
    config = LeaseConfiguration.parse(payload["configuration"])
    if config.mode != "cleanup-only" or config.helper_revision != source:
        raise LifecycleError("daemon utility accepts only the prepared cleanup-only configuration")
    if operation == "admission":
        run_id = identity(payload["run_id"])
        return admission_projection(
            config,
            run_id=run_id,
            container_id=str(payload["container_id"]),
            directory=evidence_root / "runs" / run_id,
            docker=docker,
        )
    if operation != "import" or digest(migration(payload["mapping"])) != config.migration_sha256:
        raise LifecycleError("daemon utility import differs from its approved mapping")
    root = import_root
    root.mkdir(mode=0o700, exist_ok=True)
    private_directory(root)
    spool = root / config.migration_sha256
    spool.mkdir(mode=0o700, exist_ok=True)
    retain(spool / "binding.json", {"migration_sha256": config.migration_sha256})
    result = publish_import(
        config.generations[config.active_generation]["cleanup"].reader(),
        vault=config.journal_vault,
        approved=payload["mapping"],
        spool=spool,
        docker=docker,
    )
    return {"format": UTILITY_FORMAT, "operation": "import", "migration_sha256": result}


def retain(path: Path, value: dict[str, object]) -> dict[str, object]:
    if not path.exists():
        write_private(path, value, maximum=MAX_OUTPUT)
    if read_private(path, maximum=MAX_OUTPUT) != value:
        raise LifecycleError("retained activation input differs from the original")
    return value


def local_events(mapping: dict[str, object]) -> list[dict[str, object]]:
    """Recover exact original events from the reviewed private-file inventory."""
    from scripts.m3_11_qualification_evidence import fields  # noqa: PLC0415
    from scripts.m3_11_unattended.creation_outcome import RETAINED_FORMAT  # noqa: PLC0415
    from scripts.m3_11_unattended.legacy_terminal import retained_bytes  # noqa: PLC0415

    records = []
    for filename, expected in strings(mapping["retained_files"]).items():
        path = Path(filename)
        if hashlib.sha256(retained_bytes(mapping, path)).hexdigest() != expected:
            raise LifecycleError("retained legacy evidence differs from the reviewed import")
        from scripts.m3_11_unattended.legacy_actors import MANUAL_EVENTS  # noqa: PLC0415

        if path.parent.parent.name == "manual-page-rules" and path.name in MANUAL_EVENTS:
            record = validate_record(read_private(path))
            if record["run_id"] != path.parent.name:
                raise LifecycleError("manual original event identity differs")
            records.append(record)
        elif path.parent.name == "credential-created":
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


def reader_images(mapping: dict[str, object]) -> set[str]:
    """Use the original approved image bindings, never bridge-provided tags."""
    issuers = cast(list[dict[str, object]], mapping["issuers"])
    if mapping["format"] == MIGRATION_FORMAT_V2:
        return bridge_contract.images([cast(dict[str, object], row["actor"]) for row in issuers])
    # The opt-in bridge admits only v2 imports. V1 cannot confer bridge authority.
    return set()


def recheck_import(mapping: dict[str, object], docker: Docker) -> None:
    """Fresh original-file and issuer facts are required even after visible publication."""
    from scripts.m3_11_unattended.legacy_terminal import retained_bytes  # noqa: PLC0415

    for filename, expected_file in strings(mapping["retained_files"]).items():
        if hashlib.sha256(retained_bytes(mapping, Path(filename))).hexdigest() != expected_file:
            raise LifecycleError("retained legacy evidence differs from the reviewed import")
    issuers = cast(list[dict[str, object]], mapping["issuers"])
    if mapping["format"] == MIGRATION_FORMAT_V2:
        from scripts.m3_11_unattended import legacy_actors  # noqa: PLC0415

        if legacy_actors.inventory(docker, reader_images=reader_images(mapping)) != {
            row["container_id"] for row in issuers
        }:
            raise LifecycleError("legacy actor inventory differs from the reviewed import")
        for row in issuers:
            if digest(docker.info()) != row["daemon_sha256"]:
                raise LifecycleError("legacy actor daemon differs")
            if (
                legacy_actors.fenced(docker, cast(dict[str, object], row["actor"]))
                != row["fence_state"]
            ):
                raise LifecycleError("legacy actor restarted after its reviewed fence")
        return
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


def publish_import(
    client: Connect, *, vault: str, approved: object, spool: Path, docker: Docker
) -> str:
    mapping = migration(approved)
    expected = digest(mapping)
    journal = ConnectObligations(client, vault, spool=spool, expected=expected)
    items = journal._items()
    if any(item.get("title") == "m3-11-import-" + expected for item in items):
        journal.records()
        recheck_import(mapping, docker)
        return expected
    originals = journal.originals()
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
    minimum = strings(mapping["records"])
    actual = {str(row["event_id"]): digest(row) for row in originals}
    if (
        any(actual.get(key) != expected for key, expected in minimum.items())
        or (mapping["format"] != MIGRATION_FORMAT_V2 and actual != minimum)
        or any(
            row["kind"] in {"run", "intent", "created"} and str(row["event_id"]) not in minimum
            for row in originals
        )
    ):
        raise LifecycleError("reviewed legacy inventory differs from current original records")
    obligations = cast(dict[str, dict[str, object]], mapping["obligations"])
    owned = _intents(originals)
    if set(obligations) != {item.sha256 for item in owned} or any(
        obligations[item.sha256]["provider_id"] != _known_id(originals, item) for item in owned
    ):
        raise LifecycleError("reviewed import omits or changes an original obligation")
    validate_claims(mapping, originals)
    recheck_import(mapping, docker)
    from scripts.m3_11_unattended.legacy_actors import require_import_readers  # noqa: PLC0415

    for record in imported:
        publish_original(journal, record)
    pending = spool / ("import-" + expected + ".json")
    if pending.exists():
        raise LifecycleError("legacy import POST is uncertain; reconcile its original identity")
    require_import_readers(docker, vault=vault, expected=expected, images=reader_images(mapping))
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
    validate(config, now=datetime.now(UTC), active_only=True)
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
    checked = {config.active_generation}
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
            if generation.generation_id not in checked:
                available.providers(targets=config.targets, now=datetime.now(UTC), reader=client)
                checked.add(generation.generation_id)
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
    if sys.argv[1:] == ["daemon-utility"]:
        try:
            raw = sys.stdin.buffer.read(MAX_UTILITY_BYTES + 1)
            if len(raw) > MAX_UTILITY_BYTES:
                raise LifecycleError("daemon utility input exceeded its bound")
            envelope = json.loads(raw)
            result = daemon_utility(envelope)
            output = canonical_bytes(
                {"format": UTILITY_FORMAT, "input_sha256": digest(envelope), "result": result}
            )
            if len(output) > MAX_UTILITY_BYTES:
                raise LifecycleError("daemon utility output exceeded its bound")
            sys.stdout.buffer.write(output)
            return 0
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            print(
                "Daemon migration operation is unresolved; preserve original evidence.",
                file=sys.stderr,
            )
            return 1
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
            mapping = read_private(args.approved_import, maximum=MAX_OUTPUT)
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
