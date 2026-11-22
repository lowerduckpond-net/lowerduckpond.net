"""Read-only P4 preparation over two independently enrolled SSH endpoints."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from scripts.m3_12_contracts import (
    Document,
    ValidationError,
    decode,
    digest,
    encode,
    require,
)
from scripts.m3_12_diagnostic_store import Attempt, clock, failure, publish, read
from scripts.m3_12_droplet_inventory import (
    ConnectedDroplet,
    OwnedDroplet,
    prepare_source_and_restore,
)
from scripts.m3_12_droplet_ssh import Endpoint, observe


def _seal(directory: Path, name: str, document: Document) -> None:
    try:
        publish(directory, name, document)
    except FileExistsError:
        require(read(directory, name) == document, "droplet-preparation-original-changed")


def _scope(endpoint: Endpoint, production: Document) -> Document:
    _, key = endpoint.validate()
    approved = endpoint.allocation
    require(
        type(endpoint.provider.droplet_id) is int
        and endpoint.provider.droplet_id > 0
        and all(
            re.fullmatch(r"[0-9a-f]{64}", value) is not None
            for value in (
                endpoint.provider.project_id_sha256,
                approved.state_sha256,
                approved.allocation_sha256,
                approved.inventory_sha256,
                approved.transaction_namespace_sha256,
            )
        ),
        "droplet-preparation-allocation-invalid",
    )
    excluded = {*production["dropletIds"], *production["addresses"], *production["identityDigests"]}
    identifiers = {
        endpoint.provider.droplet_id,
        endpoint.provider.ipv4,
        key,
        digest(endpoint.provider.document()),
        approved.state_sha256,
        approved.allocation_sha256,
        approved.inventory_sha256,
        approved.transaction_namespace_sha256,
    }
    require(not excluded.intersection(identifiers), "production-crossover")
    return {
        "provider": endpoint.provider.document(),
        "sshKeySha256": key,
        "stateSha256": approved.state_sha256,
        "allocationSha256": approved.allocation_sha256,
        "inventorySha256": approved.inventory_sha256,
        "transactionNamespaceSha256": approved.transaction_namespace_sha256,
    }


def _observe_role(
    attempt: Attempt, role: str, endpoint: Endpoint, prepared: Document
) -> tuple[OwnedDroplet, Document]:
    doc = observe(endpoint)
    _seal(
        attempt.directory,
        f"droplet-{role}-observation.json",
        {
            "format": "lowerduckpond-m3-12-preparation-observation-v1",
            "role": role,
            "preparationSha256": digest(prepared),
            "observation": doc,
        },
    )
    observed = ConnectedDroplet(
        provider=endpoint.provider,
        metadata_id=doc["metadata"]["dropletId"],
        metadata_ipv4=doc["metadata"]["ipv4"],
        host_identity=doc["hostIdentity"],
        pinned_host_key_sha256=prepared[role]["sshKeySha256"],
    )
    return OwnedDroplet(endpoint.allocation, observed), doc


def _record_failure(attempt: Attempt, started: tuple[str, int], error: Exception) -> None:
    category = "transport" if isinstance(error, ConnectionError) else "authority"
    try:
        attempt.append(
            "preparation",
            "ssh",
            started,
            status=1,
            incident=failure("primary", category, "ssh", error),
        )
    except Exception:
        print("M3.12 SSH preparation failure could not be persisted.", file=sys.stderr)


def prepare(
    attempt: Attempt, source: Endpoint, restore: Endpoint, production_exclusions: bytes
) -> dict[str, tuple[Document, Document]]:
    """Pin both endpoints before connecting. Read back the original preparation on retry."""
    with attempt.lock("controller.lock", blocking=False):
        started = clock()
        attempt.append("preparation", "ssh", started)
        try:
            result = _prepare(attempt, source, restore, production_exclusions)
        except Exception as error:
            _record_failure(attempt, started, error)
            raise
        attempt.append("preparation", "ssh", started, status=0)
        return result


def _prepare(
    attempt: Attempt, source: Endpoint, restore: Endpoint, production_exclusions: bytes
) -> dict[str, tuple[Document, Document]]:
    run_id = attempt.directory.parent.name
    require(
        source.allocation.run_id == restore.allocation.run_id == run_id
        and source.provider.droplet_id != restore.provider.droplet_id
        and source.provider.ipv4 != restore.provider.ipv4
        and source.allocation.transaction_namespace_sha256
        != restore.allocation.transaction_namespace_sha256,
        "droplet-preparation-role-conflict",
    )
    production = decode(production_exclusions, "droplet-production-exclusions")
    prepared: Document = {
        "format": "lowerduckpond-m3-12-disposable-preparation-v1",
        "runId": run_id,
        "invocationId": attempt.directory.name,
        "productionExclusionsSha256": digest(production),
        "source": _scope(source, production),
        "restore": _scope(restore, production),
    }
    require(
        prepared["source"]["sshKeySha256"] != prepared["restore"]["sshKeySha256"],
        "droplet-preparation-role-conflict",
    )
    _seal(attempt.directory, "droplet-preparation.json", prepared)
    source_host, _ = _observe_role(attempt, "source", source, prepared)
    restore_host, restore_doc = _observe_role(attempt, "restore", restore, prepared)
    if restore_doc["state"] not in (
        {"artifactSelected": False, "launchPresent": False, "publication": "absent"},
        {"artifactSelected": False, "launchPresent": False, "publication": "dark"},
    ):
        raise ValidationError("droplet-restore-target-is-not-cold")
    pair = prepare_source_and_restore(source_host, restore_host, production_exclusions)
    _seal(
        attempt.directory,
        "droplet-preparation-result.json",
        {
            "format": "lowerduckpond-m3-12-disposable-preparation-result-v1",
            "preparationSha256": digest(prepared),
            **{
                role: {"target": target, "enrollment": enrollment}
                for role, (target, enrollment) in pair.items()
            },
        },
    )
    return pair


def inspect_boot(
    attempt: Attempt, role: str, endpoint: Endpoint, production_exclusions: bytes
) -> Document:
    """Observe boot continuity for the exact enrolled host without causing a reboot."""
    require(role in {"source", "restore"}, "droplet-inspection-role-invalid")
    with attempt.lock("controller.lock", blocking=False):
        production = decode(production_exclusions, "droplet-production-exclusions")
        prepared = read(attempt.directory, "droplet-preparation.json")
        original_scope = digest(prepared)
        completed = read(attempt.directory, "droplet-preparation-result.json")
        require(
            prepared["runId"] == attempt.directory.parent.name
            and prepared["invocationId"] == attempt.directory.name
            and prepared["productionExclusionsSha256"] == digest(production)
            and completed["preparationSha256"] == original_scope
            and prepared[role] == _scope(endpoint, production)
            and endpoint.allocation.run_id == prepared["runId"],
            "droplet-inspection-scope-changed",
        )
        original = read(attempt.directory, f"droplet-{role}-observation.json")
        require(
            original["role"] == role and original["preparationSha256"] == original_scope,
            "droplet-inspection-observation-changed",
        )
        before = decode(encode(original["observation"]), "droplet-observation")
        after = observe(endpoint)
        require(
            before["metadata"] == after["metadata"]
            and before["hostIdentity"] == after["hostIdentity"],
            "droplet-inspection-host-changed",
        )
        result = {
            "format": "lowerduckpond-m3-12-boot-observation-v1",
            "preparationSha256": original_scope,
            "role": role,
            "originalObservationSha256": digest(original),
            "originalBootSha256": before["bootSha256"],
            "observedBootSha256": after["bootSha256"],
            "bootChanged": after["bootSha256"] != before["bootSha256"],
        }
        _seal(attempt.directory, f"droplet-{role}-boot-{after['bootSha256']}.json", result)
        return result
