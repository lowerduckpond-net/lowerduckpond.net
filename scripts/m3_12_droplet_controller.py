"""Prepare P4 journeys using pinned, independently enrolled SSH endpoints."""

from __future__ import annotations

import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import cast

from lowerduckpond_static_host_agent.host_restore_fence import require_fence_policy
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs

from scripts.m3_12_contracts import (
    Document,
    decode,
    digest,
    encode,
    require,
)
from scripts.m3_12_diagnostic_store import Attempt, clock, failure, publish, read
from scripts.m3_12_droplet_inventory import (
    ConnectedDroplet,
    OwnedDroplet,
    enrollment_records,
    prepare_source_and_restore,
)
from scripts.m3_12_droplet_ssh import Endpoint, observe

COLD_STATE = (
    {"artifactSelected": False, "launchPresent": False, "publication": "absent"},
    {"artifactSelected": False, "launchPresent": False, "publication": "dark"},
)


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
        "role": approved.role,
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
        and source.allocation.role == "source"
        and restore.allocation.role == "restore"
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
    require(restore_doc["state"] in COLD_STATE, "droplet-restore-target-is-not-cold")
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


def prepare_fresh(
    attempt: Attempt, endpoint: Endpoint, production_exclusions: bytes
) -> tuple[Document, Document]:
    """Seal an independent fresh-install role before any candidate setup."""
    with attempt.lock("controller.lock", blocking=False):
        started = clock()
        attempt.append("preparation", "ssh", started)
        try:
            result = _prepare_fresh(attempt, endpoint, production_exclusions)
        except Exception as error:
            _record_failure(attempt, started, error)
            raise
        attempt.append("preparation", "ssh", started, status=0)
        return result


def _prepare_fresh(
    attempt: Attempt, endpoint: Endpoint, production_exclusions: bytes
) -> tuple[Document, Document]:
    run_id = attempt.directory.parent.name
    require(
        endpoint.allocation.run_id == run_id and endpoint.allocation.role == "fresh",
        "droplet-preparation-role-conflict",
    )
    production = decode(production_exclusions, "droplet-production-exclusions")
    prepared = {
        "format": "lowerduckpond-m3-12-disposable-preparation-v1",
        "runId": run_id,
        "invocationId": attempt.directory.name,
        "productionExclusionsSha256": digest(production),
        "fresh": _scope(endpoint, production),
    }
    _seal(attempt.directory, "droplet-preparation.json", prepared)
    host, observed = _observe_role(attempt, "fresh", endpoint, prepared)
    require(observed["state"] == COLD_STATE[0], "droplet-fresh-target-is-not-pristine")
    target, enrollment = enrollment_records(
        host.allocation, host.observation, production_exclusions
    )
    _seal(
        attempt.directory,
        "droplet-preparation-result.json",
        {
            "format": "lowerduckpond-m3-12-disposable-preparation-result-v1",
            "preparationSha256": digest(prepared),
            "fresh": {"target": target, "enrollment": enrollment},
        },
    )
    return target, enrollment


def _retained_role(
    attempt: Attempt, role: str, endpoint: Endpoint, production_exclusions: bytes
) -> tuple[Document, Document, Document]:
    production = decode(production_exclusions, "droplet-production-exclusions")
    prepared = read(attempt.directory, "droplet-preparation.json")
    original_scope = digest(prepared)
    completed = read(attempt.directory, "droplet-preparation-result.json")
    require(
        prepared["runId"] == attempt.directory.parent.name
        and prepared["invocationId"] == attempt.directory.name
        and prepared["productionExclusionsSha256"] == digest(production)
        and completed["preparationSha256"] == original_scope
        and prepared.get(role) == _scope(endpoint, production)
        and role in completed
        and endpoint.allocation.run_id == prepared["runId"]
        and endpoint.allocation.role == role,
        "droplet-inspection-scope-changed",
    )
    original = read(attempt.directory, f"droplet-{role}-observation.json")
    require(
        original["role"] == role and original["preparationSha256"] == original_scope,
        "droplet-inspection-observation-changed",
    )
    before = decode(encode(original["observation"]), "droplet-observation")
    return completed, original, before


def _observe_same_host(endpoint: Endpoint, before: Document) -> Document:
    after = observe(endpoint)
    require(
        before["metadata"] == after["metadata"] and before["hostIdentity"] == after["hostIdentity"],
        "droplet-inspection-host-changed",
    )
    return after


def prepare_cold_restore(  # noqa: PLR0913 - owned pair and two independent restore inputs
    attempt: Attempt,
    source: Endpoint,
    restore: Endpoint,
    production_exclusions: bytes,
    *,
    trusted_inputs: bytes,
    source_fence: bytes,
) -> Document:
    """Bind the original recovery policy to the pinned pair before destination setup.

    Inputs come from separately reviewed custody. This uses the native restore
    preflight, which does not prove repository contents, live firewall state,
    snapshot materialization, archive versions or ingress verification.
    """
    with attempt.lock("controller.lock", blocking=False):
        completed, _, source_before = _retained_role(
            attempt, "source", source, production_exclusions
        )
        _, _, restore_before = _retained_role(attempt, "restore", restore, production_exclusions)
        inputs = RestoreInputs.from_bytes(trusted_inputs)
        fence = require_fence_policy(source_fence, inputs)
        require(
            sha256(cast(str, fence["sourceMachineId"]).encode("ascii")).hexdigest()
            == source_before["hostIdentity"]["machineSha256"]
            and sha256(
                cast(str, inputs.document["destinationMachineId"]).encode("ascii")
            ).hexdigest()
            == restore_before["hostIdentity"]["machineSha256"],
            "droplet-restore-policy-host-changed",
        )
        plan = {
            "format": "lowerduckpond-m3-12-cold-restore-inputs-v1",
            "preparationSha256": digest(completed),
            "restoreId": inputs.restore_id,
            "snapshotId": inputs.snapshot_id,
            "trustedInputs": inputs.digest,
            "sourceFence": inputs.document["sourceFenceDigest"],
        }
        _seal(attempt.directory, "droplet-cold-restore-inputs.json", plan)
        observed = _observe_same_host(restore, restore_before)
        require(observed["state"] in COLD_STATE, "droplet-restore-target-is-not-cold")
        return plan


def inspect_boot(
    attempt: Attempt, role: str, endpoint: Endpoint, production_exclusions: bytes
) -> Document:
    """Observe boot continuity for the exact enrolled host without causing a reboot."""
    require(role in {"source", "restore", "fresh"}, "droplet-inspection-role-invalid")
    with attempt.lock("controller.lock", blocking=False):
        completed, original, before = _retained_role(attempt, role, endpoint, production_exclusions)
        after = _observe_same_host(endpoint, before)
        result = {
            "format": "lowerduckpond-m3-12-boot-observation-v1",
            "preparationSha256": completed["preparationSha256"],
            "role": role,
            "originalObservationSha256": digest(original),
            "originalBootSha256": before["bootSha256"],
            "observedBootSha256": after["bootSha256"],
            "bootChanged": after["bootSha256"] != before["bootSha256"],
        }
        _seal(attempt.directory, f"droplet-{role}-boot-{after['bootSha256']}.json", result)
        return result
