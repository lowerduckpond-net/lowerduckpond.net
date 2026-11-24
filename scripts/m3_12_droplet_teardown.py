"""Reconcile original P4 cleanup obligations without issuing another mutation."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from lowerduckpond_static_contracts import ContractError, decode_json_object

from scripts.m3_12_contracts import (
    MAX_RECORD_BYTES,
    Document,
    ValidationError,
    digest,
    encode,
    require,
)
from scripts.m3_12_diagnostic_store import read
from scripts.m3_12_droplet_cleanup import (
    InitialRetirement,
    reconcile_initial_retirement,
    verify_initial_destroy_plan,
)
from scripts.m3_12_droplet_native import AdapterInputs
from scripts.m3_12_droplet_scope import ROLES
from scripts.m3_12_droplet_storage import storage_target

TEARDOWN = frozenset({"teardown"})
FINGERPRINT = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class HostAbsence:
    original: InitialRetirement
    state_json: bytes
    readback: Document
    state_evidence: Document | None = None


def _host_authority(scope: Document, role: str, original: InitialRetirement) -> str:
    require(role in ROLES, "droplet-teardown-host-role-changed")
    allocation = original.allocation
    host = scope["resources"]["hosts"][role]
    target = host["target"]
    require(
        allocation.role == role
        and allocation.run_id == scope["runId"]
        and original.state_key == host["stateKey"]
        and target["allocationSha256"] == allocation.allocation_sha256
        and target["stateSha256"] == allocation.state_sha256
        and target["inventorySha256"] == allocation.inventory_sha256
        and target["transactionNamespaceSha256"] == allocation.transaction_namespace_sha256
        and target["droplet"]["providerIdentitySha256"] == digest(allocation.identity.document()),
        "droplet-teardown-host-authority-changed",
    )
    return digest(
        {
            "role": role,
            "targetSha256": digest(target),
            "stateKey": original.state_key,
            "firewallId": original.firewall_id,
            "projectUrn": original.urn,
        }
    )


def _fingerprint(value: object) -> bool:
    return isinstance(value, str) and FINGERPRINT.fullmatch(value) is not None


def _original_authority(inputs: AdapterInputs, intent: Document, raw: bytes) -> Document:
    reference = intent["prerequisites"]["retain-originals"]
    receipt = read(inputs.attempt.directory, reference["file"])
    try:
        authority = decode_json_object(raw, maximum_bytes=MAX_RECORD_BYTES)
    except ContractError:
        raise ValidationError("droplet-teardown-original-invalid") from None
    require(
        set(authority) == {"format", "allocationSha256", "hosts", "grants", "archiveRetentions"}
        and authority["format"] == "lowerduckpond-m3-12-teardown-authority-v1"
        and authority["allocationSha256"] == intent["allocationSha256"]
        and isinstance(authority["hosts"], dict)
        and set(authority["hosts"]) == set(ROLES)
        and all(_fingerprint(key) for key in authority["hosts"].values())
        and isinstance(authority["grants"], list)
        and all(_fingerprint(key) for key in authority["grants"])
        and len(set(authority["grants"])) == len(authority["grants"])
        and isinstance(authority["archiveRetentions"], dict)
        and all(
            _fingerprint(key) and _fingerprint(value)
            for key, value in authority["archiveRetentions"].items()
        )
        and encode(authority) == raw
        and digest(receipt) == reference["sha256"]
        and digest(authority) == receipt["evidence"]["cleanupAuthority"],
        "droplet-teardown-original-changed",
    )
    return authority


def review_destroy_plan(  # noqa: PLR0913 - original scope and reviewed saved-plan inputs
    inputs: AdapterInputs,
    authority_raw: bytes,
    role: str,
    original: InitialRetirement,
    plan_json: bytes,
    *,
    reviewed_sha256: str,
) -> None:
    scope, intent = inputs.open(TEARDOWN)
    authority = _original_authority(inputs, intent, authority_raw)
    require(
        _host_authority(scope, role, original) == authority["hosts"][role],
        "droplet-teardown-host-authority-changed",
    )
    verify_initial_destroy_plan(
        original,
        plan_json,
        reviewed_sha256=reviewed_sha256,
        state_key=scope["resources"]["hosts"][role]["stateKey"],
    )


def _status(row: object, expected: str, statuses: frozenset[str]) -> str:
    require(
        isinstance(row, dict)
        and set(row) == {"identitySha256", "evidenceSha256", "status"}
        and row["identitySha256"] == expected
        and _fingerprint(row["evidenceSha256"])
        and isinstance(row["status"], str)
        and row["status"] in statuses,
        "droplet-teardown-readback-changed",
    )
    assert isinstance(row, dict)  # noqa: S101 - checked above
    status: str = row["status"]
    return status


def _normalize_external(
    scope: Document, intent: Document, authority: Document, observed: Document
) -> Document:
    require(
        set(observed) == {"dns", "storage", "grants"}
        and all(isinstance(value, dict) for value in observed.values()),
        "droplet-teardown-readback-changed",
    )
    edge = {
        f"{zone}-{role}": digest(
            {
                "zoneId": row["zoneId"],
                "zoneName": row["zoneName"],
                "scope": row[role],
            }
        )
        for zone, row in scope["resources"]["edge"].items()
        for role in ("source", "fresh")
    }
    storage = {
        f"{role}-{kind}": digest(storage_target(scope, intent, role, kind).document())
        for role in ("source", "fresh")
        for kind in ("restic", "archive")
    }
    retentions = authority["archiveRetentions"]
    require(
        set(retentions) <= {value for name, value in storage.items() if name.endswith("-archive")}
        and set(observed["dns"]) == set(edge)
        and set(observed["storage"]) == set(storage)
        and set(observed["grants"]) == set(authority["grants"]),
        "droplet-teardown-readback-changed",
    )
    statuses = frozenset({"absent", "present", "unverified"})
    dns = {name: _status(observed["dns"][name], key, statuses) for name, key in edge.items()}
    grants = {
        key: _status(row, key, frozenset({"revoked", "expired", "active", "unverified"}))
        for key, row in observed["grants"].items()
    }
    state = {}
    for name, key in storage.items():
        row = observed["storage"][name]
        status = _status(row, key, statuses | {"retained"})
        if key in retentions:
            state[name] = (
                "retained"
                if status == "retained" and row["evidenceSha256"] == retentions[key]
                else "unresolved"
            )
        else:
            state[name] = "unresolved" if status == "retained" else status
    return {"dns": dns, "storage": state, "grants": grants}


def reconcile_teardown(
    inputs: AdapterInputs,
    authority_raw: bytes,
    hosts: Mapping[str, HostAbsence],
    external: Document,
    *,
    independently_observed_sha256: str,
) -> Document:
    """Join independent exacts facts, keeping any pending obligation unresolved."""
    scope, intent = inputs.open(TEARDOWN)
    original = _original_authority(inputs, intent, authority_raw)
    require(
        digest(external) == independently_observed_sha256,
        "droplet-teardown-independent-readback-changed",
    )
    require(set(hosts) == set(ROLES), "droplet-teardown-host-set-changed")
    outcomes = {}
    for role, capture in hosts.items():
        require(
            original["hosts"][role] == _host_authority(scope, role, capture.original),
            "droplet-teardown-host-authority-changed",
        )
        outcomes[role] = reconcile_initial_retirement(
            capture.original, capture.state_json, capture.readback, capture.state_evidence
        )
    remaining = _normalize_external(scope, intent, original, external)
    complete = (
        all(row["outcome"] == "absent" for row in outcomes.values())
        and all(value == "absent" for value in remaining["dns"].values())
        and all(value in {"absent", "retained"} for value in remaining["storage"].values())
        and all(value in {"revoked", "expired"} for value in remaining["grants"].values())
    )
    return {
        "format": "lowerduckpond-m3-12-teardown-readback-v1",
        "intentSha256": digest(intent),
        "authoritySha256": digest(original),
        "externalReadbackSha256": digest(external),
        "hosts": outcomes,
        **remaining,
        "outcome": "reconciled" if complete else "unresolved",
    }
