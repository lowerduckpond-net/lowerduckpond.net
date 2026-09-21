from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest
from lowerduckpond_static_host_agent.backup_caddy import MANIFEST_DIGEST_FORMAT
from lowerduckpond_static_host_agent.backup_descriptor import (
    ARTIFACT_DIGEST_FORMAT,
    BACKUP_SCHEMA,
    INTENT_DIGEST_FORMAT,
    MAX_BACKUP_DESCRIPTOR_BYTES,
    OBSERVED_DIGEST_FORMAT,
    backup_descriptor_digest,
    decode_backup_descriptor,
    encode_backup_descriptor,
)
from lowerduckpond_static_host_agent.backup_identity import (
    LINEAGE_SCHEMA,
    BackupIdentityError,
    RepositoryIdentity,
)
from lowerduckpond_static_host_agent.backup_sources import TREE_FORMAT, source_policy_digest

ID = "0198d17f-6f4a-7000-8000-000000000001"
SECOND_ID = "0198d17f-6f4a-7000-8000-000000000002"


def _digest(format_identifier: str) -> dict[str, str]:
    return {"format": format_identifier, "algorithm": "sha256", "value": "a" * 64}


@pytest.fixture
def document() -> dict[str, object]:
    repository = RepositoryIdentity("a" * 64, "node", "/private/backup")
    namespace = _digest("lowerduckpond-platform-state-v1")
    return {
        "schema": BACKUP_SCHEMA,
        "captureId": SECOND_ID,
        "capturedAt": "2026-09-21T05:00:00Z",
        "sourcePolicyDigest": source_policy_digest(),
        "artifactDigest": _digest(ARTIFACT_DIGEST_FORMAT),
        "lineage": {
            "schema": LINEAGE_SCHEMA,
            "lineageId": ID,
            "repository": repository.document(),
            "repositoryBinding": repository.binding(),
            "namespaceDigest": namespace,
            "initializedAt": "2026-09-21T04:00:00Z",
            "initialEntryCount": 0,
            "initialTerminalEntryDigest": None,
        },
        "namespaceDigest": namespace,
        "launchDigest": None,
        "audit": {"entryCount": 0, "segmentCount": 0, "terminalEntryDigest": None},
        "authority": {"treeDigest": _digest(TREE_FORMAT), "entryCount": 20, "contentBytes": 4096},
        "tenants": [],
        "intents": [],
        "caddy": {
            "active": ID,
            "startIntent": None,
            "generations": [
                {
                    "generationId": ID,
                    "manifestDigest": _digest(MANIFEST_DIGEST_FORMAT),
                    "routeStateDigest": _digest("lowerduckpond-caddy-route-state-v1"),
                }
            ],
            "selectedTarget": {"generationId": ID, "manifestSha256": "a" * 64},
        },
    }


def _tenant(identifier: str) -> dict[str, object]:
    return {
        "tenantId": identifier,
        "desiredDigest": _digest("lowerduckpond-manifest-v1"),
        "observedDigest": _digest(OBSERVED_DIGEST_FORMAT),
        "deployments": [
            {"deploymentId": ID, "recordDigest": _digest("lowerduckpond-deployment-record-v1")}
        ],
        "archives": [
            {"deploymentId": ID, "recordDigest": _digest("lowerduckpond-archive-record-v1")}
        ],
        "releases": [{"deploymentId": ID, "treeDigest": _digest("lowerduckpond-release-tree-v1")}],
    }


def test_descriptor_binds_exact_canonical_bytes_and_has_no_snapshot_id(
    document: dict[str, object],
) -> None:
    raw = encode_backup_descriptor(document)
    assert decode_backup_descriptor(raw) == document
    assert "snapshotId" not in document
    assert backup_descriptor_digest(raw) == {
        "format": BACKUP_SCHEMA,
        "algorithm": "sha256",
        "value": hashlib.sha256(
            BACKUP_SCHEMA.encode() + b"\0" + len(raw).to_bytes(8, "big") + raw
        ).hexdigest(),
    }
    changed = deepcopy(document)
    changed["capturedAt"] = "2026-09-21T05:00:01Z"
    assert backup_descriptor_digest(encode_backup_descriptor(changed)) != backup_descriptor_digest(
        raw
    )


def test_descriptor_preserves_partial_tenant_and_intent_authority_for_reconciliation(
    document: dict[str, object],
) -> None:
    partial = _tenant(ID)
    partial["desiredDigest"] = None
    partial["observedDigest"] = None
    document["tenants"] = [partial]
    document["intents"] = [
        {
            "intentId": SECOND_ID,
            "tenantId": ID,
            "kind": "TransactionIntent",
            "digest": _digest(INTENT_DIGEST_FORMAT),
        }
    ]
    assert decode_backup_descriptor(encode_backup_descriptor(document)) == document
    # This represents evidence only. The restore coordinator must still validate
    # the actual intent and reconcile it before any service is authorized.


def test_maximum_retained_tenant_inventory_fits_descriptor_bound(
    document: dict[str, object],
) -> None:
    tenants = []
    for tenant_number in range(25):
        tenant = _tenant(f"0198d17f-6f4a-7000-8000-{tenant_number:012x}")
        for name in ("deployments", "archives", "releases"):
            original = tenant[name]
            assert type(original) is list
            rows = []
            for deployment_number in range(4):
                row = deepcopy(original[0])
                row["deploymentId"] = f"0198d17f-6f4a-7000-8000-{deployment_number:012x}"
                rows.append(row)
            tenant[name] = rows
        tenants.append(tenant)
    document["tenants"] = tenants
    assert len(encode_backup_descriptor(document)) < MAX_BACKUP_DESCRIPTOR_BYTES


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "lowerduckpond-static-backup-v2"),
        ("captureId", "not-a-uuid"),
        ("capturedAt", "2026-09-21T03:59:59Z"),
        ("capturedAt", "2026-9-21T05:00:00Z"),
        ("capturedAt", "2026-09-21T05:00:00+00:00"),
        ("sourcePolicyDigest", _digest("lowerduckpond-backup-source-policy-v1")),
        ("artifactDigest", _digest("lowerduckpond-backup-file-v1")),
        ("launchDigest", _digest("lowerduckpond-platform-state-v1")),
        ("namespaceDigest", None),
        ("lineage", None),
        ("snapshotId", "b" * 64),
    ],
)
def test_tampered_identity_or_unsupported_policy_is_rejected(
    document: dict[str, object],
    field: str,
    value: object,
) -> None:
    document[field] = value
    with pytest.raises(BackupIdentityError):
        decode_backup_descriptor(json.dumps(document).encode())


@pytest.mark.parametrize(
    "field,value",
    [
        ("entryCount", -1),
        ("entryCount", True),
        ("entryCount", 2**53),
        ("segmentCount", 1),
        ("terminalEntryDigest", _digest("lowerduckpond-audit-entry-v1")),
    ],
)
def test_audit_boundary_cannot_be_ambiguous(
    document: dict[str, object], field: str, value: object
) -> None:
    audit = document["audit"]
    assert type(audit) is dict
    audit[field] = value
    with pytest.raises(BackupIdentityError):
        decode_backup_descriptor(json.dumps(document).encode())


def test_nonempty_lineage_rejects_truncated_or_forked_backup(document: dict[str, object]) -> None:
    lineage = document["lineage"]
    assert type(lineage) is dict
    lineage["initialEntryCount"] = 5
    lineage["initialTerminalEntryDigest"] = _digest("lowerduckpond-audit-entry-v1")
    with pytest.raises(BackupIdentityError):
        decode_backup_descriptor(json.dumps(document).encode())
    document["audit"] = {
        "entryCount": 5,
        "segmentCount": 1,
        "terminalEntryDigest": _digest("lowerduckpond-audit-entry-v1"),
    }
    assert decode_backup_descriptor(encode_backup_descriptor(document)) == document
    fork = _digest("lowerduckpond-audit-entry-v1")
    fork["value"] = "b" * 64
    audit = document["audit"]
    assert type(audit) is dict
    audit["terminalEntryDigest"] = fork
    with pytest.raises(BackupIdentityError):
        decode_backup_descriptor(json.dumps(document).encode())


@pytest.mark.parametrize(
    "damage", ["duplicate", "unsorted", "too-many", "unsafe-id", "extra-record", "digest", "secret"]
)
def test_bounded_sorted_tenant_inventory_rejects_tampering(
    document: dict[str, object], damage: str
) -> None:
    tenant = _tenant(ID)
    if damage == "duplicate":
        document["tenants"] = [tenant, tenant]
    elif damage == "unsorted":
        document["tenants"] = [_tenant(SECOND_ID), tenant]
    elif damage == "too-many":
        document["tenants"] = [
            _tenant(f"0198d17f-6f4a-7000-8000-{number:012x}") for number in range(26)
        ]
    else:
        document["tenants"] = [tenant]
        if damage == "unsafe-id":
            tenant["tenantId"] = "../../outside"
        elif damage == "extra-record":
            tenant["releases"] = [
                {"deploymentId": ID, "treeDigest": _digest("lowerduckpond-release-tree-v1")}
            ] * 5
        elif damage == "digest":
            tenant["observedDigest"] = _digest("lowerduckpond-manifest-v1")
        else:
            tenant["environment"] = "private"
    with pytest.raises(BackupIdentityError):
        decode_backup_descriptor(json.dumps(document).encode())


@pytest.mark.parametrize("damage", ["whitespace", "duplicate", "too-large", "truncated"])
def test_raw_descriptor_must_be_bounded_exact_canonical_json(
    document: dict[str, object], damage: str
) -> None:
    raw = encode_backup_descriptor(document)
    if damage == "whitespace":
        raw = json.dumps(document, indent=2).encode()
    elif damage == "duplicate":
        raw = b'{"schema":"other",' + raw[1:]
    elif damage == "too-large":
        raw += b" " * MAX_BACKUP_DESCRIPTOR_BYTES
    else:
        raw = raw[:-2]
    with pytest.raises(BackupIdentityError):
        decode_backup_descriptor(raw)
