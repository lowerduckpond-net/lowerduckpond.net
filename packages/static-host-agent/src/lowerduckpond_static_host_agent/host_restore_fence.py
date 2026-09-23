"""Root source-host fencing receipt consumed through trusted destination inputs."""

from __future__ import annotations

from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.backup_descriptor import decode_backup_descriptor
from lowerduckpond_static_host_agent.backup_identity import (
    BINDING_FORMAT,
    framed_digest,
    require_digest,
)
from lowerduckpond_static_host_agent.host_restore_gate import GATE_SCHEMA, close_gate
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs, machine_id
from lowerduckpond_static_host_agent.host_restore_journal import (
    GATE,
    HostRestoreError,
    RestoreStore,
    exact_object,
    full_id,
)
from lowerduckpond_static_host_agent.host_restore_services import (
    ORDINARY_ACTIVATORS,
    ORDINARY_SERVICES,
    TEMPLATES,
    close_public_ingress,
    quiesce_host,
    require_quiescent,
)
from lowerduckpond_static_host_agent.host_restore_snapshot import RestoreSnapshot

FENCE_SCHEMA = "lowerduckpond-host-restore-source-fence-v1"


def source_fence_receipt(
    store: RestoreStore,
    snapshot: RestoreSnapshot,
    restore_id: str,
    source_machine_id: str,
    artifact_sha256: str,
) -> bytes:
    """Caller owns repository EX and artifact-selection EX for this whole call.

    The selection lease drains old forced-command sessions as well as workers.
    Source fencing is durable and has no automatic expiry or un-fence command.
    The operator transfers this private receipt and keeps the source fenced.
    """
    restore_id = validate_uuid7(restore_id)
    source_machine_id = machine_id(source_machine_id)
    descriptor = decode_backup_descriptor(snapshot.descriptor)
    artifact = cast(dict[str, str], descriptor["artifactDigest"])
    if artifact["value"] != full_id(artifact_sha256):
        raise HostRestoreError("restore source artifact differs from captured authority")
    close_gate(store, restore_id)
    close_public_ingress()
    masks = quiesce_host()
    require_quiescent()
    gate = store.read_bytes(GATE[0])
    receipt = {
        "schema": FENCE_SCHEMA,
        "restoreId": restore_id,
        "snapshotId": snapshot.snapshot.snapshot_id,
        "captureId": descriptor["captureId"],
        "lineageId": snapshot.lineage["lineageId"],
        "repositoryBinding": snapshot.identity.binding(),
        "artifactDigest": artifact,
        "sourceMachineId": source_machine_id,
        "sourceGateDigest": framed_digest(GATE_SCHEMA, gate),
        "maskedUnits": list(masks),
    }
    raw = canonical_json_bytes(receipt)
    store.immutable(f"source-fence-{restore_id}.json", raw)
    return raw


def require_source_fence(
    raw: bytes, inputs: RestoreInputs, snapshot: RestoreSnapshot
) -> dict[str, object]:
    receipt = require_fence_policy(raw, inputs)
    descriptor = decode_backup_descriptor(snapshot.descriptor)
    if (
        receipt["snapshotId"] != snapshot.snapshot.snapshot_id
        or receipt["captureId"] != descriptor["captureId"]
        or receipt["lineageId"] != snapshot.lineage["lineageId"]
        or receipt["repositoryBinding"] != snapshot.identity.binding()
        or receipt["artifactDigest"] != descriptor["artifactDigest"]
    ):
        raise HostRestoreError("restore_source_fence_mismatch")
    return receipt


def require_fence_policy(raw: bytes, inputs: RestoreInputs) -> dict[str, object]:
    """Controller preflight before destination bootstrap makes its first change.

    This verifies the administrator-transferred root fencing receipt against
    reviewed target policy. Full repository/snapshot proof remains mandatory
    in the coordinator before materialization.
    """
    receipt = exact_object(
        decode_json_object(raw),
        {
            "schema",
            "restoreId",
            "snapshotId",
            "captureId",
            "lineageId",
            "repositoryBinding",
            "artifactDigest",
            "sourceMachineId",
            "sourceGateDigest",
            "maskedUnits",
        },
    )
    if canonical_json_bytes(receipt) != raw:
        raise HostRestoreError("restore source fence is not canonical")
    require_digest(receipt["repositoryBinding"], BINDING_FORMAT)
    require_digest(receipt["artifactDigest"], "lowerduckpond-static-host-agent-artifact-v1")
    require_digest(receipt["sourceGateDigest"], GATE_SCHEMA)
    validate_uuid7(receipt["captureId"])
    validate_uuid7(receipt["lineageId"])
    gate = canonical_json_bytes({"schema": GATE_SCHEMA, "restoreId": inputs.restore_id})
    if (
        receipt["schema"] != FENCE_SCHEMA
        or receipt["restoreId"] != inputs.restore_id
        or receipt["snapshotId"] != inputs.snapshot_id
        or receipt["repositoryBinding"] != inputs.document["repositoryBinding"]
        or cast(dict[str, str], receipt["artifactDigest"])["value"]
        != inputs.document["originalArtifactSha256"]
        or machine_id(receipt["sourceMachineId"]) != inputs.document["sourceMachineId"]
        or receipt["sourceGateDigest"] != framed_digest(GATE_SCHEMA, gate)
        or framed_digest(FENCE_SCHEMA, raw) != inputs.document["sourceFenceDigest"]
    ):
        raise HostRestoreError("restore_source_fence_mismatch")
    if receipt["maskedUnits"] != sorted(
        (*ORDINARY_ACTIVATORS, *ORDINARY_SERVICES, *TEMPLATES, "caddy.service")
    ):
        raise HostRestoreError("restore_source_fence_incomplete")
    return receipt
